use std::fs::read_to_string;

use anyhow::Context as EContext;
use serde::{de, ser, Deserialize, Serialize};
use serde_with::base64::{Base64, Standard};
use serde_with::formats::Unpadded;
use serde_with::serde_as;
use tss_esapi::handles::KeyHandle;
use tss_esapi::structures::{Attest, Signature};
use tss_esapi::traits::{Marshall, UnMarshall};
use tss_esapi::{
    attributes::ObjectAttributes,
    handles::{ObjectHandle, PersistentTpmHandle},
    interface_types::{
        algorithm::{HashingAlgorithm, PublicAlgorithm},
        data_handles::Persistent,
        ecc::EccCurve,
        reserved_handles::{Hierarchy, Provision},
    },
    structures::{
        Data, EccPoint, EccScheme, HashScheme, KeyDerivationFunctionScheme, PcrSelectionList,
        PcrSlot, Public, PublicBuilder, PublicEccParameters, SignatureScheme,
        SymmetricDefinitionObject,
    },
    Context,
};

use crate::attestation_key::TpmResidentKey;

#[serde_as]
#[derive(Serialize, Deserialize)]
struct AttestationRaw {
    #[serde_as(as = "Base64<Standard, Unpadded>")]
    attest: Vec<u8>,
    #[serde_as(as = "Base64<Standard, Unpadded>")]
    sig: Vec<u8>,
}

#[serde_as]
#[derive(Serialize, Deserialize)]
pub struct StorableAttestedKey {
    serdata: Vec<u8>,
    attestation: Attestation,
}

#[derive(Clone, Debug)]
pub struct Attestation(Attest, Signature);

impl Serialize for Attestation {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        AttestationRaw {
            attest: self
                .0
                .marshall()
                .map_err(|_| ser::Error::custom("Can't marshall attestation body"))?,
            sig: self
                .1
                .marshall()
                .map_err(|_| ser::Error::custom("Can't marshall attestation signature"))?,
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Attestation {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = AttestationRaw::deserialize(deserializer)?;
        let attest: Attest = Attest::unmarshall(&raw.attest)
            .map_err(|_| de::Error::custom("Cant unmarshall attestation body"))?;
        let sig = Signature::unmarshall(&raw.sig)
            .map_err(|_| de::Error::custom("Cant unmarshall signature body"))?;
        Ok(Self(attest, sig))
    }
}

pub struct AttestedKey {
    pub handle: KeyHandle,
    pub attestation: Attestation,
}

fn try_load_attested_key(context: &mut Context, path: &str) -> anyhow::Result<AttestedKey> {
    let data = read_to_string(path)?;
    let storable_key: StorableAttestedKey = serde_json::from_str(&data)?;
    let handle: KeyHandle = context.tr_deserialize(&storable_key.serdata)?.try_into()?;
    Ok(AttestedKey {
        handle,
        attestation: storable_key.attestation,
    })
}

fn save_attested_key(key: &StorableAttestedKey, path: &str) -> anyhow::Result<()> {
    std::fs::write(path, &serde_json::to_string(key)?)?;
    Ok(())
}

pub fn load_or_create_signkey(
    context: &mut Context,
    ak: &TpmResidentKey,
) -> anyhow::Result<AttestedKey> {
    let keypath = std::env::var("SIGNKEY_STORAGE_PATH")
        .context("Reading SIGNKEY_STORAGE_PATH environment")?;
    if let Ok(key) = try_load_attested_key(context, &keypath) {
        return Ok(key);
    }
    let signkey_public_template: Public = PublicBuilder::new()
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_public_algorithm(PublicAlgorithm::Ecc)
        .with_object_attributes(
            ObjectAttributes::builder()
                .with_fixed_tpm(true)
                .with_fixed_parent(true)
                .with_sensitive_data_origin(true)
                .with_sign_encrypt(true)
                .build()
                .context("Building SignKey public template ObjectAttributes")?,
        )
        .with_ecc_parameters(
            PublicEccParameters::builder()
                .with_symmetric(SymmetricDefinitionObject::Null)
                .with_ecc_scheme(EccScheme::EcSchnorr(HashScheme::new(
                    HashingAlgorithm::Sha256,
                )))
                .with_curve(EccCurve::NistP256)
                .with_key_derivation_function_scheme(KeyDerivationFunctionScheme::Null)
                .with_is_signing_key(true)
                .build()
                .context("Building PublicEccParameters for SignKey")?,
        )
        .with_ecc_unique_identifier(EccPoint::default())
        .build()
        .context("Building public signing key template")?;
    let primary = context
        .create_primary(
            Hierarchy::Endorsement,
            signkey_public_template,
            None,
            None,
            None,
            Some(
                PcrSelectionList::builder()
                    .with_selection(
                        HashingAlgorithm::Sha256,
                        &[
                            PcrSlot::Slot1,
                            PcrSlot::Slot2,
                            PcrSlot::Slot3,
                            PcrSlot::Slot4,
                            PcrSlot::Slot5,
                            PcrSlot::Slot6,
                            PcrSlot::Slot7,
                            PcrSlot::Slot8,
                            PcrSlot::Slot9,
                        ],
                    )
                    .build()
                    .context("Creating PcrSelectionList")?,
            ),
        )
        .context("CreatePrimary to create signing key")?;

    let attestation = context
        .certify_creation(
            ak.handle,
            primary
                .key_handle
                .try_into()
                .context("primary key to object")?,
            Data::default(),
            primary.creation_hash,
            SignatureScheme::RsaSsa {
                scheme: HashScheme::new(HashingAlgorithm::Sha256),
            },
            primary.creation_ticket,
        )
        .context("Certifying signing key creation")?;

    let persistent_handle = PersistentTpmHandle::new(0x81000002)?;
    let persistent = Persistent::Persistent(persistent_handle);
    if let Ok(old_handle) = context.execute_without_session(|context| {
        anyhow::Ok(context.tr_from_tpm_public(persistent_handle.try_into()?)?)
    }) {
        context
            .evict_control(Provision::Owner, old_handle, persistent)
            .context("Deleting old signing key")?;
    }

    let primary_perm: ObjectHandle = context
        .evict_control(
            Provision::Owner,
            primary.key_handle.clone().into(),
            persistent,
        )
        .context("Making signing key persistent")?;

    let primary_ser = context.tr_serialize(primary_perm)?;
    let attestation = Attestation(attestation.0, attestation.1);
    let storable = StorableAttestedKey {
        serdata: primary_ser,
        attestation: attestation.clone(),
    };
    save_attested_key(&storable, &keypath)?;
    Ok(AttestedKey {
        handle: primary_perm.try_into()?,
        attestation: attestation,
    })
}

#[cfg(test)]
mod test {
    use super::Attestation;

    #[test]
    fn attestation_serialization_should_roundtrip() {
        const RAW_ATTEST_SAMPLE: &'static str = r#"{"attest":"/1RDR4AaACIACwPAVbRAbbriGv9NI57oFj9ynakfM01/tHdSkNun0FAWAAAAAAAAGRkrDgAAAAcAAAAAASAZECMAFjY2ACIAC+IfhIAqOh2FyifrnyS8SHqTThJkjf6IHV7F+rMN8eYzACCbJZqMWqgTwI5GMcMS/VU18uqSfUTCsRMWSI3QOcUkkA","sig":"ABQACwEAS0bxr30d1uEvpdFoAd0SDdu+/g3dKJIPoYpxPd4aPkVn2pKvqg8cgEQzmnPRsqVJVYVP1g3bM2CzGNryYffgbQbI/s5ngjxhc40yBg3cKibD6mx7i5oCMmIxD+iS78Mvmz1HrRWtr74I2xrB6E86aUn6B2D9SWrt6B6urQs1BK8oTImmSrt0f21BOdF+fxL1yCQEmsZOep6lIJmexxtY7Q47Dg7xWcv8M49c3Fc7370kMN2fQhf1YhFKhhzGrhkvwiQeeK0aH1uonWxvunO1t+ys1U2xq8CIcx8qdVu6RRF36s2UcXtqfjQ/DJe/c7rJ4uC5CloODbiqiqywMUFdnw"}"#;
        assert_eq!(
            serde_json::to_string(&serde_json::from_str::<Attestation>(RAW_ATTEST_SAMPLE).unwrap())
                .unwrap(),
            RAW_ATTEST_SAMPLE.to_owned()
        );
    }
}
