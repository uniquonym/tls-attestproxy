use std::fs::read_to_string;
use std::path::Path;

use crate::attestation_key::TpmResidentKey;
use anyhow::{anyhow, Context as EContext};
use serde::{de, ser, Deserialize, Serialize};
use serde_with::serde_as;
use sha2::Digest as SHA2Digest;
use sha2::Sha256;
use tls_attestclient::signing_key_attestation::AttestationRaw;
use tss_esapi::constants::SessionType;
use tss_esapi::handles::KeyHandle;
use tss_esapi::handles::SessionHandle;
use tss_esapi::interface_types::session_handles::AuthSession;
use tss_esapi::interface_types::session_handles::PolicySession;
use tss_esapi::structures::{Attest, Digest, DigestList, Signature, SymmetricDefinition};
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

#[derive(Clone, Debug)]
pub struct Attestation(Attest, Signature, Public);

impl TryInto<AttestationRaw> for Attestation {
    type Error = anyhow::Error;

    fn try_into(self) -> Result<AttestationRaw, Self::Error> {
        Ok(AttestationRaw {
            attest: self
                .0
                .marshall()
                .map_err(|_| anyhow!("Can't marshall attestation body"))?,
            sig: self
                .1
                .marshall()
                .map_err(|_| anyhow!("Can't marshall attestation signature"))?,
            public: self
                .2
                .marshall()
                .map_err(|_| anyhow!("Can't marshall public area"))?,
        })
    }
}

impl Serialize for Attestation {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        <Self as TryInto<AttestationRaw>>::try_into(self.clone())
            .map_err(|e| ser::Error::custom(anyhow::Error::msg(e)))?
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
        let public = Public::unmarshall(&raw.public)
            .map_err(|_| de::Error::custom("Cant unmarshall public area"))?;
        Ok(Self(attest, sig, public))
    }
}

#[serde_as]
#[derive(Serialize, Deserialize)]
pub struct StorableAttestedKey {
    serdata: Vec<u8>,
    attestation: Attestation,
}

pub struct AttestedKey {
    pub handle: KeyHandle,
    pub attestation: Attestation,
}

fn try_load_attested_key(context: &mut Context, path: &Path) -> anyhow::Result<AttestedKey> {
    let data = read_to_string(path)?;
    let storable_key: StorableAttestedKey = serde_json::from_str(&data)?;
    let handle: KeyHandle = context.tr_deserialize(&storable_key.serdata)?.try_into()?;
    Ok(AttestedKey {
        handle,
        attestation: storable_key.attestation,
    })
}

fn save_attested_key(key: &StorableAttestedKey, path: &Path) -> anyhow::Result<()> {
    std::fs::write(path, &serde_json::to_string(key)?)?;
    Ok(())
}

// Note: The code to fetch PCRs only works for up to 8 PCRs,
// so take that into account before updating.
pub fn relevant_pcrs() -> anyhow::Result<PcrSelectionList> {
    PcrSelectionList::builder()
        .with_selection(
            HashingAlgorithm::Sha256,
            &[
                // PCR0 = BIOS / firmware. Cloud provider responsibility, assume they
                // won't sign if insecure, but could change (so exclude).
                // PCR1 = Boot config. Cloud provider responsibility.
                // PCR2 = Only a separator - unused.
                // PCR3 = Only a separator - unused.
                // PCR4 = EFI actions - including grub loader hash, kernel hash (critical to security)
                PcrSlot::Slot4,
                // PCR5 = Less critical EFI actions
                PcrSlot::Slot5,
                // PCR6 = Only a separator - unused.
                // PCR7 = Secure Boot EFI config.
                // (nice to have in case config induces wrong
                //  behaviour)
                PcrSlot::Slot7,
                // PCR8 = Grub text commands (critical to security)
                PcrSlot::Slot8,
                // PCR9 = Grub binary images (critical to security)
                PcrSlot::Slot9,
            ],
        )
        .build()
        .context("Creating PcrSelectionList")
}

pub fn combine_pcr_digests(digest_list: &DigestList) -> anyhow::Result<Digest> {
    let mut hasher = Sha256::new();
    for digest in digest_list.value() {
        hasher.update(digest.as_bytes());
    }
    Digest::from_bytes(&hasher.finalize()).context("Wrapping digest")
}

fn create_auth_policy(
    context: &mut Context,
    pcr_list: &PcrSelectionList,
    digest_list: &DigestList,
) -> anyhow::Result<(Digest, AuthSession)> {
    let sess = context
        .start_auth_session(
            None,
            None,
            None,
            SessionType::Policy,
            SymmetricDefinition::Null,
            HashingAlgorithm::Sha256,
        )
        .context("Starting auth policy session")?
        .ok_or_else(|| anyhow::anyhow!("No policy session returned"))?;
    let policy_sess: PolicySession = sess.try_into().context("Extracting policy session")?;

    let digest = combine_pcr_digests(&digest_list)?;
    context
        .policy_pcr(policy_sess, digest, pcr_list.clone())
        .context("Adding policy_pcr to policy")?;
    let digest = context
        .policy_get_digest(policy_sess)
        .context("Get digest from policy session")?;
    Ok((digest, sess))
}

pub fn apply_auth_policy(context: &mut Context) -> anyhow::Result<()> {
    // Cleanup current session first, since we always restart cleanly...
    if let Some(sess) = context.sessions().0 {
        context.flush_context(SessionHandle::from(sess).into())?;
    }

    context.set_sessions((None, None, None));
    let (_, pcr_list, digest_list) =
    context.pcr_read(relevant_pcrs()?).context("Reading PCRs")?;
    let (_, auth_sess) = create_auth_policy(context, &pcr_list, &digest_list)?;
    context.set_sessions((Some(auth_sess), None, None));
    Ok(())
}

pub fn load_or_create_signkey(
    context: &mut Context,
    ak: &TpmResidentKey,
    keypath: &Path,
) -> anyhow::Result<AttestedKey> {
    if let Ok(key) = try_load_attested_key(context, &keypath) {
        return Ok(key);
    }
    let (key_policy, tmp_sess) = context.execute_without_session(|context| {
        let (_, pcr_list, digest_list) =
            context.pcr_read(relevant_pcrs()?).context("Reading PCRs")?;
        create_auth_policy(context, &pcr_list, &digest_list)
    })?;
    context.flush_context(SessionHandle::from(tmp_sess).into())?;

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
                .with_ecc_scheme(EccScheme::EcDsa(HashScheme::new(HashingAlgorithm::Sha256)))
                .with_curve(EccCurve::NistP256)
                .with_key_derivation_function_scheme(KeyDerivationFunctionScheme::Null)
                .with_is_signing_key(true)
                .build()
                .context("Building PublicEccParameters for SignKey")?,
        )
        .with_ecc_unique_identifier(EccPoint::default())
        .with_auth_policy(key_policy)
        .build()
        .context("Building public signing key template")?;
    let primary = context
        .create_primary(
            Hierarchy::Endorsement,
            signkey_public_template,
            None,
            None,
            None,
            None,
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
    let attestation = Attestation(attestation.0, attestation.1, primary.out_public);
    let storable = StorableAttestedKey {
        serdata: primary_ser,
        attestation: attestation.clone(),
    };
    save_attested_key(&storable, &keypath)?;

    Ok(AttestedKey {
        handle: primary_perm.try_into()?,
        attestation,
    })
}

#[cfg(test)]
mod test {
    use hex_literal::hex;
    use tss_esapi::structures::{Digest, DigestList};

    use super::{combine_pcr_digests, Attestation};

    #[test]
    fn attestation_serialization_should_roundtrip() {
        const RAW_ATTEST_SAMPLE: &'static str = r#"{"attest":"/1RDR4AaACIACwPAVbRAbbriGv9NI57oFj9ynakfM01/tHdSkNun0FAWAAAAAAAAGR7K0AAAAAgAAAAAASAZECMAFjY2ACIAC9AfAmGauLrHXLFXEljPeHNXs1fmv+BpP1kaByerhxD1ACCbJZqMWqgTwI5GMcMS/VU18uqSfUTCsRMWSI3QOcUkkA","sig":"ABQACwEAROpV4O6D2hNf1SVPTCkL9JYPG3VoALENdbgHF4hvirS+evEQ9QUhaDYyN0KjwjVngca6mKlSgxJaRGHtKLn7/l6rp6mfS5ym+NbLPMLXRSUQdAbCuF2Up+i6Dn8VAcs0rVMaK14mz12HX5TN96pfeiMu39QXI4oFm3Z/Mr+Mp+8vC/szobhQvzkwb2MOxaGh1F/5ZS0/cIIkbk1F7u4ipqATT3iuRqHQe+61AxrIuCyWOXZjevRJA3RhsHMxPWat8KIrFGdjM01MXOwCzhv/ZF9d25NDfb4F4hiDJB3qiUHt7ycAcKSb4krsivKqKTy5UzaeWEu7kKKr+7NPktJBEg","public":"ACMACwAEADIAIEpv/5dbTLR6mBpO2trU8X75fgHzt7K2ggUc9IMNL0+aABAAGAALAAMAEAAgocPOQUdGKvhvy+UGnYEh9Rrjwr7wgIXw6pbc6cF/PAMAIPFSqc2KOpv9SLGZzfnL2x0VSVQXmIDxTeIH3OH+EOfK"}"#;
        assert_eq!(
            serde_json::to_string(&serde_json::from_str::<Attestation>(RAW_ATTEST_SAMPLE).unwrap())
                .unwrap(),
            RAW_ATTEST_SAMPLE.to_owned()
        );
    }

    #[test]
    fn combine_pcr_digests_should_sum_digests() {
        let mut digest_list = DigestList::new();
        digest_list
            .add(Digest::from(hex!(
                "ff90d79a6dd90515304f1d69c1fba57cf20174e287d72e81e94f5e8e8c602280"
            )))
            .unwrap();
        digest_list
            .add(Digest::from(hex!(
                "292a6b2406428e1fde1a8d3235ce7a2445ce3ff7264b8a0e8128d73453c3b120"
            )))
            .unwrap();
        // echo ff90d79a6dd90515304f1d69c1fba57cf20174e287d72e81e94f5e8e8c602280292a6b2406428e1fde1a8d3235ce7a2445ce3ff7264b8a0e8128d73453c3b120 | xxd -r -p | sha256sum
        // gives the correct digest.
        assert_eq!(
            combine_pcr_digests(&digest_list).unwrap().as_bytes(),
            hex!("29a8290ec3b706ce0bc1a8fda3782e442cc0a42c04ff713641e4a475f8b8194c")
        );
    }
}
