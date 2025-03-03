use std::fs::{read, read_to_string};

use actix_web::{get, rt, web, App, Error, HttpRequest, HttpResponse, HttpServer, Responder};
use actix_ws::AggregatedMessage;
use anyhow::Context as ErrContext;
use futures_util::StreamExt as _;
use serde::{de, ser, Deserialize, Serialize};
use serde_with::base64::{Base64, Standard};
use serde_with::formats::Unpadded;
use serde_with::serde_as;
use tss_esapi::Tcti;
use tss_esapi::{
    attributes::ObjectAttributes,
    constants::SessionType,
    handles::{KeyHandle, ObjectHandle, PersistentTpmHandle},
    interface_types::{
        algorithm::{HashingAlgorithm, PublicAlgorithm},
        data_handles::Persistent,
        ecc::EccCurve,
        key_bits::RsaKeyBits,
        reserved_handles::{Hierarchy, Provision},
        session_handles::AuthSession,
    },
    structures::{
        Attest, Data, EccPoint, EccScheme, HashScheme, KeyDerivationFunctionScheme,
        PcrSelectionList, PcrSlot, Public, PublicBuilder, PublicEccParameters, PublicKeyRsa,
        PublicRsaParameters, RsaExponent, RsaScheme, Signature, SignatureScheme,
        SymmetricDefinition, SymmetricDefinitionObject,
    },
    traits::{Marshall, UnMarshall},
    utils::PublicKey,
    Context,
};

#[get("/v1/binpcrlog")]
async fn binarylogsvc() -> impl Responder {
    read("/sys/kernel/security/tpm0/binary_bios_measurements")
}

#[get("/v1/tlscertify")]
async fn tlscertify(req: HttpRequest, stream: web::Payload) -> Result<HttpResponse, Error> {
    let (res, mut session, stream) = actix_ws::handle(&req, stream)?;

    let mut stream = stream
        .aggregate_continuations()
        .max_continuation_size(1000000_usize);
    rt::spawn(async move {
        while let Some(msg) = stream.next().await {
            match msg {
                Ok(AggregatedMessage::Binary(bin)) => {
                    // echo binary message
                    session.binary(bin).await.unwrap();
                }

                Ok(AggregatedMessage::Ping(msg)) => {
                    // respond to PING frame with PONG frame
                    session.pong(&msg).await.unwrap();
                }

                _ => {}
            }
        }
    });
    Ok(res)
}

#[serde_as]
#[derive(Serialize, Deserialize)]
pub struct StorableKey {
    #[serde_as(as = "Base64<Standard, Unpadded>")]
    serdata: Vec<u8>,
    public_key: PublicKey,
}

pub struct TpmResidentKey {
    handle: KeyHandle,
    public: PublicKey,
}

#[serde_as]
#[derive(Serialize, Deserialize)]
pub struct StorableAttestedKey {
    serdata: Vec<u8>,
    attestation: Attestation,
}

#[derive(Clone)]
pub struct Attestation(Attest, Signature);

#[serde_as]
#[derive(Serialize, Deserialize)]
struct AttestationRaw {
    #[serde_as(as = "Base64<Standard, Unpadded>")]
    attest: Vec<u8>,
    #[serde_as(as = "Base64<Standard, Unpadded>")]
    sig: Vec<u8>,
}
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
        type TupType = (Vec<u8>, Vec<u8>);
        let bytes = TupType::deserialize(deserializer)?;
        let attest: Attest = Attest::unmarshall(&bytes.0)
            .map_err(|_| de::Error::custom("Cant unmarshall attestation body"))?;
        let sig = Signature::unmarshall(&bytes.1)
            .map_err(|_| de::Error::custom("Cant unmarshall signature body"))?;
        Ok(Self(attest, sig))
    }
}

pub struct AttestedKey {
    handle: KeyHandle,
    attestation: Attestation,
}

fn try_load_key(context: &mut Context, path: &str) -> anyhow::Result<TpmResidentKey> {
    let data = read_to_string(path)?;
    let storable_key: StorableKey = serde_json::from_str(&data)?;
    let handle: KeyHandle = context.tr_deserialize(&storable_key.serdata)?.try_into()?;
    Ok(TpmResidentKey {
        handle,
        public: storable_key.public_key.into(),
    })
}

fn save_key(key: &StorableKey, path: &str) -> anyhow::Result<()> {
    std::fs::write(path, &serde_json::to_string(key)?)?;
    Ok(())
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

fn load_or_create_ak(context: &mut Context) -> anyhow::Result<TpmResidentKey> {
    let keypath =
        std::env::var("AK_STORAGE_PATH").context("Fetching AK_STORAGE_PATH environment")?;
    if let Ok(key) = try_load_key(context, &keypath) {
        return Ok(key);
    }

    let primary_public_template: Public = PublicBuilder::new()
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_public_algorithm(PublicAlgorithm::Rsa)
        .with_object_attributes(
            ObjectAttributes::builder()
                .with_fixed_tpm(true)
                .with_fixed_parent(true)
                .with_sensitive_data_origin(true)
                .with_user_with_auth(true)
                .with_restricted(true)
                .with_sign_encrypt(true)
                .build()
                .context("Building AK ObjectAttributes")?,
        )
        .with_rsa_parameters(
            PublicRsaParameters::builder()
                .with_symmetric(SymmetricDefinitionObject::Null)
                .with_scheme(RsaScheme::RsaSsa(HashScheme::new(HashingAlgorithm::Sha256)))
                .with_key_bits(RsaKeyBits::Rsa2048)
                .with_exponent(RsaExponent::create(65537)?)
                .build()
                .context("Creating AK PublicRsaParameters")?,
        )
        .with_rsa_unique_identifier(PublicKeyRsa::default())
        .build()
        .context("Building AK public key template")?;

    let primary = context
        .create_primary(
            Hierarchy::Endorsement,
            primary_public_template,
            None,
            None,
            None,
            None,
        )
        .context("AK CreatePrimary")?;

    let persistent_handle = PersistentTpmHandle::new(0x81000001)?;
    let persistent = Persistent::Persistent(persistent_handle);
    if let Ok(old_handle) = context.execute_without_session(|context| {
        anyhow::Ok(context.tr_from_tpm_public(persistent_handle.try_into()?)?)
    }) {
        context
            .evict_control(Provision::Owner, old_handle, persistent)
            .context("Deleting old AK")?;
    }

    let primary_perm: ObjectHandle = context
        .evict_control(
            Provision::Owner,
            primary.key_handle.clone().into(),
            persistent,
        )
        .context("Making AK persistent")?;
    let primary_ser = context.tr_serialize(primary_perm)?;
    let storable_primary: StorableKey = StorableKey {
        serdata: primary_ser.into(),
        public_key: primary.out_public.try_into()?,
    };
    save_key(&storable_primary, &keypath)?;

    Ok(TpmResidentKey {
        handle: primary_perm.try_into()?,
        public: storable_primary.public_key.clone(),
    })
}

fn load_or_create_signkey(
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

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::Builder::from_default_env().init();

    let mut context =
        Context::new(Tcti::from_environment_variable().expect("Valid TCTI environment setup"))
            .expect("Expected to be able to access tpm2");

    let hmac_sess: AuthSession = context
        .start_auth_session(
            None,
            None,
            None,
            SessionType::Hmac,
            SymmetricDefinition::AES_256_CFB,
            HashingAlgorithm::Sha256,
        )
        .expect("Expected to create an HMAC session.")
        .unwrap();

    context.set_sessions((Some(hmac_sess), None, None));

    let ak = load_or_create_ak(&mut context).expect("Expected to have created attestation key");
    let _sk =
        load_or_create_signkey(&mut context, &ak).expect("Expected to have created signing key");

    HttpServer::new(|| App::new().service(binarylogsvc))
        .bind(("0.0.0.0", 8080))?
        .run()
        .await
}

#[cfg(test)]
mod test {
    use tss_esapi::structures::Attest;

    #[test]
    fn attestation_serialization_should_roundtrip() {}
}
