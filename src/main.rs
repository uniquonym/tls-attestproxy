use std::fs::{read, read_to_string};

use actix_web::{get, rt, web, App, Error, HttpRequest, HttpResponse, HttpServer, Responder};
use actix_ws::AggregatedMessage;
use futures_util::StreamExt as _;
use serde::{Deserialize, Serialize};
use tss_esapi::{
    attributes::ObjectAttributes,
    constants::SessionType,
    handles::KeyHandle,
    interface_types::{
        algorithm::{HashingAlgorithm, PublicAlgorithm},
        key_bits::RsaKeyBits,
        reserved_handles::Hierarchy,
        session_handles::AuthSession,
    },
    structures::{
        CreatePrimaryKeyResult, HashScheme, Public, PublicBuilder, PublicKeyRsa,
        PublicRsaParameters, RsaExponent, RsaScheme, SymmetricDefinition,
        SymmetricDefinitionObject,
    },
    tss2_esys::ESYS_TR,
    utils::PublicKey,
    Context, Tcti,
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

#[derive(Serialize, Deserialize)]
pub struct StorableKey {
    handle: ESYS_TR,
    public_key: PublicKey,
}

impl TryFrom<CreatePrimaryKeyResult> for StorableKey {
    type Error = anyhow::Error;

    fn try_from(value: CreatePrimaryKeyResult) -> Result<Self, Self::Error> {
        Ok(Self {
            handle: value.key_handle.into(),
            public_key: value.out_public.try_into()?,
        })
    }
}

pub struct TpmResidentKey {
    handle: KeyHandle,
    public: PublicKey,
}

impl From<StorableKey> for TpmResidentKey {
    fn from(value: StorableKey) -> Self {
        TpmResidentKey {
            handle: value.handle.into(),
            public: value.public_key,
        }
    }
}

fn try_load_key(path: &str) -> anyhow::Result<TpmResidentKey> {
    let data = read_to_string(path)?;
    let storable_key: StorableKey = serde_json::from_str(&data)?;
    Ok(storable_key.into())
}

fn save_key(key: &StorableKey, path: &str) -> anyhow::Result<()> {
    std::fs::write(path, &serde_json::to_string(key)?)?;
    Ok(())
}

fn load_or_create_ak(context: &mut Context) -> anyhow::Result<TpmResidentKey> {
    let keypath = std::env::var("AK_STORAGE_PATH").expect("AK_STORAGE_PATH to be set");
    if let Ok(key) = try_load_key(&keypath) {
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
                .unwrap(),
        )
        .with_rsa_parameters(
            PublicRsaParameters::builder()
                .with_symmetric(SymmetricDefinitionObject::Null)
                .with_scheme(RsaScheme::RsaSsa(HashScheme::new(HashingAlgorithm::Sha256)))
                .with_key_bits(RsaKeyBits::Rsa2048)
                .with_exponent(RsaExponent::create(65537).unwrap())
                .build()
                .unwrap(),
        )
        .with_rsa_unique_identifier(PublicKeyRsa::default())
        .build()
        .expect("Expected to build public key template");

    let primary = context
        .create_primary(
            Hierarchy::Endorsement,
            primary_public_template,
            None,
            None,
            None,
            None,
        )
        .expect("Expected CreatePrimary to create EK to succeed");
    let storable_primary: StorableKey = primary.try_into().unwrap();
    save_key(&storable_primary, &keypath)?;

    Ok(storable_primary.into())
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
    let _ak = load_or_create_ak(&mut context).expect("Expected to have created attestation key");

    // context.create();

    HttpServer::new(|| App::new().service(binarylogsvc))
        .bind(("0.0.0.0", 8080))?
        .run()
        .await
}
