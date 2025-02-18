use std::fs::read;

use actix_web::{get, rt, web, App, Error, HttpRequest, HttpResponse, HttpServer, Responder};
use actix_ws::AggregatedMessage;
use futures_util::StreamExt as _;
use tss_esapi::{
    attributes::ObjectAttributes,
    constants::SessionType,
    handles::AuthHandle,
    interface_types::{
        algorithm::{HashingAlgorithm, PublicAlgorithm},
        key_bits::RsaKeyBits,
        reserved_handles::Hierarchy,
        session_handles::{AuthSession, PolicySession},
    },
    structures::{
        Digest, Nonce, Public, PublicBuilder, PublicKeyRsa, PublicRsaParameters, RsaExponent,
        RsaScheme, SymmetricDefinition, SymmetricDefinitionObject,
    },
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

    let trial_sess: PolicySession = context
        .start_auth_session(
            None,
            None,
            None,
            SessionType::Trial,
            SymmetricDefinition::AES_256_CFB,
            HashingAlgorithm::Sha256,
        )
        .expect("Expected to create a trial session.")
        .unwrap()
        .try_into()
        .unwrap();
    context.set_sessions((Some(hmac_sess), None, None));
    // This needs to exactly match the TCG template (also used by Google).
    context
        .policy_secret(
            trial_sess,
            AuthHandle::Endorsement,
            Nonce::default(),
            Digest::default(),
            Nonce::default(),
            None,
        )
        .expect("Expected PolicySecret to succeed");
    context.set_sessions((None, None, None));
    let policy_digest = context.policy_get_digest(trial_sess).unwrap();
    // println!("EK Policy Digest: {:02X?}", policy_digest.as_bytes());

    let primary_public_template: Public = PublicBuilder::new()
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
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
        .with_auth_policy(policy_digest)
        .with_rsa_parameters(
            PublicRsaParameters::builder()
                .with_symmetric(SymmetricDefinitionObject::AES_128_CFB)
                .with_scheme(RsaScheme::Null)
                .with_key_bits(RsaKeyBits::Rsa2048)
                .with_exponent(RsaExponent::ZERO_EXPONENT)
                .build()
                .unwrap(),
        )
        .with_rsa_unique_identifier(PublicKeyRsa::new_empty_with_size(RsaKeyBits::Rsa2048))
        .build()
        .expect("Expected to build public key template");

    context
        .create_primary(
            Hierarchy::Endorsement,
            primary_public_template,
            None,
            None,
            None,
            None,
        )
        .expect("Expected CreatePrimary to create EK to succeed");

    HttpServer::new(|| App::new().service(binarylogsvc))
        .bind(("0.0.0.0", 8080))?
        .run()
        .await
}
