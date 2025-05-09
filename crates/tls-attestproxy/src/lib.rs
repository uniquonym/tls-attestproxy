use crate::certify_protocol_server::do_certify_protocol_server;
use crate::signing_key::AttestedKey;
use actix_web::web::Data;
use actix_web::{get, rt, web, Error, HttpRequest, HttpResponse, Responder};
use log::info;
use std::fs::read;
use std::sync::Mutex;
use tss_esapi::{
    constants::SessionType,
    interface_types::{algorithm::HashingAlgorithm, session_handles::AuthSession},
    structures::SymmetricDefinition,
    Context,
};

pub mod attestation_key;
pub mod certify_protocol_server;
pub mod message_signing;
pub mod secure_connection_server;
pub mod signing_key;

pub struct ReqData {
    pub context: Mutex<Context>,
    pub sign_key: AttestedKey,
}

#[get("/v1/binpcrlog")]
pub async fn binarylogsvc() -> impl Responder {
    read("/sys/kernel/security/tpm0/binary_bios_measurements")
}

#[get("/v1/tlscertify")]
pub async fn tlscertify(
    data: Data<ReqData>,
    req: HttpRequest,
    stream: web::Payload,
) -> Result<HttpResponse, Error> {
    let (res, mut session, stream) = actix_ws::handle(&req, stream)?;

    let mut stream = stream
        .aggregate_continuations()
        .max_continuation_size(1000000_usize);
    rt::spawn(async move {
        if let Err(err) =
            do_certify_protocol_server(&data.context, &data.sign_key, &mut session, &mut stream)
                .await
        {
            info!(
                "Failed to complete certification protocol for stream: {}",
                err
            );
        }
    });
    Ok(res)
}

pub fn start_tpm_session(context: &mut Context) {
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
}
