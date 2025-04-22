use std::fs::read;
use std::sync::Mutex;

use actix_web::web::Data;
use actix_web::{get, rt, web, App, Error, HttpRequest, HttpResponse, HttpServer, Responder};
use attestation_key::load_or_create_ak;
use certify_protocol_server::do_certify_protocol_server;
use log::info;
use signing_key::{load_or_create_signkey, AttestedKey};
use tss_esapi::Tcti;
use tss_esapi::{
    constants::SessionType,
    interface_types::{algorithm::HashingAlgorithm, session_handles::AuthSession},
    structures::SymmetricDefinition,
    Context,
};
mod attestation_key;
mod certify_protocol_server;
mod message_signing;
mod secure_connection_server;
mod signing_key;

#[get("/v1/binpcrlog")]
async fn binarylogsvc() -> impl Responder {
    read("/sys/kernel/security/tpm0/binary_bios_measurements")
}

#[get("/v1/tlscertify")]
async fn tlscertify(
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

pub struct ReqData {
    context: Mutex<Context>,
    sign_key: AttestedKey,
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
    let sk =
        load_or_create_signkey(&mut context, &ak).expect("Expected to have created signing key");

    println!(
        "My attestation: {}",
        serde_json::ser::to_string(&sk.attestation).unwrap_or_else(|_| "".to_owned())
    );

    let data = Data::new(ReqData {
        context: context.into(),
        sign_key: sk,
    });

    HttpServer::new(move || {
        App::new()
            .app_data(data.clone())
            .service(binarylogsvc)
            .service(tlscertify)
    })
    .bind(("0.0.0.0", 8080))?
    .run()
    .await
}
