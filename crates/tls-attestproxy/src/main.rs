use std::fs::read;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Mutex;

use actix_web::web::Data;
use actix_web::{get, rt, web, App, Error, HttpRequest, HttpResponse, HttpServer, Responder};
use anyhow::Context as EContext;
use log::info;
use tls_attestproxy::attestation_key::load_or_create_ak;
use tls_attestproxy::certify_protocol_server::do_certify_protocol_server;
use tls_attestproxy::signing_key::{load_or_create_signkey, AttestedKey};
use tls_attestproxy::start_tpm_session;
use tss_esapi::Context;
use tss_esapi::Tcti;

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

    start_tpm_session(&mut context);

    let ak_keypath = PathBuf::from_str(
        &std::env::var("AK_STORAGE_PATH")
            .context("Fetching AK_STORAGE_PATH environment")
            .unwrap(),
    )
    .unwrap();
    let sk_keypath = PathBuf::from_str(
        &std::env::var("SIGNKEY_STORAGE_PATH")
            .context("Fetching SIGNKEY_STORAGE_PATH environment")
            .unwrap(),
    )
    .unwrap();

    let ak = load_or_create_ak(&mut context, &ak_keypath)
        .expect("Expected to have created attestation key");
    let sk = load_or_create_signkey(&mut context, &ak, &sk_keypath)
        .expect("Expected to have created signing key");

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
