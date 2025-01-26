use std::fs::read;

use actix_web::{get, rt, web, App, Error, HttpRequest, HttpResponse, HttpServer, Responder};
use actix_ws::AggregatedMessage;
use futures_util::StreamExt as _;

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
    Ok(res);
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| App::new().service(binarylogsvc))
        .bind(("::", 8080))?
        .run()
        .await
}
