use std::fs::read_to_string;

use actix_web::{get, App, HttpServer, Responder};

#[get("/binpcrlog")]
async fn binarylogsvc() -> impl Responder {
    read_to_string("/sys/kernel/security/tpm0/binary_bios_measurements")
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| App::new().service(binarylogsvc))
        .bind(("::", 8080))?
        .run()
        .await
}
