use std::sync::Mutex;

use actix_web::web::Bytes;
use actix_ws::{AggregatedMessage, AggregatedMessageStream, Session};
use anyhow::{anyhow, Context as EContext};
use futures_util::StreamExt;
use k256::PublicKey;
use serde::{Deserialize, Serialize};
use tss_esapi::Context;

use crate::{secure_connection::SecureConnection, signing_key::AttestedKey};

async fn next_ws_binary(
    session: &mut Session,
    stream: &mut AggregatedMessageStream,
) -> anyhow::Result<Option<Bytes>> {
    while let Some(msg) = stream.next().await {
        match msg {
            Ok(AggregatedMessage::Binary(bin)) => {
                return Ok(Some(bin));
            }

            Ok(AggregatedMessage::Ping(msg)) => {
                session.pong(&msg).await.unwrap();
            }

            _ => {}
        }
    }
    Ok(None)
}

#[derive(Serialize, Deserialize, Eq, Ord, Clone, PartialEq, PartialOrd)]
pub enum ClientIntroMessage {
    ClientIntroV1(PublicKey),
}

#[derive(Serialize, Deserialize, Eq, Ord, Clone, PartialEq, PartialOrd)]
pub struct TargetServernameV1 {
    servername: String
}
pub enum ClientToServerMessage {

}

pub async fn do_certify_protocol(
    context: &Mutex<Context>,
    attested_key: &AttestedKey,
    session: &mut Session,
    stream: &mut AggregatedMessageStream,
) -> anyhow::Result<()> {
    // Step 1: Create private channel protected by ephemeral key.
    // The key is derived from a keypair, with the public half signed
    // by the TPM2 resident signing key.
    let intro_msg = next_ws_binary(session, stream)
        .await?
        .ok_or_else(|| anyhow!("Expected initial client public key"))?;

    let intro_msg: ClientIntroMessage =
        bincode::serde::borrow_decode_from_slice(&intro_msg, bincode::config::standard())
            .context("Decoding intro msg")?
            .0;

    let client_pubkey = match intro_msg {
        ClientIntroMessage::ClientIntroV1(k) => k,
    };

    let (conn, server_cert) =
        SecureConnection::new(&mut context.lock().unwrap(), client_pubkey, attested_key)?;

    session
        .binary(bincode::serde::encode_to_vec(
            server_cert,
            bincode::config::standard(),
        )?)
        .await?;

    // Step 2: The client sends the target servername...
    conn.encrypt_server_to_client(plaintext);

    todo!()
}
