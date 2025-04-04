use std::{
    io::{Cursor, ErrorKind, Read, Write},
    sync::Mutex,
};

use actix_web::web::{Buf, Bytes};
use actix_ws::{AggregatedMessage, AggregatedMessageStream, Session};
use anyhow::{anyhow, Context as EContext};
use bincode::config::{Configuration};
use futures_util::StreamExt;
use k256::PublicKey;
use rustls::{pki_types::ServerName, ClientConfig, ClientConnection};
use rustls_platform_verifier::ConfigVerifierExt;
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
    servername: String,
}

#[derive(Serialize, Deserialize, Eq, Ord, Clone, PartialEq, PartialOrd)]
pub enum ClientToServerMessage {
    ReceivedFromClient(Vec<u8>),
    ReceivedFromServer(Vec<u8>),
    DisconnectFromClient,
}

#[derive(Serialize, Deserialize, Eq, Ord, Clone, PartialEq, PartialOrd)]
pub enum ServerToClientMessage {
    SendToServer(Vec<u8>),
    SendToClient(Vec<u8>),
    DisconnectFromServer,
}

pub struct TLSOpenState {
    open_from_server: bool,
    open_from_client: bool,
}

async fn send_message_to_client(
    session: &mut Session,
    secure_connection: &mut SecureConnection,
    msg: &ServerToClientMessage,
    bincfg: Configuration,
) -> anyhow::Result<()> {
    let binmsg = bincode::serde::encode_to_vec(msg, bincfg)?;
    let binmsg = secure_connection.encrypt_server_to_client(&binmsg)?;

    session.binary(binmsg).await?;
    Ok(())
}

async fn handle_send_tlsconn_to_ws(
    session: &mut Session,
    tls_state: &mut ClientConnection,
    bincfg: Configuration,
    secure_connection: &mut SecureConnection,
    open_state: &mut TLSOpenState,
) -> anyhow::Result<()> {
    while tls_state.wants_write() {
        let mut writebuf: Vec<u8> = Vec::new();
        tls_state.write_tls(&mut writebuf)?;
        session
            .binary(bincode::serde::encode_to_vec(
                ServerToClientMessage::SendToClient(writebuf),
                bincfg,
            )?)
            .await?;
    }
    let mut readbuf: [u8; 4096] = [0; 4096];
    loop {
        match tls_state.reader().read(&mut readbuf) {
            Ok(0) => {
                if open_state.open_from_server {
                    open_state.open_from_server = false;
                    send_message_to_client(
                        session,
                        secure_connection,
                        &ServerToClientMessage::DisconnectFromServer,
                        bincfg,
                    )
                    .await?;
                }
            }
            Ok(n) => {
                send_message_to_client(
                    session,
                    secure_connection,
                    &ServerToClientMessage::SendToClient(readbuf[0..n].into()),
                    bincfg,
                )
                .await?;
            }
            Err(k) if k.kind() == ErrorKind::WouldBlock.into() => return Ok(()),
            Err(e) => return Err(e.into()),
        }
    }
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
    let bincfg = bincode::config::standard();
    let intro_msg = next_ws_binary(session, stream)
        .await?
        .ok_or_else(|| anyhow!("Expected initial client public key"))?;

    let intro_msg: ClientIntroMessage =
        bincode::serde::borrow_decode_from_slice(&intro_msg, bincfg)
            .context("Decoding intro msg")?
            .0;
    let mut open_state: TLSOpenState = TLSOpenState {
        open_from_server: true,
        open_from_client: true,
    };

    let client_pubkey = match intro_msg {
        ClientIntroMessage::ClientIntroV1(k) => k,
    };

    let (mut conn, server_cert) =
        SecureConnection::new(&mut context.lock().unwrap(), client_pubkey, attested_key)?;

    session
        .binary(bincode::serde::encode_to_vec(server_cert, bincfg)?)
        .await?;

    // Step 2: The client sends the target servername...
    let servername_msg = next_ws_binary(session, stream)
        .await?
        .ok_or_else(|| anyhow!("Expected servername message"))?;
    let servername_msg = conn.decrypt_client_to_server(&servername_msg)?;
    let servername: TargetServernameV1 =
        bincode::serde::borrow_decode_from_slice(&servername_msg, bincfg)?.0;

    let mut tls_state = ClientConnection::new(
        ClientConfig::with_platform_verifier().into(),
        ServerName::try_from(servername.servername)?,
    )?;

    // Step 3: Process and react to ordinary messages from the client.
    loop {
        let incoming = next_ws_binary(session, stream)
            .await?
            .ok_or_else(|| anyhow!("Unexpected end of client connection"))?;
        let incoming = conn.decrypt_client_to_server(&incoming)?;
        let incoming: ClientToServerMessage =
            bincode::serde::borrow_decode_from_slice(&incoming, bincfg)?.0;
        match incoming {
            ClientToServerMessage::ReceivedFromClient(msg) => {
                tls_state.writer().write_all(&msg)?;
                handle_send_tlsconn_to_ws(
                    session,
                    &mut tls_state,
                    bincfg,
                    &mut conn,
                    &mut open_state,
                )
                .await?;
            }
            ClientToServerMessage::ReceivedFromServer(msg) => {
                let mut buf_read = Cursor::new(&msg);

                while buf_read.has_remaining() {
                    tls_state.read_tls(&mut buf_read)?;
                    tls_state.process_new_packets()?;

                    handle_send_tlsconn_to_ws(
                        session,
                        &mut tls_state,
                        bincfg,
                        &mut conn,
                        &mut open_state,
                    )
                    .await?;
                }
            }
            ClientToServerMessage::DisconnectFromClient => {
                open_state.open_from_client = false;
                tls_state.send_close_notify();

                handle_send_tlsconn_to_ws(
                    session,
                    &mut tls_state,
                    bincfg,
                    &mut conn,
                    &mut open_state,
                )
                .await?;
            }
        }

        if !open_state.open_from_client && !open_state.open_from_server {
            break;
        }
    }

    todo!()
}
