use std::{
    io::{Cursor, ErrorKind, Read, Write},
    sync::Mutex,
};

use actix_web::web::{Buf, Bytes};
use actix_ws::{AggregatedMessage, AggregatedMessageStream, Session};
use anyhow::{anyhow, Context as EContext};
use bincode::config::Configuration;
use der::{oid::AssociatedOid, Decode};
use futures_util::StreamExt;
use rustls::{pki_types::ServerName, ClientConfig, ClientConnection};
use rustls_platform_verifier::ConfigVerifierExt;
use sha2::{Digest, Sha256};
use tss_esapi::Context;
use x509_cert::{ext::pkix::SignedCertificateTimestampList, Certificate};

use crate::{
    certify_protocol::{
        add_message_to_transcript, ClientIntroMessage, ClientToServerMessage,
        ServerToClientMessage, TargetServernameV1, TranscriptMessage,
    },
    message_signing::sign_message,
    secure_connection_server::ServerSecureConnection,
    signed_message::SignableMessage,
    signing_key::AttestedKey,
};

async fn read_next_ws_binary(
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

struct TLSOpenState {
    open_from_server: bool,
    open_from_client: bool,
    verified_cert: bool,
}

async fn send_message_to_client(
    session: &mut Session,
    secure_connection: &mut ServerSecureConnection,
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
    transcript: &mut Sha256,
    bincfg: Configuration,
    secure_connection: &mut ServerSecureConnection,
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
                    add_message_to_transcript(
                        transcript,
                        bincfg,
                        &TranscriptMessage::ClosedByServer,
                    )?;
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
                add_message_to_transcript(
                    transcript,
                    bincfg,
                    &TranscriptMessage::ServerToClient(&readbuf[0..n]),
                )?;
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

pub async fn do_certify_protocol_server(
    context: &Mutex<Context>,
    attested_key: &AttestedKey,
    session: &mut Session,
    stream: &mut AggregatedMessageStream,
) -> anyhow::Result<()> {
    // Step 1: Create private channel protected by ephemeral key.
    // The key is derived from a keypair, with the public half signed
    // by the TPM2 resident signing key.
    let bincfg = bincode::config::standard();
    let intro_msg = read_next_ws_binary(session, stream)
        .await?
        .ok_or_else(|| anyhow!("Expected initial client public key"))?;

    let intro_msg: ClientIntroMessage =
        bincode::serde::borrow_decode_from_slice(&intro_msg, bincfg)
            .context("Decoding intro msg")?
            .0;
    let client_pubkey = match intro_msg {
        ClientIntroMessage::ClientIntroV1(k) => k,
    };

    let (mut conn, server_cert) =
        ServerSecureConnection::new(&mut context.lock().unwrap(), client_pubkey, attested_key)?;

    session
        .binary(bincode::serde::encode_to_vec(server_cert, bincfg)?)
        .await?;

    // Step 2: The client sends the target servername...
    let servername_msg = read_next_ws_binary(session, stream)
        .await?
        .ok_or_else(|| anyhow!("Expected servername message"))?;
    let servername_msg = conn.decrypt_client_to_server(&servername_msg)?;
    let servername: TargetServernameV1 =
        bincode::serde::borrow_decode_from_slice(&servername_msg, bincfg)?.0;

    let mut tls_state = ClientConnection::new(
        ClientConfig::with_platform_verifier().into(),
        ServerName::try_from(servername.servername.clone())?,
    )?;

    let mut transcript: Sha256 = Sha256::new();

    // Step 3: Process and react to ordinary messages from the client.
    let cert_result = certify_core_loop(
        session,
        stream,
        bincfg,
        &mut conn,
        servername,
        &mut tls_state,
        &mut transcript,
    )
    .await;

    if let Err(e) = cert_result {
        send_message_to_client(
            session,
            &mut conn,
            &ServerToClientMessage::EncounteredError(e.to_string()),
            bincfg,
        )
        .await?;
        return Err(e);
    }

    let transcript_msg = sign_message(
        &mut context.lock().unwrap(),
        &SignableMessage::Transcript(transcript.finalize().to_vec()),
        attested_key,
    )?;
    send_message_to_client(
        session,
        &mut conn,
        &ServerToClientMessage::TranscriptAvailable(transcript_msg),
        bincfg,
    )
    .await
}

async fn certify_core_loop(
    session: &mut Session,
    stream: &mut AggregatedMessageStream,
    bincfg: Configuration,
    conn: &mut ServerSecureConnection,
    servername: TargetServernameV1,
    tls_state: &mut ClientConnection,
    transcript: &mut Sha256,
) -> Result<(), anyhow::Error> {
    let mut open_state: TLSOpenState = TLSOpenState {
        open_from_server: true,
        open_from_client: true,
        verified_cert: true,
    };

    loop {
        let incoming = read_next_ws_binary(session, stream)
            .await?
            .ok_or_else(|| anyhow!("Unexpected end of client connection"))?;
        let incoming = conn.decrypt_client_to_server(&incoming)?;
        let incoming: ClientToServerMessage =
            bincode::serde::borrow_decode_from_slice(&incoming, bincfg)?.0;
        match incoming {
            ClientToServerMessage::ReceivedFromClient(msg) => {
                add_message_to_transcript(
                    transcript,
                    bincfg,
                    &TranscriptMessage::ClientToServer(&msg),
                )?;
                tls_state.writer().write_all(&msg)?;
                handle_send_tlsconn_to_ws(
                    session,
                    tls_state,
                    transcript,
                    bincfg,
                    conn,
                    &mut open_state,
                )
                .await?;
            }
            ClientToServerMessage::ReceivedFromServer(msg) => {
                let mut buf_read = Cursor::new(&msg);

                while buf_read.has_remaining() {
                    tls_state.read_tls(&mut buf_read)?;
                    tls_state.process_new_packets()?;

                    check_cert_verified(
                        session,
                        bincfg,
                        &mut open_state,
                        &servername,
                        &tls_state,
                        conn,
                        transcript,
                    )
                    .await?;
                    handle_send_tlsconn_to_ws(
                        session,
                        tls_state,
                        transcript,
                        bincfg,
                        conn,
                        &mut open_state,
                    )
                    .await?;
                }
            }
            ClientToServerMessage::DisconnectFromClient => {
                open_state.open_from_client = false;
                tls_state.send_close_notify();
                add_message_to_transcript(transcript, bincfg, &TranscriptMessage::ClosedByClient)?;

                handle_send_tlsconn_to_ws(
                    session,
                    tls_state,
                    transcript,
                    bincfg,
                    conn,
                    &mut open_state,
                )
                .await?;
            }
        }

        if !open_state.open_from_client && !open_state.open_from_server {
            break;
        }
    }
    Ok(())
}

async fn check_cert_verified(
    session: &mut Session,
    bincfg: Configuration,
    open_state: &mut TLSOpenState,
    servername: &TargetServernameV1,
    tls_state: &ClientConnection,
    secure_connection: &mut ServerSecureConnection,
    transcript: &mut Sha256,
) -> Result<(), anyhow::Error> {
    if !open_state.verified_cert {
        if let Some(&[ref cert, ..]) = tls_state.peer_certificates() {
            let decoded_cert = Certificate::from_der(cert.as_ref())?;
            let certs = decoded_cert
                .tbs_certificate
                .extensions
                .ok_or_else(|| anyhow!("Expected certificate to have extensions"))?;
            let sct_extension = certs
                .into_iter()
                .find(|ex| ex.extn_id == SignedCertificateTimestampList::OID)
                .ok_or_else(|| anyhow!("Expected certificate to have Certificate Transparency"))?;
            let sct_list =
                SignedCertificateTimestampList::from_der(sct_extension.extn_value.as_bytes())?;
            let sct_list = sct_list
                .parse_timestamps()
                .map_err(|_| anyhow!("Couldn't parse certificate transparency SCTs"))?;
            let first_sct = sct_list
                .first()
                .ok_or_else(|| anyhow!("No certificate transparency SCTs parsed"))?;
            let first_sct = first_sct
                .parse_timestamp()
                .map_err(|_| anyhow!("Couldn't parse first certificate transparency SCT"))?;

            add_message_to_transcript(
                transcript,
                bincfg,
                &TranscriptMessage::ValidServerX509 {
                    server_name: &servername.servername,
                    rfc9162_log_id: &first_sct.log_id.key_id,
                    rfc9162_timestamp: first_sct.timestamp,
                },
            )?;
            send_message_to_client(
                session,
                secure_connection,
                &ServerToClientMessage::ValidServerX509 {
                    rfc9162_log_id: first_sct.log_id.key_id.to_vec(),
                    rfc9162_timestamp: first_sct.timestamp,
                },
                bincfg,
            )
            .await?;
            open_state.verified_cert = true;
        }
    }
    Ok(())
}
