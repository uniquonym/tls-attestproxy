use std::{collections::HashSet, pin::Pin};

use aes_gcm::aead::OsRng;
use anyhow::anyhow;
use http::{
    Uri,
    uri::{Parts, PathAndQuery},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream},
    net::{TcpStream, ToSocketAddrs},
    spawn,
};
use tokio_websockets::{MaybeTlsStream, Message, WebSocketStream};
use zerocopy::IntoBytes;

use crate::{
    certify_protocol::{
        ClientIntroMessage, ClientToServerMessage, ServerToClientMessage, TargetServernameV1,
    },
    message_verification::MessageVerification,
    secure_connection_client::SecureConnectionClient,
    signed_message::SignedMessage,
    signing_key_attestation::{AttestationRaw, TrustedPCRSet, calculate_pcr_policy_hash},
};
use futures_util::{SinkExt, StreamExt};

pub struct ProxyInfo {
    pub ws_uri: Uri,
    pub attestation_pubkey: rsa::RsaPublicKey,
    pub allowed_proxy_pcrs: HashSet<TrustedPCRSet>,
}

pub struct Certification {}

type WSStream = WebSocketStream<MaybeTlsStream<TcpStream>>;

async fn next_ws_binary(stream: &mut WSStream) -> anyhow::Result<Option<Vec<u8>>> {
    loop {
        match stream.next().await {
            None => break Ok(None),
            Some(Err(e)) => Err(e)?,
            Some(Ok(m)) => {
                if m.is_ping() {
                    stream.send(Message::pong(m.as_payload().clone())).await?;
                } else if m.is_binary() {
                    break Ok(Some(m.as_payload().as_bytes().to_vec()));
                }
            }
        }
    }
}

async fn core_loop(
    ws: &mut WSStream,
    tls: &mut TcpStream,
    local: &mut DuplexStream,
    secure_connection: &mut SecureConnectionClient,
) -> anyhow::Result<CertifyOutcome> {
    let mut local_buf: [u8; 2048] = [0; 2048];
    let mut tls_buf: [u8; 2048] = [0; 2048];
    let mut local_open = true;
    let mut tls_open = true;
    let bincfg = bincode::config::standard();

    loop {
        tokio::select! {
            local_bytes = local.read(&mut local_buf), if local_open => {
                match local_bytes {
                    Err(e) => return Ok(CertifyOutcome::LocalIoError(e.into())),
                    Ok(0) => {
                        local_open = false;
                        let msg = bincode::serde::encode_to_vec(&ClientToServerMessage::DisconnectFromClient, bincfg)?;
                        if let Err(e) = ws.send(Message::binary(
                            secure_connection.encrypt_client_to_server(&msg)?,
                        ))
                        .await {
                            return Ok(CertifyOutcome::WebsocketIoError(e.into()));
                        }
                    },
                    Ok(n) => {
                        let msg = bincode::serde::encode_to_vec(&ClientToServerMessage::ReceivedFromClient(local_buf[0..n].to_vec()), bincfg)?;
                        if let Err(e) = ws.send(Message::binary(
                            secure_connection.encrypt_client_to_server(&msg)?,
                        ))
                        .await {
                            return Ok(CertifyOutcome::WebsocketIoError(e.into()));
                        }

                    }
                }
            },
            tls_bytes = tls.read(&mut tls_buf), if tls_open => {
                match tls_bytes {
                    Err(e) => return Ok(CertifyOutcome::TlsSocketIoError(e.into())),
                    Ok(0) => {
                        // The other end should have received an encrypted alert already, if the TLS server
                        // follows the protocol - so we don't need to inform the proxy.
                        tls_open = false;
                    },
                    Ok(n) => {
                        let msg = bincode::serde::encode_to_vec(&ClientToServerMessage::ReceivedFromServer(tls_buf[0..n].to_vec()), bincfg)?;
                        if let Err(e) = ws.send(Message::binary(
                            secure_connection.encrypt_client_to_server(&msg)?,
                        ))
                        .await {
                            return Ok(CertifyOutcome::WebsocketIoError(e.into()));
                        }

                    }
                }
            },
            r = next_ws_binary(ws) => {
                match r {
                    Ok(None) => return Ok(CertifyOutcome::WebsocketIoError(anyhow!("Premature WebSocket closure"))),
                    Ok(Some(msg)) => {
                        let (msg, _): (ServerToClientMessage, usize) = bincode::serde::decode_from_slice(&secure_connection.decrypt_server_to_client(&msg)?, bincfg)?;
                        match msg {
                            ServerToClientMessage::SendToServer(data) => {
                                if let Err(e) = tls.write_all(&data).await {
                                    return Ok(CertifyOutcome::TlsSocketIoError(e.into()));
                                }
                                if let Err(e) = tls.flush().await {
                                    return Ok(CertifyOutcome::TlsSocketIoError(e.into()));
                                }
                            },
                            ServerToClientMessage::SendToClient(data) => {
                                if let Err(e) = local.write_all(&data).await {
                                    return Ok(CertifyOutcome::LocalIoError(e.into()));
                                }
                                if let Err(e) = local.flush().await {
                                    return Ok(CertifyOutcome::LocalIoError(e.into()));
                                }
                            },
                            ServerToClientMessage::DisconnectFromServer => {
                                let _ = tls.shutdown().await;
                                tls_open = false;
                            },
                            ServerToClientMessage::TranscriptAvailable(signed_message) => {
                                return Ok(CertifyOutcome::Success { attestation: signed_message })
                            },
                            ServerToClientMessage::ValidServerX509 { .. } => {
                                // To do: Transcript update
                            },
                            ServerToClientMessage::EncounteredError(msg) => return Ok(CertifyOutcome::ProtocolErrorReceived(msg)),
                        }
                    },
                    Err(e) => return Ok(CertifyOutcome::WebsocketIoError(e)),
                }
            }
        }
    }
}

pub enum CertifyOutcome {
    LocalIoError(anyhow::Error),
    WebsocketIoError(anyhow::Error),
    TlsSocketIoError(anyhow::Error),
    ProtocolErrorReceived(String),
    OtherError(anyhow::Error),
    Success { attestation: SignedMessage },
}

/// An open connection to a TLS server that can be written or read to.
/// Both sides of the connection go via an attesting proxy, which creates a signed transcript.
/// Call finalise() to shutdown the session and attempt to get a transcript.
pub struct TlsCertifySession {
    local_stream: Pin<Box<DuplexStream>>,
    result_receiver: tokio::sync::mpsc::Receiver<CertifyOutcome>,
}

impl AsyncRead for TlsCertifySession {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        return self.local_stream.as_mut().poll_read(cx, buf);
    }
}

impl AsyncWrite for TlsCertifySession {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        return self.local_stream.as_mut().poll_write(cx, buf);
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        return self.local_stream.as_mut().poll_flush(cx);
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        return self.local_stream.as_mut().poll_shutdown(cx);
    }
}

impl TlsCertifySession {
    pub async fn finalise(mut self) -> CertifyOutcome {
        if let Err(e) = self.local_stream.shutdown().await {
            return CertifyOutcome::LocalIoError(e.into());
        }
        match self.result_receiver.recv().await {
            Some(r) => r,
            None => CertifyOutcome::OtherError(anyhow!(
                "Session processing shutdown unexpectedly with no outcome"
            )),
        }
    }
}

/// Connects a TLS stream, while sending data to a certifying "proxy" to be
/// encrypted and included in a signed transcript. Note traffic to the TLS
/// server is still sent locally, only the encryption happens on the proxy.
///
/// tls_server_addr is where to connect for upstream TLS server.
/// servername is the hostname to request from the server (with Server Name Indication).
/// proxy_info has details on how to connect and establish trust with the proxy.
/// # Errors
/// Returns an Err with the error as the cause if the proxy fails (e.g. proxy doesn't
/// trust CA). Can also similarly return an error if there is an IO problem talking to
/// the TLS server or to the proxy, or the proxy cannot be authenticated.
pub async fn certify_tls<A: ToSocketAddrs>(
    tls_server_addr: A,
    servername: &str,
    proxy_info: &ProxyInfo,
) -> anyhow::Result<TlsCertifySession> {
    let bincfg = bincode::config::standard();
    // Optimised for simplicity for now - we could do more in paralell.
    let mut tls_stream = TcpStream::connect(tls_server_addr).await?;

    let mut full_uri: Parts = proxy_info.ws_uri.clone().into_parts();
    full_uri.path_and_query = Some(PathAndQuery::from_static("/v1/tlscertify"));
    let full_uri: Uri = full_uri.try_into()?;
    let (mut ws_conn, _) = tokio_websockets::client::Builder::new()
        .uri(&full_uri.to_string())?
        .connect()
        .await?;

    let secure_connection = SecureConnectionClient::new(&mut OsRng::default());
    let client_intro = bincode::serde::encode_to_vec(
        ClientIntroMessage::ClientIntroV1(secure_connection.pubkey()),
        bincfg,
    )?;
    ws_conn.send(Message::binary(client_intro)).await?;

    let ((key_msg, attest), _): ((SignedMessage, AttestationRaw), usize) =
        bincode::serde::borrow_decode_from_slice(
            &next_ws_binary(&mut ws_conn)
                .await?
                .ok_or_else(|| anyhow!("WebSocket closed during handshake"))?,
            bincfg,
        )?;
    let msg_verifier = MessageVerification::setup(
        &attest,
        &proxy_info.attestation_pubkey,
        &proxy_info
            .allowed_proxy_pcrs
            .iter()
            .map(|trusted_pcrset| calculate_pcr_policy_hash(trusted_pcrset))
            .collect(),
    )?;
    let mut secure_connection = secure_connection.complete_handshake(&msg_verifier, &key_msg)?;

    // We've now got a trusted channel to the server. Send the hostname...
    let msg = bincode::serde::encode_to_vec(
        &TargetServernameV1 {
            servername: servername.to_string(),
        },
        bincfg,
    )?;
    ws_conn
        .send(Message::binary(
            secure_connection.encrypt_client_to_server(&msg)?,
        ))
        .await?;

    let (mut local, remote) = tokio::io::duplex(1024);
    let (tx_result, rx_result) = tokio::sync::mpsc::channel::<CertifyOutcome>(1);

    spawn(async move {
        match core_loop(
            &mut ws_conn,
            &mut tls_stream,
            &mut local,
            &mut secure_connection,
        )
        .await
        {
            Ok(outcome) => {
                let _ = local.shutdown().await;
                let _ = ws_conn.close().await;
                let _ = tls_stream.shutdown().await;
                let _ = tx_result.send(outcome).await;
            }
            Err(e) => {
                let _ = local.shutdown().await;
                let _ = ws_conn.close().await;
                let _ = tls_stream.shutdown().await;
                let _ = tx_result.send(CertifyOutcome::OtherError(e)).await;
            }
        }
    });

    Ok(TlsCertifySession {
        local_stream: Box::pin(remote),
        result_receiver: rx_result,
    })
}
