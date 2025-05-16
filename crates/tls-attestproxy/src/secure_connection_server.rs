use aes_gcm::{
    aead::{Aead, KeyInit, OsRng, Payload},
    Aes256Gcm,
};
use anyhow::{bail, Context as ErrContext};
use p256::{elliptic_curve::ecdh::EphemeralSecret, PublicKey};
use tls_attestclient::secure_connection::{
    create_nonce, derive_cipher_key, FlowDirection, SecureConnectionState,
};
use tss_esapi::Context;

use crate::{message_signing::sign_message, signing_key::AttestedKey};
use tls_attestverify::signed_message::{SignableMessage, SignedMessage};

pub struct ServerSecureConnection(SecureConnectionState);
impl ServerSecureConnection {
    pub fn new(
        context: &mut Context,
        client_public_key: PublicKey,
        sign_key: &AttestedKey,
    ) -> anyhow::Result<(Self, SignedMessage)> {
        let server_secret = EphemeralSecret::random(&mut OsRng::default());
        let shared_secret = server_secret.diffie_hellman(&client_public_key);
        let server_public_key = server_secret.public_key();

        let signed_key = sign_message(
            context,
            &SignableMessage::EcdhePublicKey(server_public_key),
            sign_key,
        )
        .context("Signing server's ECDHE public key")?;

        let shared_secret = derive_cipher_key(&shared_secret)?;

        Ok((
            Self(SecureConnectionState {
                cipher: Aes256Gcm::new(&shared_secret),
                client_sequence: 0,
                server_sequence: 0,
            }),
            signed_key,
        ))
    }

    pub fn encrypt_server_to_client(&mut self, plaintext: &[u8]) -> anyhow::Result<Vec<u8>> {
        let nonce = create_nonce(FlowDirection::ServerToClient, self.0.server_sequence);

        let payload = Payload {
            msg: plaintext,
            aad: &[],
        };
        if self.0.server_sequence == u64::MAX {
            bail!("Server->Client reached maximum for cipher.");
        }
        self.0.server_sequence += 1;

        let ciphertext = self
            .0
            .cipher
            .encrypt(&nonce, payload)
            .map_err(|_e| anyhow::anyhow!("Encryption error"))?;

        Ok(ciphertext)
    }

    pub fn decrypt_client_to_server(&mut self, ciphertext: &[u8]) -> anyhow::Result<Vec<u8>> {
        let nonce = create_nonce(FlowDirection::ClientToServer, self.0.client_sequence);

        let payload = Payload {
            msg: ciphertext,
            aad: &[],
        };
        if self.0.client_sequence == u64::MAX {
            bail!("Client->Server reached maximum for cipher.");
        }
        self.0.client_sequence += 1;

        let plaintext = self
            .0
            .cipher
            .decrypt(&nonce, payload)
            .map_err(|_e| anyhow::anyhow!("Decryption error"))?;

        Ok(plaintext)
    }
}
