use aes_gcm::{
    aead::{Aead, KeyInit, OsRng, Payload},
    AeadCore, Aes256Gcm, Key, Nonce,
};
use anyhow::{anyhow, bail, Context as ErrContext};
use k256::{ecdh::SharedSecret, elliptic_curve::ecdh::EphemeralSecret, PublicKey};
use sha2::Sha256;
use tss_esapi::Context;

use crate::{
    message_signing::sign_message,
    signed_message::{SignableMessage, SignedMessage},
    signing_key::AttestedKey,
};

pub struct SecureConnection {
    /// The cipher, including the key embedded in it
    cipher: Aes256Gcm,
    /// Sequence number for client->server messages
    client_sequence: u64,
    /// Sequence number for server->client messages
    server_sequence: u64,
}

/// Derives a cipher key from the shared secret
fn derive_cipher_key(shared_secret: &SharedSecret) -> anyhow::Result<Key<Aes256Gcm>> {
    let mut key: Key<Aes256Gcm> = Key::<Aes256Gcm>::default();
    shared_secret
        .extract::<Sha256>(None)
        .expand(&[], key.as_mut_slice())
        .map_err(|_| anyhow!("Expanding cipher key"))?;
    Ok(key)
}

enum FlowDirection {
    ServerToClient,
    ClientToServer,
}

type AeadNonce = Nonce<<Aes256Gcm as AeadCore>::NonceSize>;
fn create_nonce(direction: FlowDirection, sequence: u64) -> AeadNonce {
    let mut nonce: AeadNonce = AeadNonce::default();
    nonce[0] = match direction {
        FlowDirection::ServerToClient => 0x80,
        FlowDirection::ClientToServer => 0x00,
    };

    nonce[1..9].copy_from_slice(&sequence.to_be_bytes());

    nonce
}

impl SecureConnection {
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
            Self {
                cipher: Aes256Gcm::new(&shared_secret),
                client_sequence: 0,
                server_sequence: 0,
            },
            signed_key,
        ))
    }

    pub fn encrypt_server_to_client(&mut self, plaintext: &[u8]) -> anyhow::Result<Vec<u8>> {
        let nonce = create_nonce(FlowDirection::ServerToClient, self.server_sequence);

        let payload = Payload {
            msg: plaintext,
            aad: &[],
        };
        if self.server_sequence == u64::MAX {
            bail!("Server->Client reached maximum for cipher.");
        }
        self.server_sequence += 1;

        let ciphertext = self
            .cipher
            .encrypt(&nonce, payload)
            .map_err(|_e| anyhow::anyhow!("Encryption error"))?;

        Ok(ciphertext)
    }

    pub fn decrypt_client_to_server(&mut self, ciphertext: &[u8]) -> anyhow::Result<Vec<u8>> {
        let nonce = create_nonce(FlowDirection::ClientToServer, self.client_sequence);

        let payload = Payload {
            msg: ciphertext,
            aad: &[],
        };
        if self.client_sequence == u64::MAX {
            bail!("Client->Server reached maximum for cipher.");
        }
        self.client_sequence += 1;

        let plaintext = self
            .cipher
            .decrypt(&nonce, payload)
            .map_err(|_e| anyhow::anyhow!("Decryption error"))?;

        Ok(plaintext)
    }
}
