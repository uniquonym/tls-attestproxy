use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit};
use anyhow::bail;
use p256::PublicKey;
use p256::ecdh::EphemeralSecret;
use rsa::rand_core::CryptoRngCore;

use crate::secure_connection::{
    FlowDirection, SecureConnectionState, create_nonce, derive_cipher_key,
};
use tls_attestverify::message_verification::MessageVerification;
use tls_attestverify::signed_message::{SignableMessage, SignedMessage};

pub struct SecureConnectionHandshake {
    ephemeral: EphemeralSecret,
}
pub struct SecureConnectionClient(SecureConnectionState);

impl SecureConnectionClient {
    pub fn new(rng: &mut impl CryptoRngCore) -> SecureConnectionHandshake {
        SecureConnectionHandshake {
            ephemeral: EphemeralSecret::random(rng),
        }
    }

    pub fn encrypt_client_to_server(&mut self, plaintext: &[u8]) -> anyhow::Result<Vec<u8>> {
        let nonce = create_nonce(FlowDirection::ClientToServer, self.0.client_sequence);

        let payload = Payload {
            msg: plaintext,
            aad: &[],
        };
        if self.0.client_sequence == u64::MAX {
            bail!("Client->Server reached maximum for cipher.");
        }
        self.0.client_sequence += 1;

        let ciphertext = self
            .0
            .cipher
            .encrypt(&nonce, payload)
            .map_err(|_e| anyhow::anyhow!("Encryption error"))?;

        Ok(ciphertext)
    }

    pub fn decrypt_server_to_client(&mut self, ciphertext: &[u8]) -> anyhow::Result<Vec<u8>> {
        let nonce = create_nonce(FlowDirection::ServerToClient, self.0.server_sequence);

        let payload = Payload {
            msg: ciphertext,
            aad: &[],
        };
        if self.0.server_sequence == u64::MAX {
            bail!("Server->Client reached maximum for cipher.");
        }
        self.0.server_sequence += 1;

        let plaintext = self
            .0
            .cipher
            .decrypt(&nonce, payload)
            .map_err(|_e| anyhow::anyhow!("Decryption error"))?;

        Ok(plaintext)
    }
}

impl SecureConnectionHandshake {
    pub fn pubkey(&self) -> PublicKey {
        self.ephemeral.public_key()
    }

    pub fn complete_handshake(
        self,
        verifier: &MessageVerification,
        msg: &SignedMessage,
    ) -> anyhow::Result<SecureConnectionClient> {
        match verifier.verify(&msg)? {
            SignableMessage::EcdhePublicKey(public_key) => {
                Ok(SecureConnectionClient(SecureConnectionState {
                    cipher: Aes256Gcm::new(&derive_cipher_key(
                        &self.ephemeral.diffie_hellman(public_key),
                    )?),
                    client_sequence: 0,
                    server_sequence: 0,
                }))
            }
            _ => bail!("Handshake pubkey message had unexpected type"),
        }
    }
}
