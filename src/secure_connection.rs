use aes_gcm::{AeadCore, Aes256Gcm, Key, Nonce};
use anyhow::anyhow;
use k256::ecdh::SharedSecret;
use sha2::Sha256;

pub struct SecureConnectionState {
    /// The cipher, including the key embedded in it
    pub cipher: Aes256Gcm,
    /// Sequence number for client->server messages
    pub client_sequence: u64,
    /// Sequence number for server->client messages
    pub server_sequence: u64,
}

pub fn derive_cipher_key(shared_secret: &SharedSecret) -> anyhow::Result<Key<Aes256Gcm>> {
    let mut key: Key<Aes256Gcm> = Key::<Aes256Gcm>::default();
    shared_secret
        .extract::<Sha256>(None)
        .expand(&[], key.as_mut_slice())
        .map_err(|_| anyhow!("Expanding cipher key"))?;
    Ok(key)
}

pub enum FlowDirection {
    ServerToClient,
    ClientToServer,
}

pub type AeadNonce = Nonce<<Aes256Gcm as AeadCore>::NonceSize>;
pub fn create_nonce(direction: FlowDirection, sequence: u64) -> AeadNonce {
    let mut nonce: AeadNonce = AeadNonce::default();
    nonce[0] = match direction {
        FlowDirection::ServerToClient => 0x80,
        FlowDirection::ClientToServer => 0x00,
    };

    nonce[1..9].copy_from_slice(&sequence.to_be_bytes());

    nonce
}
