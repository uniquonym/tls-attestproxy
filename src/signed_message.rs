use anyhow::Context as ErrContext;
use k256::PublicKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tss_esapi::{
    interface_types::algorithm::HashingAlgorithm,
    structures::{Digest as TpmDigest, HashScheme, Signature, SignatureScheme},
    traits::Marshall,
    Context,
};

use crate::signing_key::AttestedKey;

#[derive(Serialize, Deserialize, Eq, Ord, Clone, PartialEq, PartialOrd)]
pub enum TranscriptMessage {
    ValidServerX509 {
        server_name: String,
        // The RFC9162 (Certificate Transparency 2) parameters are for
        // diagnosis of problems - they make it possible to track down
        // what certificate was used.
        rfc9162_log_id: Vec<u8>,
        rfc9162_leaf_hash: Vec<u8>,
    },
    ServerToClient(Vec<u8>),
    ClientToServer(Vec<u8>),
    ClosedByClient,
    ClosedByServer,
}

#[derive(Serialize, Deserialize, Clone, Eq, Ord, PartialEq, PartialOrd)]
pub enum SignableMessage {
    EcdhePublicKey(PublicKey),
    Transcript(Vec<TranscriptMessage>),
}

#[derive(Serialize, Deserialize)]
pub struct SignedMessage {
    message: SignableMessage,
    signature: Vec<u8>,
}

pub fn sign_message(
    context: &mut Context,
    input: &SignableMessage,
    sign_key: &AttestedKey,
) -> anyhow::Result<SignedMessage> {
    let mut hasher = Sha256::new();
    bincode::serde::encode_into_std_write(input, &mut hasher, bincode::config::standard())?;
    let digest = TpmDigest::from_bytes(&hasher.finalize())?;

    let sig: Signature = context
        .sign(
            sign_key.handle,
            digest,
            SignatureScheme::EcSchnorr {
                scheme: HashScheme::new(HashingAlgorithm::Sha256),
            },
            None
        )
        .context("Signing message")?;
    let signature = sig.marshall()?;
    Ok(SignedMessage {
        message: input.clone(),
        signature,
    })
}
