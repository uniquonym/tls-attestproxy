use anyhow::Context as ErrContext;
use sha2::{Digest, Sha256};
use tss_esapi::{
    interface_types::algorithm::HashingAlgorithm,
    structures::{Digest as TpmDigest, HashScheme, Signature, SignatureScheme},
    traits::Marshall,
    Context,
};

use crate::{
    signed_message::{SignableMessage, SignedMessage},
    signing_key::AttestedKey,
};

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
            None,
        )
        .context("Signing message")?;
    let signature = sig.marshall()?;
    Ok(SignedMessage {
        message: input.clone(),
        signature,
    })
}
