use std::collections::HashSet;

use anyhow::bail;
use rsa::RsaPublicKey;
use sha2::{Digest, Sha256};

use crate::{
    message_verification::MessageVerification,
    signed_message::{SignableMessage, add_message_to_transcript},
    signed_transcript::SignedTranscript,
    signing_key_attestation::PolicyHash,
};

/// Checks that a TranscriptMessage is valid and the signature chains back to the key.
pub fn verify_transcript(
    transcript: &SignedTranscript,
    attestation_key: &RsaPublicKey,
    trusted_policy_hashes: &HashSet<PolicyHash>,
) -> anyhow::Result<()> {
    let msg_verifier = MessageVerification::setup(
        &transcript.key_attestation,
        attestation_key,
        trusted_policy_hashes,
    )?;

    let signable_msg = msg_verifier.verify(&transcript.message_attestation)?;

    let mut transcript_hash = Sha256::new();
    let bincfg = bincode::config::standard();
    for msg in &transcript.transcript {
        add_message_to_transcript(&mut transcript_hash, bincfg, msg)?;
    }

    let signed_transcript_hash = match signable_msg {
        SignableMessage::Transcript(items) => items,
        _ => bail!("Signed transcript message wasn't actually a transcript"),
    };

    if transcript_hash.finalize().as_slice() != signed_transcript_hash.as_slice() {
        bail!("Signed transcript message hash didn't match actual hash");
    }

    Ok(())
}
