use std::collections::HashSet;

use anyhow::anyhow;
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
use rsa::RsaPublicKey;

use crate::signed_message::{SignableMessage, SignedMessage};
use crate::signing_key_attestation::{AttestationRaw, PolicyHash};

pub struct MessageVerification {
    verifying_key: VerifyingKey,
}

impl MessageVerification {
    /// Creates a MessageVerification that can be used to verify messages from
    /// an attestation.
    pub fn setup(
        attestation: &AttestationRaw,
        attestation_key: &RsaPublicKey,
        trusted_policy_hashes: &HashSet<PolicyHash>,
    ) -> anyhow::Result<MessageVerification> {
        let signing_key =
            attestation.validate_and_get_key(attestation_key, &trusted_policy_hashes)?;
        Ok(MessageVerification {
            verifying_key: VerifyingKey::from(&signing_key),
        })
    }

    pub fn verify<'msgl>(
        &self,
        msg: &'msgl SignedMessage,
    ) -> anyhow::Result<&'msgl SignableMessage> {
        let msg_bytes = bincode::serde::encode_to_vec(&msg.message, bincode::config::standard())?;
        let signature =
            Signature::from_slice(&msg.signature).map_err(|_| anyhow!("Invalid signature"))?;
        self.verifying_key
            .verify(&msg_bytes, &signature)
            .map_err(|_| anyhow!("Signature didn't verify"))?;
        Ok(&msg.message)
    }
}
