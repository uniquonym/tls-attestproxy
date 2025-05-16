use serde::{Deserialize, Serialize};
use serde_with::serde_as;

use crate::signed_message::SignedMessage;
use crate::signing_key_attestation::AttestationRaw;
use serde_with::base64::{Base64, Standard};
use serde_with::formats::Unpadded;

#[serde_as]
#[derive(Serialize, Deserialize, Eq, Ord, Clone, PartialEq, PartialOrd, Debug)]
pub enum TranscriptMessage {
    ValidServerX509 {
        server_name: String,
        // The RFC9162 (Certificate Transparency 2) parameters are for
        // diagnosis of problems - they make it possible to track down
        // what certificate was used.
        #[serde_as(as = "Base64<Standard, Unpadded>")]
        rfc9162_log_id: [u8; 32],
        rfc9162_timestamp: u64,
    },
    ServerToClient(#[serde_as(as = "Base64<Standard, Unpadded>")] Vec<u8>),
    ClientToServer(#[serde_as(as = "Base64<Standard, Unpadded>")] Vec<u8>),
    ClosedByClient,
    ClosedByServer,
}

/// A SignedTranscript represents cryptographic proof that a given plaintext transcript happened
/// over TLS (with a validated X.509 certificate trusted by the proxy).
#[derive(Serialize, Deserialize, Eq, PartialEq, Debug)]
pub struct SignedTranscript {
    /// Attestation chaining the message signing key back to an attestation key.
    pub key_attestation: AttestationRaw,
    /// Attestation by the message signing key to the transcript.
    pub message_attestation: SignedMessage,
    /// The actual sequence of plaintext.
    pub transcript: Vec<TranscriptMessage>,
}
