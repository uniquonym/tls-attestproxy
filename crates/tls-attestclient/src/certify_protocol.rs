use p256::PublicKey;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

use serde_with::base64::{Base64, Standard};
use serde_with::formats::Unpadded;
use tls_attestverify::signed_message::SignedMessage;

#[derive(Serialize, Deserialize, Eq, Ord, Clone, PartialEq, PartialOrd)]
pub enum ClientIntroMessage {
    ClientIntroV1(PublicKey),
}

#[derive(Serialize, Deserialize, Eq, Ord, Clone, PartialEq, PartialOrd)]
pub struct TargetServernameV1 {
    pub servername: String,
}

#[derive(Serialize, Deserialize, Eq, Ord, Clone, PartialEq, PartialOrd, Debug)]
pub enum ClientToServerMessage {
    ReceivedFromClient(Vec<u8>),
    ReceivedFromServer(Vec<u8>),
    DisconnectFromClient,
}

#[serde_as]
#[derive(Serialize, Deserialize, Eq, Ord, Clone, PartialEq, PartialOrd, Debug)]
pub enum ServerToClientMessage {
    SendToServer(Vec<u8>),
    SendToClient(Vec<u8>),
    DisconnectFromServer,
    TranscriptAvailable(SignedMessage),
    ValidServerX509 {
        // The RFC9162 (Certificate Transparency 2) parameters are for
        // diagnosis of problems - they make it possible to track down
        // what certificate was used.
        #[serde_as(as = "Base64<Standard, Unpadded>")]
        rfc9162_log_id: [u8; 32],
        rfc9162_timestamp: u64,
    },
    // If this happens, no transcript can be produced & the connection should
    // be closed.
    EncounteredError(String),
}
