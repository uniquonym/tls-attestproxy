use p256::PublicKey;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Eq, Ord, PartialEq, PartialOrd, Debug)]
pub enum SignableMessage {
    EcdhePublicKey(PublicKey),
    Transcript(Vec<u8>),
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Ord, PartialOrd, Clone, Debug)]
pub struct SignedMessage {
    pub message: SignableMessage,
    pub signature: Vec<u8>,
}
