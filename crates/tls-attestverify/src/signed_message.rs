use std::io::Write;

use bincode::config::Configuration;
use p256::PublicKey;
use serde::{Deserialize, Serialize};

use crate::signed_transcript::TranscriptMessage;

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

pub fn add_message_to_transcript<D: Write>(
    transcript_digest: &mut D,
    bincfg: Configuration,
    msg: &TranscriptMessage,
) -> anyhow::Result<()> {
    bincode::serde::encode_into_std_write(msg, transcript_digest, bincfg)?;
    Ok(())
}
