use std::io::Cursor;

use crate::signing_key::AttestedKey;
use anyhow::{bail, Context as ErrContext};
use binrw::{binread, BinRead};
use elliptic_curve::generic_array::GenericArray;
use p256::{ecdsa::Signature as ECSignature, U32};
use sha2::{Digest, Sha256};
use tls_attestclient::signed_message::{SignableMessage, SignedMessage};
use tss_esapi::{
    interface_types::algorithm::HashingAlgorithm,
    structures::{Digest as TpmDigest, HashScheme, Signature, SignatureScheme},
    traits::Marshall,
    Context,
};

#[binread]
#[allow(dead_code)]
// 16 bit algorithm: ECDSA = 0x0018
// 16 bit hash algorithm: SHA256 = 0x000B
#[br(big, magic = b"\x00\x18\x00\x0B")]
struct TpmEcdsaSignature {
    r_len: u16,
    #[br(count = r_len)]
    r_param: Vec<u8>,
    s_len: u16,
    #[br(count = s_len)]
    s_param: Vec<u8>,
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
            SignatureScheme::EcDsa {
                scheme: HashScheme::new(HashingAlgorithm::Sha256),
            },
            None,
        )
        .context("Signing message")?;
    let signature = sig.marshall()?;
    let signature = TpmEcdsaSignature::read(&mut Cursor::new(signature))
        .context("Error decoding TPM signature")?;
    if signature.s_len < 32 || signature.r_len < 32 {
        bail!("Scalar TPM signature parameters too short");
    }
    let r: &GenericArray<u8, U32> = signature.r_param
        [((signature.r_len as usize) - 32)..(signature.r_len as usize)]
        .try_into()?;
    let s: &GenericArray<u8, U32> = signature.s_param
        [((signature.s_len as usize) - 32)..(signature.s_len as usize)]
        .try_into()?;
    let signature = ECSignature::from_scalars(*r, *s).context("Constructing ECDSA signature")?;
    Ok(SignedMessage {
        message: input.clone(),
        signature: signature.to_vec(),
    })
}
