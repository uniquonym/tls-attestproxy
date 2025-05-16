use std::collections::HashSet;
use std::io::Cursor;

use anyhow::{Context, anyhow, bail, ensure};
use binrw::{BinRead, binread};
use p256::elliptic_curve::sec1::FromEncodedPoint;
use rsa::RsaPublicKey;
use rsa::traits::SignatureScheme;
use serde::{Deserialize, Serialize};
use serde_with::base64::{Base64, Standard};
use serde_with::formats::Unpadded;
use serde_with::serde_as;
use sha2::{Digest, Sha256};

#[serde_as]
#[derive(Serialize, Deserialize, Eq, PartialEq, Debug)]
pub struct AttestationRaw {
    // Serialised TPMS_ATTEST structure.
    // 32 bit - TPM_GENERATED_VALUE tag (0xFF544347)
    // 16 bit - TPMI_ST_ATTEST type - TPM_ST_ATTEST_CREATION (0x801A)
    // Qualified signer (TPM2B_NAME)
    //   16 bit - name size
    //   bytes - data for name
    // Extra data (TPM2B_DATA)
    //   16 bit - data size
    //   bytes - data
    // TPMS_CLOCK_INFO
    //   64 bit - counter
    //   32 bit - reset count
    //   32 bit - restart count
    //   16 bit - 1 = safe.
    // 64 bit - firmware version
    // TPMU_ATTEST -> TPMS_CREATION_INFO
    // Object name (TPM2B_NAME)
    //   16 bit - name size
    //   bytes - data for name
    // Digest
    //   16 bit - digest size
    //   bytes - data for digest
    #[serde_as(as = "Base64<Standard, Unpadded>")]
    pub attest: Vec<u8>,
    // Serialised TPMT_SIGNATURE structure.
    // 16 bits: 0x14 (RSA SSA indicator)
    // 16 bits: 0xB (SHA256 indicator)
    // 16 bits: Signature length
    // 2048 bits: signature bytes (PKCS#1.5)
    #[serde_as(as = "Base64<Standard, Unpadded>")]
    pub sig: Vec<u8>,
    // Serialised TPMT_PUBLIC structure.
    #[serde_as(as = "Base64<Standard, Unpadded>")]
    //  16 bits: Algorithm type = 0x0023 TPM_ALG_ECC
    //  16 bits: Hash algorithm = 0x000B TPM_ALG_SHA256
    //  32 bits: objectAttributes - 0x2 fixed tpm | 0x10 fixed parent | 0x20 sensitive data origin | 0x40000 sign/encrypt = 0x40032
    //  16 bits: auth policy size
    //  bytes: auth policy hash
    // TPMU_PUBLIC_PARMS -> TPMS_ECC_PARMS
    //   TPMT_SYM_DEF_OBJECT -> TPM_ALG_NULL (16 bit 0x0010)
    //   TPMT_ECC_SCHEME
    //      16 bits: Scheme = TPM_ALG_ECDSA (0x0018)
    //      16 bits: Hash Scheme = TPM_ALG_SHA256 (0xB)
    //   TPMI_ECC_CURVE - 16 bits: TPM_ECC_NIST_P256 (0x3)
    //   TPMT_KDF_SCHEME - 16 bits: TPM_ALG_NULL (16 bit 0x0010)
    // TPMU_PUBLIC_ID -> TPMS_ECC_POINT
    //   TPM2B_ECC_PARAMETER x
    //      16 bit - size
    //      bytes
    //   TPM2B_ECC_PARAMETER y
    //      16 bit - size
    //      bytes
    pub public: Vec<u8>,
}

#[binread]
#[allow(dead_code)]
#[br(big, magic = b"\xFF\x54\x43\x47\x80\x1A")]
struct TpmsAttestData {
    signer_len: u16,
    #[br(count = signer_len)]
    signer_name: Vec<u8>,
    extradata_len: u16,
    #[br(count = extradata_len)]
    extradata: Vec<u8>,
    counter: u64,
    reset_count: u32,
    restart_count: u32,
    clock_safe_flags: u8,
    firmware_version: u64,
    created_object_name_len: u16,
    #[br(count = created_object_name_len)]
    created_object_name: Vec<u8>,
    // ... remaining fields unused
}

#[binread]
#[allow(dead_code)]
#[br(big, magic = b"\x00\x23\x00\x0B\x00\x04\x00\x32")]
struct TpmsEcPublicData {
    auth_policy_hash_len: u16,
    #[br(count = auth_policy_hash_len)]
    auth_policy_hash: Vec<u8>,
    // Magic covers no sym def, alg = ECDSA, hash = SHA256,
    //   curve = NistP256, no KDF scheme.
    #[br(magic = b"\x00\x10\x00\x18\x00\x0B\x00\x03\x00\x10")]
    ec_x_len: u16,
    #[br(count = ec_x_len)]
    ec_x: Vec<u8>,
    ec_y_len: u16,
    #[br(count = ec_y_len)]
    ec_y: Vec<u8>,
}

const TPMT_SIG_HEADER_LEN: usize = 6;
const TPMT_SIG_RSA_LEN: usize = 256;

#[derive(Serialize, Deserialize, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct PCRHash(pub [u8; 32]);
#[derive(Eq, Ord, Hash, PartialEq, PartialOrd)]
pub struct PolicyHash(pub [u8; 32]);

#[derive(Serialize, Deserialize, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[serde_as]
pub struct TrustedPCRSet {
    #[serde_as(as = "Hex<Lowercase>")]
    pub pcr4: PCRHash,
    #[serde_as(as = "Hex<Lowercase>")]
    pub pcr5: PCRHash,
    #[serde_as(as = "Hex<Lowercase>")]
    pub pcr7: PCRHash,
    #[serde_as(as = "Hex<Lowercase>")]
    pub pcr8: PCRHash,
    #[serde_as(as = "Hex<Lowercase>")]
    pub pcr9: PCRHash,
}

pub fn calculate_pcr_policy_hash(trusted_pcrs: &TrustedPCRSet) -> PolicyHash {
    let mut hasher = Sha256::new();
    hasher.update(trusted_pcrs.pcr4.0);
    hasher.update(trusted_pcrs.pcr5.0);
    hasher.update(trusted_pcrs.pcr7.0);
    hasher.update(trusted_pcrs.pcr8.0);
    hasher.update(trusted_pcrs.pcr9.0);
    let pcr_hash = hasher.finalize();

    let mut hasher = Sha256::new();
    // Old policy is the zero policy - we are adding to that.
    hasher.update([0; 32]);
    // Add TPM_CC_PolicyPCR (0x0000017F, 32 bits)
    // We only have one PCR selection bitmap (0x00000001, 32 bits)
    // Hash algorithm is SHA256 (0x000B, 16 bits)
    // We use a 3-byte selector size for compatiblity (0x03, 8 bit size)
    // Next is a 24-bit bitmap of the actual PCRs. This is effectively little endian - least significant PCRs first.
    // [0] 0xB0 - select PCRs 4,5,7
    // [1] 0x03 - select PCRs 8-9
    // [2] 0x00 - no PCRs 16-23
    hasher.update(b"\x00\x00\x01\x7F\x00\x00\x00\x01\x00\x0B\x03\xB0\x03\x00");
    hasher.update(pcr_hash);
    PolicyHash(hasher.finalize().into())
}

impl AttestationRaw {
    pub fn validate_and_get_key(
        &self,
        parent_key: &RsaPublicKey,
        allowed_auth_hashes: &HashSet<PolicyHash>,
    ) -> anyhow::Result<p256::PublicKey> {
        // Validate the attestation against the parent key...
        if self.sig.len() < TPMT_SIG_HEADER_LEN + TPMT_SIG_RSA_LEN {
            bail!("Attestation signature too short");
        }
        let signer = rsa::Pkcs1v15Sign::new::<Sha256>();
        let attest_hash = Sha256::digest(&self.attest);
        signer.verify(
            parent_key,
            &attest_hash,
            &self.sig[TPMT_SIG_HEADER_LEN..(TPMT_SIG_HEADER_LEN + TPMT_SIG_RSA_LEN)],
        )?;

        // Validate the public area against the attestation...
        let attest = TpmsAttestData::read(&mut Cursor::new(&self.attest))
            .context("Parsing TPM attestation")?;
        let public_hash = Sha256::digest(&self.public);
        ensure!(
            &attest.created_object_name[0..2] == &[0, 0xB],
            "Expected public hash alg to be SHA256"
        );
        ensure!(
            public_hash.as_slice() == &attest.created_object_name[2..],
            "Supplied public area doesn't match hash"
        );

        // Make sure the public area is locked down to policies that restrict to trusted PCRs.
        // Parsing also checks for 'sensitive data origin' flag, i.e. key originated on the vTPM.
        let public = TpmsEcPublicData::read(&mut Cursor::new(&self.public))
            .context("Parsing TPM EC public data")?;
        ensure!(
            public.auth_policy_hash_len == 32,
            "Expected auth policy hash alg to be SHA256"
        );
        ensure!(
            allowed_auth_hashes.contains(&PolicyHash(public.auth_policy_hash[0..32].try_into()?)),
            "Auth policy hash not allowlisted"
        );

        p256::PublicKey::from_encoded_point(&p256::EncodedPoint::from_affine_coordinates(
            public
                .ec_x
                .as_slice()
                .try_into()
                .context("Checking size of public key EC X")?,
            public
                .ec_y
                .as_slice()
                .try_into()
                .context("Checking size of public key EC Y")?,
            false,
        ))
        .into_option()
        .ok_or_else(|| anyhow!("Public key is invalid EC point"))
    }
}
