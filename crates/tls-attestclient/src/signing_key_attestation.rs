use anyhow::bail;
use rsa::RsaPublicKey;
use rsa::traits::SignatureScheme;
use serde::{Deserialize, Serialize};
use serde_with::base64::{Base64, Standard};
use serde_with::formats::Unpadded;
use serde_with::serde_as;
use sha2::{Digest, Sha256};

#[serde_as]
#[derive(Serialize, Deserialize)]
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
    //   TPMT_SYM_DEF_OBJECT
    //   TPMT_ECC_SCHEME
    //   TPMI_ECC_CURVE
    //   TPMT_KDF_SCHEME
    // TPMU_PUBLIC_ID -> TPMS_ECC_POINT
    //   TPM2B_ECC_PARAMETER x
    //      16 bit - size
    //      bytes
    //   TPM2B_ECC_PARAMETER y
    //      16 bit - size
    //      bytes
    pub public: Vec<u8>,
}

const TPMT_SIG_HEADER_LEN: usize = 6;
const TPMT_SIG_RSA_LEN: usize = 256;

impl AttestationRaw {
    pub fn validate_and_get_key(
        &self,
        parent_key: &RsaPublicKey,
    ) -> anyhow::Result<k256::PublicKey> {
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
        todo!();
    }
}
