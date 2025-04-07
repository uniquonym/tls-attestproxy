use std::fs::read_to_string;

use anyhow::Context as EContext;
use serde::{Deserialize, Serialize};
use serde_with::base64::{Base64, Standard};
use serde_with::formats::Unpadded;
use serde_with::serde_as;
use tss_esapi::attributes::ObjectAttributes;
use tss_esapi::handles::KeyHandle;
use tss_esapi::handles::{ObjectHandle, PersistentTpmHandle};
use tss_esapi::interface_types::algorithm::{HashingAlgorithm, PublicAlgorithm};
use tss_esapi::interface_types::data_handles::Persistent;
use tss_esapi::interface_types::key_bits::RsaKeyBits;
use tss_esapi::interface_types::reserved_handles::{Hierarchy, Provision};
use tss_esapi::structures::{
    HashScheme, Public, PublicBuilder, PublicKeyRsa, PublicRsaParameters, RsaExponent, RsaScheme,
    SymmetricDefinitionObject,
};
use tss_esapi::Context;

#[serde_as]
#[derive(Serialize, Deserialize)]
pub struct StorableKey {
    #[serde_as(as = "Base64<Standard, Unpadded>")]
    serdata: Vec<u8>,
}

pub struct TpmResidentKey {
    pub handle: KeyHandle,
}

fn try_load_key(context: &mut Context, path: &str) -> anyhow::Result<TpmResidentKey> {
    let data = read_to_string(path)?;
    let storable_key: StorableKey = serde_json::from_str(&data)?;
    let handle: KeyHandle = context.tr_deserialize(&storable_key.serdata)?.try_into()?;
    Ok(TpmResidentKey { handle })
}

fn save_key(key: &StorableKey, path: &str) -> anyhow::Result<()> {
    std::fs::write(path, &serde_json::to_string(key)?)?;
    Ok(())
}

pub fn load_or_create_ak(context: &mut Context) -> anyhow::Result<TpmResidentKey> {
    let keypath =
        std::env::var("AK_STORAGE_PATH").context("Fetching AK_STORAGE_PATH environment")?;
    if let Ok(key) = try_load_key(context, &keypath) {
        return Ok(key);
    }

    let primary_public_template: Public = PublicBuilder::new()
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_public_algorithm(PublicAlgorithm::Rsa)
        .with_object_attributes(
            ObjectAttributes::builder()
                .with_fixed_tpm(true)
                .with_fixed_parent(true)
                .with_sensitive_data_origin(true)
                .with_user_with_auth(true)
                .with_restricted(true)
                .with_sign_encrypt(true)
                .build()
                .context("Building AK ObjectAttributes")?,
        )
        .with_rsa_parameters(
            PublicRsaParameters::builder()
                .with_symmetric(SymmetricDefinitionObject::Null)
                .with_scheme(RsaScheme::RsaSsa(HashScheme::new(HashingAlgorithm::Sha256)))
                .with_key_bits(RsaKeyBits::Rsa2048)
                .with_exponent(RsaExponent::create(65537)?)
                .build()
                .context("Creating AK PublicRsaParameters")?,
        )
        .with_rsa_unique_identifier(PublicKeyRsa::default())
        .build()
        .context("Building AK public key template")?;

    let primary = context
        .create_primary(
            Hierarchy::Endorsement,
            primary_public_template,
            None,
            None,
            None,
            None,
        )
        .context("AK CreatePrimary")?;

    let persistent_handle = PersistentTpmHandle::new(0x81000001)?;
    let persistent = Persistent::Persistent(persistent_handle);
    if let Ok(old_handle) = context.execute_without_session(|context| {
        anyhow::Ok(context.tr_from_tpm_public(persistent_handle.try_into()?)?)
    }) {
        context
            .evict_control(Provision::Owner, old_handle, persistent)
            .context("Deleting old AK")?;
    }

    let primary_perm: ObjectHandle = context
        .evict_control(
            Provision::Owner,
            primary.key_handle.clone().into(),
            persistent,
        )
        .context("Making AK persistent")?;
    let primary_ser = context.tr_serialize(primary_perm)?;
    let storable_primary: StorableKey = StorableKey {
        serdata: primary_ser.into(),
    };
    save_key(&storable_primary, &keypath)?;

    Ok(TpmResidentKey {
        handle: primary_perm.try_into()?,
    })
}
