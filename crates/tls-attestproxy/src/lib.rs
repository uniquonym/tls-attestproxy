use tss_esapi::{
    constants::SessionType,
    interface_types::{algorithm::HashingAlgorithm, session_handles::AuthSession},
    structures::SymmetricDefinition,
    Context,
};

pub mod attestation_key;
pub mod certify_protocol_server;
pub mod message_signing;
pub mod secure_connection_server;
pub mod signing_key;

pub fn start_tpm_session(context: &mut Context) {
    let hmac_sess: AuthSession = context
        .start_auth_session(
            None,
            None,
            None,
            SessionType::Hmac,
            SymmetricDefinition::AES_256_CFB,
            HashingAlgorithm::Sha256,
        )
        .expect("Expected to create an HMAC session.")
        .unwrap();
    context.set_sessions((Some(hmac_sess), None, None));
}
