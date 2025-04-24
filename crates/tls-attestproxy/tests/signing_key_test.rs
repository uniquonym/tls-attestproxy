use std::{
    collections::HashSet,
    fs::{create_dir, Permissions},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Command,
    thread::sleep,
    time::Duration,
};

use rsa::{BigUint, RsaPublicKey};
use tempfile::Builder;
use tls_attestclient::signing_key_attestation::{
    calculate_pcr_policy_hash, AttestationRaw, PCRHash, PolicyHash, TrustedPCRSet,
};
use tss_esapi::{
    constants::SessionType,
    interface_types::{algorithm::HashingAlgorithm, session_handles::PolicySession},
    structures::{Public, SymmetricDefinition},
    tcti_ldr::TpmSimulatorConfig,
    Context, Tcti,
};

use tls_attestproxy::{
    attestation_key::load_or_create_ak,
    signing_key::{combine_pcr_digests, load_or_create_signkey, relevant_pcrs},
    start_tpm_session,
};

fn with_test_tpm<F>(f: F) -> ()
where
    F: FnOnce(Context, &Path) -> (),
{
    let tmpdir = Builder::new()
        .permissions(Permissions::from_mode(0o700))
        .tempdir()
        .expect("Couldn't create temporary directory");
    let ctrl_path: PathBuf = tmpdir.path().join("socket.ctrl");
    let server_path: PathBuf = tmpdir.path().join("socket");
    let state_dir: PathBuf = tmpdir.path().join("state");
    create_dir(&state_dir).expect("Couldn't create tpm state directory");
    let mut swtpm_proc = Command::new("swtpm")
        .args([
            "socket",
            "--tpm2",
            "--ctrl",
            &format!("type=unixio,path={}", &ctrl_path.display()),
            "--server",
            &format!("type=unixio,path={}", &server_path.display()),
            "--tpmstate",
            &format!("dir={}", &state_dir.display()),
            "--flags",
            "not-need-init,startup-clear",
        ])
        .spawn()
        .expect("Couldn't run swtpm");
    let mut sleep_time: Duration = Duration::from_micros(100);
    while !server_path.exists() {
        sleep_time = sleep_time * 2;
        sleep(sleep_time);
        if sleep_time > Duration::from_secs(2) {
            panic!("swtpm didn't eventually create socket");
        }
    }
    let context = Context::new(Tcti::Swtpm(TpmSimulatorConfig::Unix {
        path: server_path.to_str().unwrap().to_owned(),
    }))
    .expect("Expected to be able to access tpm2");
    f(context, tmpdir.path());
    swtpm_proc
        .kill()
        .expect("Couldn't kill swtpm process after test")
}

fn get_current_pcrs_as_trusted(context: &mut Context) -> TrustedPCRSet {
    let (_, _, digest_list) = context
        .execute_without_session(|context| context.pcr_read(relevant_pcrs().unwrap()))
        .expect("Error reading PCRs");

    TrustedPCRSet {
        pcr4: PCRHash(digest_list.value()[0].clone().try_into().unwrap()),
        pcr5: PCRHash(digest_list.value()[1].clone().try_into().unwrap()),
        pcr7: PCRHash(digest_list.value()[2].clone().try_into().unwrap()),
        pcr8: PCRHash(digest_list.value()[3].clone().try_into().unwrap()),
        pcr9: PCRHash(digest_list.value()[4].clone().try_into().unwrap()),
    }
}

#[test]
fn compute_policy_hash_matches_trial_session_policy_result() {
    with_test_tpm(|mut context, _tmpdir| {
        let sess = context
            .start_auth_session(
                None,
                None,
                None,
                SessionType::Trial,
                SymmetricDefinition::Null,
                HashingAlgorithm::Sha256,
            )
            .expect("Could start trial session")
            .expect("No trial session returned");
        let policy_sess: PolicySession = sess.try_into().unwrap();

        let (_, pcr_list, digest_list) = context
            .pcr_read(relevant_pcrs().unwrap())
            .expect("Error reading PCRs");

        let digest = combine_pcr_digests(&digest_list).unwrap();
        context
            .policy_pcr(policy_sess, digest, pcr_list.clone())
            .unwrap();
        let final_digest: [u8; 32] = context
            .policy_get_digest(policy_sess)
            .unwrap()
            .try_into()
            .unwrap();

        let trusted_pcrs = get_current_pcrs_as_trusted(&mut context);
        let policy_hash = calculate_pcr_policy_hash(&trusted_pcrs);

        assert_eq!(policy_hash.0, final_digest);
    })
}

#[test]
fn signing_key_attestation_verifies() {
    with_test_tpm(|mut ctx, tmpdir| {
        // Given a valid signing key...
        let ak_path = tmpdir.to_path_buf().join("ak.json");
        let sk_path = tmpdir.to_path_buf().join("sk.json");
        start_tpm_session(&mut ctx);
        let ak = load_or_create_ak(&mut ctx, &ak_path).unwrap();
        let sk = load_or_create_signkey(&mut ctx, &ak, &sk_path).expect("Couldn't create signkey");

        let trusted_pcrs = get_current_pcrs_as_trusted(&mut ctx);

        // And a known RSA public attestation key for the TPM2...
        let public_attest = ctx
            .execute_without_session(|ctx| ctx.read_public(ak.handle))
            .unwrap()
            .0;
        let (pubkey_n, pubkey_e): ([u8; 256], u32) = match public_attest {
            Public::Rsa {
                unique, parameters, ..
            } => (
                unique.try_into().expect("2048 bit key"),
                parameters.exponent().value(),
            ),
            _ => panic!("Expected RSA key"),
        };
        let pubkey = RsaPublicKey::new(BigUint::from_bytes_be(&pubkey_n), pubkey_e.into()).unwrap();

        // When I serialise a signing key attestation...
        let key_attestation: AttestationRaw = sk.attestation.clone().try_into().unwrap();

        let allowed_hashes: HashSet<PolicyHash> = vec![calculate_pcr_policy_hash(&trusted_pcrs)]
            .into_iter()
            .collect();

        // Then that attestation should verify as valid.
        key_attestation
            .validate_and_get_key(&pubkey, &allowed_hashes)
            .expect("Key attestation didn't validate");
    });
}
