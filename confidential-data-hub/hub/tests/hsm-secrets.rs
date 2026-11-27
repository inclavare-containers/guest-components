// Copyright (c) 2024 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

#![cfg(all(
    feature = "cli",
    feature = "kbs",
    any(feature = "aliyun", feature = "ehsm")
))]

use base64::{engine::general_purpose::STANDARD, Engine};
use std::{env, fs, path::Path, process::Command};

fn test_input(name: &str) -> String {
    env::var(name).unwrap_or_else(|_| panic!("{name} must be set for the live KMS test"))
}

fn secret_cli() -> Command {
    Command::new(env!("CARGO_BIN_EXE_secret"))
}

#[cfg(feature = "aliyun")]
#[test]
#[ignore = "requires an Aliyun KMS ClientKey and an accessible KMS instance"]
fn aliyun_envelope_round_trip() {
    envelope_round_trip(
        &test_input("CDH_TEST_ALIYUN_KMS_KEY_ID"),
        Path::new(&test_input("CDH_TEST_ALIYUN_KMS_CREDENTIAL_DIR")),
        &[
            "ali",
            "--password-file-path",
            &test_input("CDH_TEST_ALIYUN_KMS_PASSWORD_FILE"),
            "--kms-instance-id",
            &test_input("CDH_TEST_ALIYUN_KMS_INSTANCE_ID"),
            "--client-key-file-path",
            &test_input("CDH_TEST_ALIYUN_KMS_CLIENT_KEY_FILE"),
            "--cert-path",
            &test_input("CDH_TEST_ALIYUN_KMS_CA_FILE"),
        ],
    );
}

#[cfg(feature = "ehsm")]
#[test]
#[ignore = "requires eHSM credentials and an accessible eHSM instance"]
fn ehsm_envelope_round_trip() {
    envelope_round_trip(
        &test_input("CDH_TEST_EHSM_KEY_ID"),
        Path::new(&test_input("CDH_TEST_EHSM_CREDENTIAL_DIR")),
        &[
            "ehsm",
            "--credential-file-path",
            &test_input("CDH_TEST_EHSM_CREDENTIAL_FILE"),
            "--endpoint",
            &test_input("CDH_TEST_EHSM_ENDPOINT"),
        ],
    );
}

fn envelope_round_trip(key_id: &str, credential_dir: &Path, provider_args: &[&str]) {
    let dir = tempfile::tempdir().unwrap();
    let plaintext = rand::random::<[u8; 32]>();
    let plaintext_path = dir.path().join("plaintext");
    fs::write(&plaintext_path, plaintext).unwrap();

    let keygen = secret_cli()
        .args(["keygen", "--kid", "test-signer", "--output-dir"])
        .arg(dir.path())
        .output()
        .unwrap();
    assert!(keygen.status.success(), "generate envelope signing key");

    let resource_file = dir.path().join("resources.json");
    let public_key = fs::read(dir.path().join("test-signer-public.json")).unwrap();
    fs::write(
        &resource_file,
        serde_json::json!({"default/key/test-signer": STANDARD.encode(public_key)}).to_string(),
    )
    .unwrap();

    let seal = secret_cli()
        .args([
            "seal",
            "--signing-kid",
            "kbs:///default/key/test-signer",
            "--signing-jwk-path",
        ])
        .arg(dir.path().join("test-signer-private.json"))
        .args(["envelope", "--key-id", key_id, "--file-path"])
        .arg(&plaintext_path)
        .args(provider_args)
        .output()
        .unwrap();
    assert!(seal.status.success(), "seal envelope through KMS");
    let sealed = std::str::from_utf8(&seal.stdout)
        .unwrap()
        .lines()
        .find(|line| line.starts_with("sealed."))
        .expect("signed envelope");
    let sealed_path = dir.path().join("sealed.txt");
    fs::write(&sealed_path, sealed).unwrap();

    let unseal = secret_cli()
        .env("OFFLINE_FS_KBC_EXTRA_FILE_PATH", &resource_file)
        .args(["unseal", "--file-path"])
        .arg(&sealed_path)
        .args(["--aa-kbc-params", "offline_fs_kbc::", "--key-path"])
        .arg(credential_dir)
        .output()
        .unwrap();
    assert!(
        unseal.status.success(),
        "verify and unseal envelope through KMS"
    );
    assert!(fs::read(dir.path().join("sealed.txt.unsealed")).unwrap() == plaintext);
}
