// Copyright (c) 2024 Red Hat, Inc
//
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;

use assert_cmd::Command;
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::Value;
use tempfile::TempDir;

/// Generate a keypair, sign a vault secret, obtain both verification key and
/// secret through the OpenAnolis-compatible OfflineFS KBC, and unseal it.
#[test]
fn seal_unseal_vault_e2e() {
    let tmp = TempDir::new().unwrap();
    let kid = "e2e-test-key";
    let signing_key_path = "default/sealed-signing/e2e-test-key";
    let signing_key_uri = format!("kbs:///{signing_key_path}");
    let secret_path = "default/sealed-secret/e2e-test";
    let secret_uri = format!("kbs:///{secret_path}");
    let plaintext = b"super-secret-value-42";

    Command::cargo_bin("secret")
        .unwrap()
        .args(["keygen", "--kid", kid, "--output-dir"])
        .arg(tmp.path())
        .assert()
        .success();

    let private_jwk_path = tmp.path().join(format!("{kid}-private.json"));
    let public_jwk_path = tmp.path().join(format!("{kid}-public.json"));
    let private_jwk: Value =
        serde_json::from_slice(&std::fs::read(&private_jwk_path).unwrap()).unwrap();
    let public_jwk: Value =
        serde_json::from_slice(&std::fs::read(&public_jwk_path).unwrap()).unwrap();
    assert_eq!(private_jwk["kty"], "EC");
    assert_eq!(private_jwk["crv"], "P-256");
    assert_eq!(private_jwk["alg"], "ES256");
    assert!(private_jwk["d"].is_string());
    assert!(public_jwk.get("d").is_none());
    assert_eq!(private_jwk["x"], public_jwk["x"]);
    assert_eq!(private_jwk["y"], public_jwk["y"]);

    // Keygen refuses to overwrite either half of an existing keypair.
    Command::cargo_bin("secret")
        .unwrap()
        .args(["keygen", "--kid", kid, "--output-dir"])
        .arg(tmp.path())
        .assert()
        .failure();

    let resource_file = tmp.path().join("offline-resources.json");
    let resources: HashMap<String, String> = [
        (
            signing_key_path.to_string(),
            STANDARD.encode(std::fs::read(&public_jwk_path).unwrap()),
        ),
        (secret_path.to_string(), STANDARD.encode(plaintext)),
    ]
    .into_iter()
    .collect();
    std::fs::write(&resource_file, serde_json::to_vec(&resources).unwrap()).unwrap();

    let seal = Command::cargo_bin("secret")
        .unwrap()
        .args([
            "seal",
            "--signing-kid",
            &signing_key_uri,
            "--signing-jwk-path",
            private_jwk_path.to_str().unwrap(),
            "vault",
            "--resource-uri",
            &secret_uri,
            "--provider",
            "kbs",
        ])
        .output()
        .unwrap();
    assert!(
        seal.status.success(),
        "seal failed: {}",
        String::from_utf8_lossy(&seal.stderr)
    );
    let sealed = String::from_utf8(seal.stdout)
        .unwrap()
        .lines()
        .find(|line| line.starts_with("sealed."))
        .expect("seal output must contain a signed secret")
        .to_string();
    let sealed_path = tmp.path().join("sealed.txt");
    std::fs::write(&sealed_path, sealed).unwrap();

    Command::cargo_bin("secret")
        .unwrap()
        .env("OFFLINE_FS_KBC_EXTRA_FILE_PATH", &resource_file)
        .args([
            "unseal",
            "--file-path",
            sealed_path.to_str().unwrap(),
            "--aa-kbc-params",
            "offline_fs_kbc::",
        ])
        .assert()
        .success();

    assert_eq!(
        std::fs::read(tmp.path().join("sealed.txt.unsealed")).unwrap(),
        plaintext
    );
}
