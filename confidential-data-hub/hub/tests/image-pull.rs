// Copyright (c) 2024 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use std::time::Duration;

/// Script for preparing resources.json for offline-fs-kbc.
const OFFLINE_FS_KBC_RESOURCE_SCRIPT: &str =
    "../../image-rs/scripts/install_offline_fs_kbc_files.sh";
const COSIGN_SIGNED_IMAGE: &str =
    "ghcr.io/confidential-containers/test-container-image-rs:cosign-signed";
const LIVE_IMAGE_PULL_TESTS_ENV: &str = "RUN_LIVE_IMAGE_PULL_TESTS";
const LIVE_COSIGN_TESTS_ENV: &str = "RUN_LIVE_COSIGN_TESTS";

#[rstest::rstest]
#[case::unsigned_unencrypted_image("busybox:latest")]
#[case::cosign_signed_unencrypted_image(COSIGN_SIGNED_IMAGE)]
#[case::unsigned_encrypted_image("ghcr.io/confidential-containers/test-container:encrypted")]
#[case::private_registry("quay.io/liudalibj/private-busy-box")]
#[tokio::test]
#[serial_test::serial]
async fn test_pull_image(#[case] image_ref: &str) {
    if std::env::var_os(LIVE_IMAGE_PULL_TESTS_ENV).is_none() {
        eprintln!(
            "skipping live image pull test; set {}=1 to run it",
            LIVE_IMAGE_PULL_TESTS_ENV
        );
        return;
    }

    if image_ref == COSIGN_SIGNED_IMAGE && std::env::var_os(LIVE_COSIGN_TESTS_ENV).is_none() {
        eprintln!(
            "skipping live cosign image pull test; set {}=1 to run it",
            LIVE_COSIGN_TESTS_ENV
        );
        return;
    }

    tokio::process::Command::new(OFFLINE_FS_KBC_RESOURCE_SCRIPT)
        .arg("install")
        .arg("aa-offline_fs_kbc-resources.json")
        .output()
        .await
        .expect("Install offline-fs-kbcs's resources failed.");

    let tempdir = tempfile::tempdir().unwrap();

    let cdh_path = format!(
        "{}/../../target/debug/ttrpc-cdh",
        std::env!("CARGO_MANIFEST_DIR")
    );

    let _cdh = tokio::process::Command::new(cdh_path)
        .arg("-c")
        .arg(format!(
            "{}/tests/cdh.toml",
            std::env!("CARGO_MANIFEST_DIR")
        ))
        .env("RUST_LOG", "info")
        .kill_on_drop(true)
        .spawn()
        .unwrap();

    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_cmd::Command::cargo_bin("ttrpc-cdh-tool")
        .unwrap()
        // Encrypted and multi-layer image pulls can exceed the generic short
        // RPC timeout on a cold cache or a constrained guest network.
        .arg("--timeout")
        .arg("300")
        .arg("pull-image")
        .arg("--image-url")
        .arg(image_ref)
        .arg("--bundle-path")
        .arg(tempdir.path())
        .assert()
        .success();

    let mut flag_file = tempdir.path().to_path_buf();
    flag_file.push("rootfs");
    flag_file.push("bin");
    flag_file.push("ls");
    // `bin/ls` is commonly an absolute symlink to `/bin/busybox`. `exists()`
    // follows that link against the host rootfs and can report a false
    // negative even though the image rootfs is populated.
    assert!(
        std::fs::symlink_metadata(&flag_file).is_ok(),
        "failed to pull image"
    );

    let mounted_path = tempdir.path().to_path_buf().join("rootfs");
    nix::mount::umount(&mounted_path).unwrap();
}
