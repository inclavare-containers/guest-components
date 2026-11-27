// Copyright (c) 2024 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use std::{
    io::ErrorKind,
    os::unix::{fs::FileTypeExt, net::UnixStream},
    path::Path,
    time::Duration,
};

const COSIGN_SIGNED_IMAGE: &str =
    "ghcr.io/confidential-containers/test-container-image-rs:cosign-signed";
const LIVE_IMAGE_PULL_TESTS_ENV: &str = "RUN_LIVE_IMAGE_PULL_TESTS";
const LIVE_COSIGN_TESTS_ENV: &str = "RUN_LIVE_COSIGN_TESTS";
const EXTRA_RESOURCES_ENV: &str = "OFFLINE_FS_KBC_EXTRA_FILE_PATH";
const REGISTRY_AUTH_URI_ENV: &str = "CDH_DEFAULT_IMAGE_AUTHENTICATED_REGISTRY_CREDENTIALS";
const PUBLIC_OFFLINE_RESOURCES: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../image-rs/test_data/offline-fs-kbc/aa-offline_fs_kbc-resources.json"
);

#[derive(Clone, Copy, PartialEq, Eq)]
enum ImagePullCase {
    Public,
    CosignSigned,
    Encrypted,
    PrivateRegistry,
}

#[rstest::rstest]
#[case::unsigned_unencrypted_image(ImagePullCase::Public)]
#[case::cosign_signed_unencrypted_image(ImagePullCase::CosignSigned)]
#[case::unsigned_encrypted_image(ImagePullCase::Encrypted)]
#[case::private_registry(ImagePullCase::PrivateRegistry)]
#[tokio::test]
#[serial_test::serial]
async fn test_pull_image(#[case] case: ImagePullCase) {
    if std::env::var_os(LIVE_IMAGE_PULL_TESTS_ENV).is_none() {
        eprintln!("skipping live image pull test; set {LIVE_IMAGE_PULL_TESTS_ENV}=1 to run it");
        return;
    }

    if case == ImagePullCase::CosignSigned && std::env::var_os(LIVE_COSIGN_TESTS_ENV).is_none() {
        eprintln!("skipping live cosign image pull test; set {LIVE_COSIGN_TESTS_ENV}=1 to run it");
        return;
    }

    let image_ref = match case {
        ImagePullCase::Public => {
            std::env::var("CDH_TEST_PUBLIC_IMAGE").unwrap_or_else(|_| "busybox:latest".into())
        }
        ImagePullCase::CosignSigned => {
            std::env::var("CDH_TEST_COSIGN_IMAGE").unwrap_or_else(|_| COSIGN_SIGNED_IMAGE.into())
        }
        ImagePullCase::Encrypted => {
            std::env::var("CDH_TEST_ENCRYPTED_IMAGE").expect("set CDH_TEST_ENCRYPTED_IMAGE")
        }
        ImagePullCase::PrivateRegistry => std::env::var("CDH_TEST_PRIVATE_REGISTRY_IMAGE")
            .expect("set CDH_TEST_PRIVATE_REGISTRY_IMAGE"),
    };

    let extra_resources = std::env::var(EXTRA_RESOURCES_ENV).unwrap_or_default();
    let extra_resources: Vec<_> = extra_resources
        .split(',')
        .map(str::trim)
        .filter(|path| !path.is_empty())
        .collect();
    assert!(
        !matches!(
            case,
            ImagePullCase::Encrypted | ImagePullCase::PrivateRegistry
        ) || !extra_resources.is_empty(),
        "set {EXTRA_RESOURCES_ENV} to the offline KBC bundle paths for encrypted or private images"
    );
    assert!(
        extra_resources
            .iter()
            .all(|path| { Path::new(path).is_file() && std::fs::File::open(path).is_ok() }),
        "{EXTRA_RESOURCES_ENV} entries must be readable regular files"
    );
    let resources = std::iter::once(PUBLIC_OFFLINE_RESOURCES)
        .chain(extra_resources)
        .collect::<Vec<_>>()
        .join(",");

    let tempdir = tempfile::tempdir().unwrap();
    let config_path = tempdir.path().join("cdh.toml");
    let mut config: toml::Value = toml::from_str(include_str!("cdh.toml")).unwrap();
    config["image"].as_table_mut().unwrap().insert(
        "work_dir".into(),
        tempdir.path().join("image").to_str().unwrap().into(),
    );
    std::fs::write(&config_path, toml::to_string(&config).unwrap()).unwrap();

    // The test runs with CDH's standard ttRPC socket in a disposable guest.
    // Keep its generated keyprovider configuration out of shared runtime paths.
    let keyprovider_config = tempdir.path().join("ocicrypt.json");
    let socket = config["socket"].as_str().unwrap();
    let socket_path = socket.strip_prefix("unix://").unwrap();
    let available = match std::fs::symlink_metadata(socket_path) {
        Ok(metadata) => {
            metadata.file_type().is_socket()
                && matches!(UnixStream::connect(socket_path), Err(error)
                    if error.kind() == ErrorKind::ConnectionRefused)
        }
        Err(error) => error.kind() == ErrorKind::NotFound,
    };
    assert!(
        available,
        "CDH test socket is in use or unavailable; run the test in a disposable guest"
    );
    std::fs::write(
        &keyprovider_config,
        serde_json::json!({
            "key-providers": { "attestation-agent": { "ttrpc": socket } }
        })
        .to_string(),
    )
    .unwrap();

    let mut command = tokio::process::Command::new(
        option_env!("CARGO_BIN_EXE_ttrpc-cdh").expect("build CDH with the bin and ttrpc features"),
    );
    command
        .arg("-c")
        .arg(config_path)
        .env("AA_KBC_PARAMS", "offline_fs_kbc::null")
        .env(EXTRA_RESOURCES_ENV, resources)
        .env("OCICRYPT_KEYPROVIDER_CONFIG", keyprovider_config)
        .env_remove(REGISTRY_AUTH_URI_ENV)
        .env("RUST_LOG", "info")
        .kill_on_drop(true);
    if case == ImagePullCase::PrivateRegistry {
        command.env(REGISTRY_AUTH_URI_ENV, "kbs:///default/credential/test");
    }
    let mut cdh = command.spawn().unwrap();

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
    cdh.kill().await.unwrap();
}
