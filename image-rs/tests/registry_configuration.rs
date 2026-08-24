// Copyright (c) 2025 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0

pub mod common;

#[cfg(all(
    feature = "kbs",
    any(feature = "keywrap-ttrpc", feature = "keywrap-grpc")
))]
#[rstest::rstest]
#[case::banned_registry("example.com/banned", false)]
#[case::mirror_registry("mirror-test.com/some-image", true)]
#[case::remapping_registry("remapping-test.com/some-image", true)]
#[case::insecure_registry("127.0.0.1:5000/some-image", true)]
#[tokio::test]
#[serial_test::serial]
async fn test_use_registry_configuration(#[case] image_ref: &str, #[case] successful: bool) {
    use testcontainers::{
        core::{IntoContainerPort, WaitFor},
        runners::AsyncRunner,
        ImageExt,
    };
    use tokio::process::Command;

    if !common::live_image_pull_tests_enabled() {
        eprintln!(
            "skipping live registry configuration test; set {}=1 to run it",
            common::LIVE_IMAGE_PULL_TESTS_ENV
        );
        return;
    }

    common::prepare_test(common::OFFLINE_FS_KBC_RESOURCES_FILE).await;

    let _cdh = common::start_confidential_data_hub()
        .await
        .expect("Failed to start confidential data hub!");

    let _registry = testcontainers::GenericImage::new("registry", "2")
        .with_wait_for(WaitFor::message_on_stderr("listening on [::]:5000"))
        .with_mapped_port(5000, 5000.tcp())
        .start()
        .await
        .expect("start registry failed");

    let source_image = std::env::var("REGISTRY_TEST_SOURCE_IMAGE")
        .unwrap_or_else(|_| "busybox:latest".to_string());
    let inspect_output = Command::new("docker")
        .args(["image", "inspect", &source_image])
        .output()
        .await
        .expect("Failed to inspect registry source image");
    if !inspect_output.status.success() {
        let pull_output = Command::new("docker")
            .args(["pull", &source_image])
            .output()
            .await
            .expect("Failed to pull registry source image");
        assert!(
            pull_output.status.success(),
            "Failed to pull registry source image: {pull_output:?}",
        );
    }

    let target_image = "127.0.0.1:5000/some-image:latest";
    let tag_output = Command::new("docker")
        .args(["tag", &source_image, target_image])
        .output()
        .await
        .expect("Failed to tag registry source image");
    assert!(
        tag_output.status.success(),
        "Failed to tag registry source image: {tag_output:?}",
    );

    let push_output = Command::new("docker")
        .args(["push", target_image])
        .output()
        .await
        .expect("Failed to push image to registry");
    assert!(
        push_output.status.success(),
        "Failed to push image to registry: {push_output:?}",
    );

    let work_dir = tempfile::tempdir().unwrap();
    let mut image_client = image_rs::builder::ClientBuilder::default()
        .registry_configuration_uri("kbs:///default/registry-configuration/test".into())
        .work_dir(work_dir.path().to_path_buf())
        .build()
        .await
        .unwrap();
    let bundle_dir = tempfile::tempdir().unwrap();

    let result = image_client
        .pull_image(
            image_ref,
            bundle_dir.path(),
            &None,
            &Some(common::AA_PARAMETER),
        )
        .await;
    if result.is_ok() {
        common::umount_bundle(&bundle_dir);
    }

    assert_eq!(result.is_ok(), successful, "{result:?}");
    common::clean().await;
}
