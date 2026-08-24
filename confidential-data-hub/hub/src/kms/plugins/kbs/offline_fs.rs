// Copyright (c) 2021 IBM Corp.
// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use std::collections::HashMap;

use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD, Engine};
use log::warn;
use resource_uri::{ResourcePluginPath, ResourceUri};
use tokio::fs;

use super::Kbc;
use super::{Error, Result};

const KEYS_PATH: &str = "/etc/aa-offline_fs_kbc-keys.json";
const RESOURCES_PATH: &str = "/etc/aa-offline_fs_kbc-resources.json";

/// Comma-separated additional resource files loaded after the standard files.
/// Later files override duplicate resource definitions from earlier files.
const EXTRA_FILE_PATH_ENV_VAR: &str = "OFFLINE_FS_KBC_EXTRA_FILE_PATH";

pub struct OfflineFsKbc {
    /// Stored resources, loaded from file system
    resources: HashMap<String, Vec<u8>>,
}

#[async_trait]
impl Kbc for OfflineFsKbc {
    async fn get_resource(&mut self, rid: ResourceUri) -> Result<Vec<u8>> {
        let ResourcePluginPath { repo, r#type, tag } =
            ResourcePluginPath::try_from(&rid).map_err(|e| {
                Error::KbsClientError(format!(
                    "offline-fs-kbc only supports the resource plugin: {e:#}"
                ))
            })?;
        let resource_path = format!("{repo}/{type}/{tag}");
        self.resources
            .get(&resource_path)
            .ok_or(Error::KbsClientError(format!(
                "offline-fs-kbc: resource not found {resource_path}"
            )))
            .cloned()
    }
}

impl OfflineFsKbc {
    pub async fn new() -> Result<Self> {
        let mut res = Self {
            resources: HashMap::new(),
        };

        res.init_with_file(KEYS_PATH).await?;
        res.init_with_file(RESOURCES_PATH).await?;

        if let Ok(extra_file_paths) = std::env::var(EXTRA_FILE_PATH_ENV_VAR) {
            for path in extra_file_paths.split(',').map(str::trim) {
                if !path.is_empty() {
                    res.init_with_file(path).await?;
                }
            }
        }

        Ok(res)
    }

    async fn init_with_file(&mut self, path: &str) -> Result<()> {
        let file = match fs::read(path).await {
            Ok(f) => f,
            Err(e) => {
                warn!("Failed to read file {path} to init offline-fs-kbc: {e:?}");
                return Ok(());
            }
        };

        let map: HashMap<String, String> = serde_json::from_slice(&file).map_err(|e| {
            Error::KbsClientError(format!(
                "offline-fs-kbc: illegal resource file {path}: {e:?}"
            ))
        })?;
        for (k, v) in &map {
            let value = STANDARD.decode(v).map_err(|e| {
                Error::KbsClientError(format!(
                    "offline-fs-kbc: decode value from file {path} failed: {e:?}"
                ))
            })?;
            if self.resources.insert(k.to_owned(), value).is_some() {
                warn!("detected duplicated resource definition {k} in file {path} when initializing offline-fs-kbc");
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::{env, ffi::OsString};

    use base64::{engine::general_purpose::STANDARD, Engine};
    use resource_uri::ResourceUri;
    use rstest::rstest;
    use serial_test::serial;

    use crate::kms::plugins::kbs::{
        offline_fs::{OfflineFsKbc, EXTRA_FILE_PATH_ENV_VAR},
        Kbc,
    };

    struct ExtraFilesEnvRestore(Option<OsString>);

    impl ExtraFilesEnvRestore {
        fn capture() -> Self {
            Self(env::var_os(EXTRA_FILE_PATH_ENV_VAR))
        }
    }

    impl Drop for ExtraFilesEnvRestore {
        fn drop(&mut self) {
            match self.0.take() {
                Some(value) => env::set_var(EXTRA_FILE_PATH_ENV_VAR, value),
                None => env::remove_var(EXTRA_FILE_PATH_ENV_VAR),
            }
        }
    }

    #[rstest]
    #[tokio::test]
    #[case("default/key/1", b"key1")]
    async fn test_get_key(#[case] key: &str, #[case] value: &[u8]) {
        let mut kbc = OfflineFsKbc {
            resources: [(key.to_string(), value.to_vec())]
                .iter()
                .cloned()
                .collect(),
        };

        let rid = ResourceUri::try_from(&format!("kbs:///{key}")[..]).unwrap();
        assert_eq!(
            kbc.get_resource(rid).await.expect("get key failed")[..],
            *value
        );
    }

    #[tokio::test]
    async fn rejects_non_resource_plugin() {
        let mut kbc = OfflineFsKbc {
            resources: Default::default(),
        };
        let rid = ResourceUri::try_from("kbs+pkcs11:///slot/key/label").unwrap();
        assert!(kbc.get_resource(rid).await.is_err());
    }

    #[tokio::test]
    async fn init_with_missing_file_is_noop() {
        let mut kbc = OfflineFsKbc {
            resources: Default::default(),
        };
        kbc.init_with_file("/no/such/path/resources.json")
            .await
            .expect("missing file must not fail");
        assert!(kbc.resources.is_empty());
    }

    #[tokio::test]
    async fn init_with_malformed_json_returns_error() {
        let file = tempfile::NamedTempFile::new().unwrap();
        tokio::fs::write(file.path(), b"{ not valid json }")
            .await
            .unwrap();
        let mut kbc = OfflineFsKbc {
            resources: Default::default(),
        };

        assert!(kbc
            .init_with_file(file.path().to_str().unwrap())
            .await
            .is_err());
    }

    #[tokio::test]
    async fn init_with_valid_file_populates_resources() {
        let content = serde_json::json!({
            "default/key/1": STANDARD.encode(b"key1"),
            "default/key/2": STANDARD.encode(b"key2"),
        })
        .to_string();
        let file = tempfile::NamedTempFile::new().unwrap();
        tokio::fs::write(file.path(), content.as_bytes())
            .await
            .unwrap();
        let mut kbc = OfflineFsKbc {
            resources: Default::default(),
        };

        kbc.init_with_file(file.path().to_str().unwrap())
            .await
            .unwrap();
        assert_eq!(kbc.resources.get("default/key/1").unwrap(), b"key1");
        assert_eq!(kbc.resources.get("default/key/2").unwrap(), b"key2");
    }

    #[tokio::test]
    async fn duplicate_resource_is_overridden_by_later_file() {
        let first = tempfile::NamedTempFile::new().unwrap();
        let second = tempfile::NamedTempFile::new().unwrap();
        tokio::fs::write(
            first.path(),
            serde_json::json!({"default/key/1": STANDARD.encode(b"first")}).to_string(),
        )
        .await
        .unwrap();
        tokio::fs::write(
            second.path(),
            serde_json::json!({"default/key/1": STANDARD.encode(b"second")}).to_string(),
        )
        .await
        .unwrap();
        let mut kbc = OfflineFsKbc {
            resources: Default::default(),
        };

        kbc.init_with_file(first.path().to_str().unwrap())
            .await
            .unwrap();
        kbc.init_with_file(second.path().to_str().unwrap())
            .await
            .unwrap();
        assert_eq!(kbc.resources.get("default/key/1").unwrap(), b"second");
    }

    #[tokio::test]
    #[serial]
    async fn new_loads_trimmed_extra_file_list_in_order() {
        let _restore = ExtraFilesEnvRestore::capture();
        let first = tempfile::NamedTempFile::new().unwrap();
        let second = tempfile::NamedTempFile::new().unwrap();
        tokio::fs::write(
            first.path(),
            serde_json::json!({
                "default/key/extra": STANDARD.encode(b"first"),
                "default/key/only-first": STANDARD.encode(b"one"),
            })
            .to_string(),
        )
        .await
        .unwrap();
        tokio::fs::write(
            second.path(),
            serde_json::json!({"default/key/extra": STANDARD.encode(b"second")}).to_string(),
        )
        .await
        .unwrap();
        env::set_var(
            EXTRA_FILE_PATH_ENV_VAR,
            format!(" {},, {} ", first.path().display(), second.path().display()),
        );

        let kbc = OfflineFsKbc::new().await.unwrap();
        assert_eq!(kbc.resources.get("default/key/extra").unwrap(), b"second");
        assert_eq!(kbc.resources.get("default/key/only-first").unwrap(), b"one");
    }
}
