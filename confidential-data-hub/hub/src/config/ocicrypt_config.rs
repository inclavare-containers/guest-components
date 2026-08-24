// Copyright (c) 2026 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0

//! Default ocicrypt keyprovider configuration generation.

use std::{env, fs, path::Path};

use anyhow::{Context, Result};

use super::CdhConfig;

const OCICRYPT_CONFIG_PATH: &str = "/run/confidential-containers/cdh/ocicrypt_config.json";
pub const OCICRYPT_KEYPROVIDER_CONFIG_ENV: &str = "OCICRYPT_KEYPROVIDER_CONFIG";

impl CdhConfig {
    /// Configure ocicrypt to send the historical `attestation-agent`
    /// keyprovider requests to this CDH instance. An operator-provided value
    /// always takes precedence.
    pub(super) fn ensure_ocicrypt_keyprovider_config(&self) -> Result<()> {
        self.ensure_ocicrypt_keyprovider_config_at(Path::new(OCICRYPT_CONFIG_PATH))
    }

    fn ensure_ocicrypt_keyprovider_config_at(&self, path: &Path) -> Result<()> {
        if env::var(OCICRYPT_KEYPROVIDER_CONFIG_ENV).is_ok() {
            return Ok(());
        }

        let parent = path.parent().expect("ocicrypt config path has a parent");
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
        fs::write(path, self.default_ocicrypt_keyprovider_config()).with_context(|| {
            format!(
                "failed to write default ocicrypt keyprovider config to {}",
                path.display()
            )
        })?;
        env::set_var(OCICRYPT_KEYPROVIDER_CONFIG_ENV, path);
        log::info!(
            "OCICRYPT_KEYPROVIDER_CONFIG unset; wrote default keyprovider config {} for {}",
            path.display(),
            self.socket
        );
        Ok(())
    }

    fn default_ocicrypt_keyprovider_config(&self) -> String {
        cfg_if::cfg_if! {
            if #[cfg(feature = "ttrpc")] {
                serde_json::json!({
                    "key-providers": {
                        "attestation-agent": { "ttrpc": self.socket }
                    }
                }).to_string()
            } else {
                serde_json::json!({
                    "key-providers": {
                        "attestation-agent": { "grpc": self.socket }
                    }
                }).to_string()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;

    use image_rs::config::ImageConfig;
    use serial_test::serial;

    use super::*;
    use crate::{KbsConfig, LogConfig};

    fn test_config(socket: &str) -> CdhConfig {
        CdhConfig {
            kbc: KbsConfig {
                name: "offline_fs_kbc".into(),
                url: String::new(),
                kbs_cert: None,
            },
            credentials: Vec::new(),
            image: ImageConfig::default(),
            socket: socket.into(),
            skip_sealed_secret_verification: false,
            aa_socket: "unix:///tmp/test-aa.sock".into(),
            log: LogConfig::default(),
        }
    }

    fn restore_env(old: Option<OsString>) {
        match old {
            Some(value) => env::set_var(OCICRYPT_KEYPROVIDER_CONFIG_ENV, value),
            None => env::remove_var(OCICRYPT_KEYPROVIDER_CONFIG_ENV),
        }
    }

    #[test]
    fn generated_config_uses_cdh_socket() {
        let config = test_config("unix:///tmp/test-cdh.sock");
        let value: serde_json::Value =
            serde_json::from_str(&config.default_ocicrypt_keyprovider_config()).unwrap();

        #[cfg(feature = "ttrpc")]
        assert_eq!(
            value["key-providers"]["attestation-agent"]["ttrpc"],
            "unix:///tmp/test-cdh.sock"
        );
        #[cfg(all(feature = "grpc", not(feature = "ttrpc")))]
        assert_eq!(
            value["key-providers"]["attestation-agent"]["grpc"],
            "unix:///tmp/test-cdh.sock"
        );
    }

    #[test]
    #[serial]
    fn writes_config_and_sets_environment_when_unset() {
        let old = env::var_os(OCICRYPT_KEYPROVIDER_CONFIG_ENV);
        env::remove_var(OCICRYPT_KEYPROVIDER_CONFIG_ENV);
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("ocicrypt.json");
        let config = test_config("unix:///tmp/test-cdh.sock");

        config.ensure_ocicrypt_keyprovider_config_at(&path).unwrap();

        assert_eq!(
            env::var_os(OCICRYPT_KEYPROVIDER_CONFIG_ENV).unwrap(),
            path.as_os_str()
        );
        let value: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert!(value["key-providers"]["attestation-agent"].is_object());
        restore_env(old);
    }

    #[test]
    #[serial]
    fn preserves_operator_override() {
        let old = env::var_os(OCICRYPT_KEYPROVIDER_CONFIG_ENV);
        env::set_var(OCICRYPT_KEYPROVIDER_CONFIG_ENV, "/operator/config.json");
        let config = test_config("unix:///tmp/test-cdh.sock");

        config
            .ensure_ocicrypt_keyprovider_config_at(Path::new("/unwritable/config.json"))
            .unwrap();

        assert_eq!(
            env::var(OCICRYPT_KEYPROVIDER_CONFIG_ENV).unwrap(),
            "/operator/config.json"
        );
        restore_env(old);
    }
}
