// Copyright (c) 2024 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use std::{env, fs, path::Path};

use anyhow::*;
use attestation_agent::config::aa_kbc_params::AaKbcParams;
use config::{Config, File};
use image_rs::config::ImageConfig;
use log::{debug, info};
use serde::Deserialize;

#[cfg(any(feature = "ttrpc", feature = "grpc"))]
mod ocicrypt_config;

cfg_if::cfg_if! {
    if #[cfg(feature = "ttrpc")] {
        const DEFAULT_CDH_SOCKET_ADDR: &str = "unix:///run/confidential-containers/cdh.sock";
    } else {
        const DEFAULT_CDH_SOCKET_ADDR: &str = "127.0.0.1:50000";
    }
}

const DEFAULT_AA_SOCKET_ADDR: &str =
    "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock";
const DEFAULT_LOG_LEVEL: &str = "info";

const CDH_DEFAULT_IMAGE_AUTHENTICATED_REGISTRY_CREDENTIALS: &str =
    "CDH_DEFAULT_IMAGE_AUTHENTICATED_REGISTRY_CREDENTIALS";

#[derive(Clone, Deserialize, Debug, PartialEq)]
pub struct KbsConfig {
    pub name: String,

    pub url: String,

    pub kbs_cert: Option<String>,
}

impl KbsConfig {
    fn new() -> Result<Self> {
        debug!("Try to get kbc and url from env and kernel commandline.");
        let aa_kbc_params =
            AaKbcParams::new().context("failed to read aa_kbc_params to initialize KbsConfig")?;
        Ok(KbsConfig {
            name: aa_kbc_params.kbc,
            url: aa_kbc_params.uri,
            kbs_cert: None,
        })
    }
}

#[derive(Clone, Deserialize, Debug, PartialEq)]
pub struct Credential {
    pub resource_uri: String,
    pub path: String,
}

fn default_aa_socket_addr() -> String {
    DEFAULT_AA_SOCKET_ADDR.to_string()
}

/// Connection settings for the Attestation Agent.
///
/// CDH uses the AA ttrpc API to obtain a Trustee passport token.  The nested
/// `[aa]` form matches upstream configuration, while the legacy top-level
/// `aa_socket` field remains accepted by [`RawCdhConfig`].
#[derive(Clone, Deserialize, Debug, PartialEq)]
pub struct AaConfig {
    #[serde(default = "default_aa_socket_addr")]
    pub aa_socket: String,
}

impl Default for AaConfig {
    fn default() -> Self {
        Self {
            aa_socket: default_aa_socket_addr(),
        }
    }
}

fn default_log_level() -> String {
    DEFAULT_LOG_LEVEL.to_string()
}

#[derive(Clone, Deserialize, Debug, PartialEq)]
pub struct LogConfig {
    #[serde(default = "default_log_level")]
    pub level: String,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
        }
    }
}

#[derive(Clone, Deserialize, Debug, PartialEq)]
#[serde(from = "RawCdhConfig")]
pub struct CdhConfig {
    pub kbc: KbsConfig,

    #[serde(default)]
    pub credentials: Vec<Credential>,

    /// Image pull configuration. Note that if `[image]` section is not given,
    /// the image pull configuration will be read from kernel commandline together
    /// with default values.
    #[serde(default = "ImageConfig::from_kernel_cmdline")]
    pub image: ImageConfig,

    pub socket: String,

    /// Disable JWS verification only for migration from legacy fake-signed
    /// sealed secrets. Verification is enabled by default.
    #[serde(default)]
    pub skip_sealed_secret_verification: bool,

    pub aa_socket: String,

    pub log: LogConfig,
}

#[derive(Deserialize)]
struct RawCdhConfig {
    kbc: KbsConfig,

    #[serde(default)]
    credentials: Vec<Credential>,

    #[serde(default = "ImageConfig::from_kernel_cmdline")]
    image: ImageConfig,

    #[serde(default)]
    socket: Option<String>,

    #[serde(default)]
    skip_sealed_secret_verification: bool,

    /// Upstream configuration form.
    #[serde(default)]
    aa: Option<AaConfig>,

    /// Legacy Inclavare configuration form.
    #[serde(default)]
    aa_socket: Option<String>,

    #[serde(default)]
    log: LogConfig,
}

impl From<RawCdhConfig> for CdhConfig {
    fn from(raw: RawCdhConfig) -> Self {
        // Prefer the upstream nested form when both forms are explicitly
        // present.  Otherwise retain the legacy top-level value and finally
        // fall back to the standard AA ttrpc socket.
        let aa_socket = raw
            .aa
            .map(|aa| aa.aa_socket)
            .or(raw.aa_socket)
            .unwrap_or_else(default_aa_socket_addr);

        Self {
            kbc: raw.kbc,
            credentials: raw.credentials,
            image: raw.image,
            socket: raw
                .socket
                .unwrap_or_else(|| DEFAULT_CDH_SOCKET_ADDR.to_string()),
            skip_sealed_secret_verification: raw.skip_sealed_secret_verification,
            aa_socket,
            log: raw.log,
        }
    }
}

impl CdhConfig {
    pub fn new(config_path: Option<String>) -> Result<Self> {
        let config_path = config_path.or_else(|| {
            if let std::result::Result::Ok(env_path) = env::var("CDH_CONFIG_PATH") {
                debug!("Read CDH's config path from env: {env_path}");
                return Some(env_path);
            }
            None
        });

        let mut config = match config_path {
            Some(path) => {
                info!("Use configuration file {path}");
                if !Path::new(&path).exists() {
                    bail!("Config file {path} not found.")
                }

                Self::from_file(&path)?
            }
            None => {
                info!("No config path specified, use a default config (some parts will read from kernel cmdline).");
                Self {
                    kbc: KbsConfig::new()?,
                    credentials: Vec::new(),
                    socket: DEFAULT_CDH_SOCKET_ADDR.into(),
                    skip_sealed_secret_verification: false,
                    aa_socket: DEFAULT_AA_SOCKET_ADDR.into(),
                    image: ImageConfig::from_kernel_cmdline(),
                    log: LogConfig::default(),
                }
            }
        };

        if let std::result::Result::Ok(env) =
            env::var(CDH_DEFAULT_IMAGE_AUTHENTICATED_REGISTRY_CREDENTIALS)
        {
            info!("Read authenticated registry credentials URI from env: {env}");
            config.image.authenticated_registry_credentials_uri = Some(env);
        }

        config.extend_credentials_from_kernel_cmdline()?;
        Ok(config)
    }

    /// Load `CdhConfig` from a configuration file. Supported formats are all formats supported by the
    /// `config` crate.
    fn from_file(config_path: &str) -> Result<Self> {
        let c = Config::builder()
            .set_default("kbc.url", "")?
            .add_source(File::with_name(config_path))
            .build()?;

        let res = c.try_deserialize().context("invalid config")?;
        Ok(res)
    }

    /// all the resource ids can be from the kernel commandline in the following format:
    /// ```shell
    /// cdh.kbs_resources=<resource id 1>::<target path 1>,<resource id 2>::<target path 2>...
    /// ```
    ///
    /// for example
    /// ```shell
    /// cdh.kbs_resources=kbs:///default/key/1::/run/temp1,kbs:///default/key/2::/run/temp2
    /// ```
    ///
    /// It is supposed that all the `target path` should be with prefix
    /// `/run/confidential-containers/cdh` or it will be treated as dangerous
    /// path.
    ///
    /// TODO: delete this way after initdata mechanism could cover CDH's launch config.
    fn extend_credentials_from_kernel_cmdline(&mut self) -> Result<()> {
        let cmdline = fs::read_to_string("/proc/cmdline").context("read kernel cmdline failed")?;
        let kbs_resources = cmdline
            .split_ascii_whitespace()
            .find(|para| para.starts_with("cdh.kbs_resources="))
            .unwrap_or("cdh.kbs_resources=")
            .strip_prefix("cdh.kbs_resources=")
            .expect("must have one")
            .split(',')
            .filter(|s| !s.is_empty())
            .filter_map(|it| it.split_once("::"))
            .map(|it| Credential {
                resource_uri: it.0.to_owned(),
                path: it.1.to_owned(),
            });

        self.credentials.extend(kbs_resources);
        Ok(())
    }
}

impl CdhConfig {
    pub fn set_configuration_envs(&self) -> Result<()> {
        if env::var("AA_KBC_PARAMS").is_err() {
            env::set_var(
                "AA_KBC_PARAMS",
                format!("{}::{}", self.kbc.name, self.kbc.url),
            );
        }
        if env::var("AA_SOCKET").is_err() {
            env::set_var("AA_SOCKET", &self.aa_socket);
        }
        // KBS configurations
        if let Some(kbs_cert) = &self.kbc.kbs_cert {
            env::set_var("KBS_CERT", kbs_cert);
        }
        if self.skip_sealed_secret_verification {
            env::set_var("SKIP_SEALED_SECRET_VERIFICATION", "true");
        }

        #[cfg(any(feature = "ttrpc", feature = "grpc"))]
        self.ensure_ocicrypt_keyprovider_config()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::{env, io::Write};

    use anyhow::anyhow;
    use image_rs::config::{ImageConfig, ProxyConfig};
    use rstest::rstest;

    use crate::{
        config::{DEFAULT_AA_SOCKET_ADDR, DEFAULT_CDH_SOCKET_ADDR},
        CdhConfig, KbsConfig, LogConfig,
    };

    #[rstest]
    #[case(
        r#"
socket = "unix:///run/confidential-containers/cdh.sock"
skip_sealed_secret_verification = true

[log]
level = "debug"

[kbc]
name = "offline_fs_kbc"
url = ""
kbs_cert = ""

[image]
max_concurrent_layer_downloads_per_image = 3
sigstore_config_uri = "kbs:///default/sigstore-config/test"
image_security_policy_uri = "kbs:///default/security-policy/test"
authenticated_registry_credentials_uri = "kbs:///default/credential/test"
extra_root_certificates = ["cert1", "cert2"]
image_pull_proxy = "http://127.0.0.1:8080"
    "#,
        Some(CdhConfig {
            kbc: KbsConfig {
                name: "offline_fs_kbc".to_string(),
                url: "".to_string(),
                kbs_cert: Some("".to_string()),
            },
            credentials: vec![],
            image: ImageConfig {
                max_concurrent_layer_downloads_per_image: 3,
                sigstore_config_uri: Some("kbs:///default/sigstore-config/test".to_string()),
                image_security_policy_uri: Some("kbs:///default/security-policy/test".to_string()),
                authenticated_registry_credentials_uri: Some("kbs:///default/credential/test".to_string()),
                image_pull_proxy: Some(ProxyConfig {
                    https_proxy: Some("http://127.0.0.1:8080".into()),
                    http_proxy: None,
                    no_proxy: None,
                }),
                skip_proxy_ips: None,
                extra_root_certificates: vec!["cert1".into(), "cert2".into()],
                ..Default::default()
            },
            socket: "unix:///run/confidential-containers/cdh.sock".to_string(),
            skip_sealed_secret_verification: true,
            aa_socket: DEFAULT_AA_SOCKET_ADDR.to_string(),
            log: LogConfig {
                level: "debug".to_string(),
            },
        })
    )]
    #[case(
        r#"
socket = "unix:///run/confidential-containers/cdh.sock"

[kbc]
name = "offline_fs_kbc"
url = ""
kbs_cert = ""

[[credentials]]
    "#,
        None
    )]
    #[case(
        r#"
[kbc]
name = "offline_fs_kbc"
"#,
    Some(CdhConfig {
        kbc: KbsConfig {
            name: "offline_fs_kbc".to_string(),
            url: "".to_string(),
            kbs_cert: None,
        },
        credentials: vec![],
        image: ImageConfig {
                sigstore_config_uri: None,
                image_security_policy_uri: None,
                authenticated_registry_credentials_uri: None,
                image_pull_proxy: None,
                skip_proxy_ips: None,
                ..Default::default()
        },
        socket: DEFAULT_CDH_SOCKET_ADDR.to_string(),
        skip_sealed_secret_verification: false,
        aa_socket: DEFAULT_AA_SOCKET_ADDR.to_string(),
        log: LogConfig::default(),
    })
    )]
    #[case(
        r#"
[kbc]
name = "offline_fs_kbc"

[image]
some_undefined_field = "unknown value"
"#,
    Some(CdhConfig {
        kbc: KbsConfig {
            name: "offline_fs_kbc".to_string(),
            url: "".to_string(),
            kbs_cert: None,
        },
        credentials: vec![],
        image: ImageConfig {
                sigstore_config_uri: None,
                image_security_policy_uri: None,
                authenticated_registry_credentials_uri: None,
                image_pull_proxy: None,
                skip_proxy_ips: None,
                ..Default::default()
        },
        socket: DEFAULT_CDH_SOCKET_ADDR.to_string(),
        skip_sealed_secret_verification: false,
        aa_socket: DEFAULT_AA_SOCKET_ADDR.to_string(),
        log: LogConfig::default(),
    })
    )]
    fn read_config(#[case] config: &str, #[case] expected: Option<CdhConfig>) {
        let mut file = tempfile::Builder::new()
            .append(true)
            .suffix(".toml")
            .tempfile()
            .unwrap();
        file.write_all(config.as_bytes()).unwrap();
        let res = CdhConfig::from_file(file.path().to_str().unwrap());
        match expected {
            Some(cfg) => assert_eq!(cfg, res.unwrap()),
            None => assert!(res.is_err()),
        }
    }

    #[test]
    fn example_config_is_valid() {
        let path = format!("{}/../example.config.toml", env!("CARGO_MANIFEST_DIR"));
        CdhConfig::from_file(&path).unwrap();
    }

    #[rstest]
    #[case(
        r#"
[kbc]
name = "offline_fs_kbc"

[aa]
aa_socket = "unix:///run/custom/upstream-aa.sock"
"#,
        "unix:///run/custom/upstream-aa.sock"
    )]
    #[case(
        r#"
aa_socket = "unix:///run/custom/legacy-aa.sock"

[kbc]
name = "offline_fs_kbc"
"#,
        "unix:///run/custom/legacy-aa.sock"
    )]
    #[case(
        r#"
aa_socket = "unix:///run/custom/legacy-aa.sock"

[kbc]
name = "offline_fs_kbc"

[aa]
aa_socket = "unix:///run/custom/upstream-aa.sock"
"#,
        "unix:///run/custom/upstream-aa.sock"
    )]
    #[case(
        r#"
[kbc]
name = "offline_fs_kbc"

[aa]
"#,
        DEFAULT_AA_SOCKET_ADDR
    )]
    fn aa_socket_config_compatibility(#[case] config: &str, #[case] expected: &str) {
        let mut file = tempfile::Builder::new()
            .append(true)
            .suffix(".toml")
            .tempfile()
            .unwrap();
        file.write_all(config.as_bytes()).unwrap();

        let config = CdhConfig::from_file(file.path().to_str().unwrap()).unwrap();
        assert_eq!(config.aa_socket, expected);
    }

    #[test]
    #[serial_test::serial]
    fn set_configuration_envs_sets_defaults_without_overriding_deployment_values() {
        let old_kbc_params = env::var_os("AA_KBC_PARAMS");
        let old_aa_socket = env::var_os("AA_SOCKET");
        let old_skip_verification = env::var_os("SKIP_SEALED_SECRET_VERIFICATION");
        let old_ocicrypt_config = env::var_os("OCICRYPT_KEYPROVIDER_CONFIG");
        env::remove_var("AA_KBC_PARAMS");
        env::remove_var("AA_SOCKET");
        env::remove_var("SKIP_SEALED_SECRET_VERIFICATION");
        env::set_var(
            "OCICRYPT_KEYPROVIDER_CONFIG",
            "/operator/ocicrypt-config.json",
        );

        let config = CdhConfig {
            kbc: KbsConfig {
                name: "cc_kbc".into(),
                url: "http://127.0.0.1:8080".into(),
                kbs_cert: None,
            },
            credentials: Vec::new(),
            image: ImageConfig::default(),
            socket: DEFAULT_CDH_SOCKET_ADDR.into(),
            skip_sealed_secret_verification: true,
            aa_socket: "unix:///run/custom/config-aa.sock".into(),
            log: LogConfig::default(),
        };

        config.set_configuration_envs().unwrap();
        assert_eq!(
            env::var("AA_KBC_PARAMS").unwrap(),
            "cc_kbc::http://127.0.0.1:8080"
        );
        assert_eq!(
            env::var("AA_SOCKET").unwrap(),
            "unix:///run/custom/config-aa.sock"
        );
        assert_eq!(env::var("SKIP_SEALED_SECRET_VERIFICATION").unwrap(), "true");

        env::set_var("AA_KBC_PARAMS", "deployment_kbc::http://kbs.example");
        env::set_var("AA_SOCKET", "unix:///run/custom/deployment-aa.sock");
        config.set_configuration_envs().unwrap();
        assert_eq!(
            env::var("AA_KBC_PARAMS").unwrap(),
            "deployment_kbc::http://kbs.example"
        );
        assert_eq!(
            env::var("AA_SOCKET").unwrap(),
            "unix:///run/custom/deployment-aa.sock"
        );

        match old_kbc_params {
            Some(value) => env::set_var("AA_KBC_PARAMS", value),
            None => env::remove_var("AA_KBC_PARAMS"),
        }
        match old_aa_socket {
            Some(value) => env::set_var("AA_SOCKET", value),
            None => env::remove_var("AA_SOCKET"),
        }
        match old_skip_verification {
            Some(value) => env::set_var("SKIP_SEALED_SECRET_VERIFICATION", value),
            None => env::remove_var("SKIP_SEALED_SECRET_VERIFICATION"),
        }
        match old_ocicrypt_config {
            Some(value) => env::set_var("OCICRYPT_KEYPROVIDER_CONFIG", value),
            None => env::remove_var("OCICRYPT_KEYPROVIDER_CONFIG"),
        }
    }

    #[test]
    #[serial_test::serial]
    fn test_config_path() {
        // --config takes precedence,
        // then env.CDH_CONFIG_PATH

        let config = CdhConfig::new(None).expect("Must be successful");
        let expected = CdhConfig {
            kbc: KbsConfig {
                name: "offline_fs_kbc".into(),
                url: "".into(),
                kbs_cert: None,
            },
            credentials: Vec::new(),
            socket: DEFAULT_CDH_SOCKET_ADDR.into(),
            skip_sealed_secret_verification: false,
            aa_socket: DEFAULT_AA_SOCKET_ADDR.into(),
            image: ImageConfig::from_kernel_cmdline(),
            log: LogConfig::default(),
        };
        assert_eq!(config, expected);

        let config = CdhConfig::new(Some("/thing".into())).unwrap_err();
        let expected = anyhow!("Config file /thing not found.");
        assert_eq!(format!("{config}"), format!("{expected}"));

        env::set_var("CDH_CONFIG_PATH", "/byenv");
        let config = CdhConfig::new(None).unwrap_err();
        let expected = anyhow!("Config file /byenv not found.");
        assert_eq!(format!("{config}"), format!("{expected}"));
        env::remove_var("CDH_CONFIG_PATH");

        let config = CdhConfig::new(Some("/thing".into())).unwrap_err();
        let expected = anyhow!("Config file /thing not found.");
        assert_eq!(format!("{config}"), format!("{expected}"));
    }

    #[test]
    #[serial_test::serial]
    fn test_config_auth_override_by_env() {
        let config = r#"
[kbc]
name = "offline_fs_kbc"

[image]
authenticated_registry_credentials_uri = "kbs:///default/auth/1"
        "#;
        let mut file = tempfile::Builder::new()
            .append(true)
            .suffix(".toml")
            .tempfile()
            .unwrap();
        file.write_all(config.as_bytes()).unwrap();

        // without env and from config file
        let config_path = file.path().to_str().unwrap().to_string();
        let config = CdhConfig::new(Some(config_path.clone())).expect("Must be successful");
        assert_eq!(
            config.image.authenticated_registry_credentials_uri,
            Some("kbs:///default/auth/1".into())
        );

        // overrided by env
        env::set_var(
            "CDH_DEFAULT_IMAGE_AUTHENTICATED_REGISTRY_CREDENTIALS",
            "file:///test",
        );
        let config = CdhConfig::new(Some(config_path.clone())).unwrap();
        assert_eq!(
            config.image.authenticated_registry_credentials_uri,
            Some("file:///test".to_string())
        );
        env::remove_var("CDH_DEFAULT_IMAGE_AUTHENTICATED_REGISTRY_CREDENTIALS");

        // no env again
        let config = CdhConfig::new(Some(config_path)).unwrap();
        assert_eq!(
            config.image.authenticated_registry_credentials_uri,
            Some("kbs:///default/auth/1".into())
        );
    }
}
