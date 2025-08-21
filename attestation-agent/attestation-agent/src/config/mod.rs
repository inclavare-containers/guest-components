// Copyright (c) 2024 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::Result;
use serde::Deserialize;

/// Default PCR index used by AA. `17` is selected for its usage of dynamic root of trust for measurement.
/// - [Linux TPM PCR Registry](https://uapi-group.org/specifications/specs/linux_tpm_pcr_registry/)
/// - [TCG TRUSTED BOOT CHAIN IN EDK II](https://tianocore-docs.github.io/edk2-TrustedBootChain/release-1.00/3_TCG_Trusted_Boot_Chain_in_EDKII.html)
const DEFAULT_PCR_INDEX: u64 = 17;

pub mod aa_kbc_params;

#[cfg(feature = "coco_as")]
pub mod coco_as;

#[cfg(feature = "kbs")]
pub mod kbs;

pub const DEFAULT_AA_CONFIG_PATH: &str = "/etc/attestation-agent.conf";

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct Config {
    /// configs about token
    pub token_configs: TokenConfigs,

    /// configs about eventlog
    pub eventlog_config: EventlogConfig,

    /// configs about aa instance
    #[cfg(feature = "instance_info")]
    #[serde(default)]
    pub aa_instance: AAInstanceConfig,
}

#[derive(Clone, Debug, Deserialize)]
pub struct EventlogConfig {
    /// PCR Register to extend INIT entry
    pub init_pcr: u64,

    /// Flag whether enable eventlog recording
    pub enable_eventlog: bool,
}

#[cfg(feature = "instance_info")]
#[derive(Clone, Debug, Deserialize, Default, PartialEq)]
pub struct AAInstanceConfig {
    /// AA instance type
    pub instance_type: Option<String>,

    /// Heartbeat configuration
    #[serde(default)]
    pub heartbeat: HeartbeatConfig,
}

#[cfg(feature = "instance_info")]
#[derive(Clone, Debug, Deserialize, Default, PartialEq)]
pub struct HeartbeatConfig {
    /// Flag whether enable heartbeat
    #[serde(default)]
    pub enabled: bool,

    /// Trustee server URL for heartbeat
    pub trustee_url: Option<String>,

    /// Heartbeat interval in minutes
    pub interval_minutes: Option<u64>,
}

impl Default for EventlogConfig {
    fn default() -> Self {
        Self {
            init_pcr: DEFAULT_PCR_INDEX,
            enable_eventlog: false,
        }
    }
}

impl Config {
    pub fn new() -> Result<Self> {
        Ok(Self {
            token_configs: TokenConfigs::from_kernel_cmdline(),
            eventlog_config: EventlogConfig::default(),
            #[cfg(feature = "instance_info")]
            aa_instance: AAInstanceConfig::default(),
        })
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct TokenConfigs {
    /// This config item is used when `coco_as` feature is enabled.
    #[cfg(feature = "coco_as")]
    pub coco_as: coco_as::CoCoASConfig,

    /// This config item is used when `kbs` feature is enabled.
    #[cfg(feature = "kbs")]
    pub kbs: kbs::KbsConfig,
}

impl TokenConfigs {
    pub fn from_kernel_cmdline() -> Self {
        #[cfg(feature = "kbs")]
        let kbs = kbs::KbsConfig::new().ok();

        Self {
            #[cfg(feature = "coco_as")]
            coco_as: None,

            #[cfg(feature = "kbs")]
            kbs,
        }
    }
}

impl TryFrom<&str> for Config {
    type Error = config::ConfigError;
    fn try_from(config_path: &str) -> Result<Self, Self::Error> {
        let c = config::Config::builder()
            .add_source(config::File::with_name(config_path))
            .set_default("eventlog_config.init_pcr", DEFAULT_PCR_INDEX)?
            .set_default("eventlog_config.enable_eventlog", "false")?
            .build()?;

        let cfg = c.try_deserialize()?;
        Ok(cfg)
    }
}

#[cfg(test)]
mod tests {
    #[rstest::rstest]
    #[case("tests/config.example.toml")]
    #[case("tests/config.example.json")]
    #[case("tests/aa_instance_info_test.toml")]
    fn parse_config(#[case] config: &str) {
        let _config = super::Config::try_from(config).expect("failed to parse config file");
    }

    #[test]
    fn test_config_default() {
        let config = super::Config::new().expect("failed to create config");
        assert_eq!(config.eventlog_config.init_pcr, super::DEFAULT_PCR_INDEX);
        assert_eq!(config.eventlog_config.enable_eventlog, false);
    }

    #[cfg(feature = "instance_info")]
    #[test]
    fn test_aa_instance_config_default() {
        let config = super::Config::new().expect("failed to create config");
        assert_eq!(config.aa_instance.heartbeat.enabled, false);
        assert_eq!(config.aa_instance.heartbeat.trustee_url, None);
        assert_eq!(config.aa_instance.heartbeat.interval_minutes, None);
        assert_eq!(config.aa_instance.instance_type, None);
    }
}
