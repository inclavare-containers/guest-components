// Copyright (c) 2024 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::Result;
use crypto::HashAlgorithm;
use serde::Deserialize;
use std::str::FromStr;

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

pub const DEFAULT_EVENTLOG_HASH: &str = "sha384";

#[derive(Clone, Debug, Deserialize)]
pub struct Config {
    /// configs about token
    pub token_configs: TokenConfigs,

    /// configs about eventlog
    pub eventlog_config: EventlogConfig,

    /// configs about file measurement
    pub file_measurement_config: FileMeasurementConfig,
}

#[derive(Clone, Debug, Deserialize)]
pub struct EventlogConfig {
    /// Hash algorithm used to extend runtime measurement for eventlog.
    pub eventlog_algorithm: HashAlgorithm,

    /// PCR Register to extend INIT entry
    pub init_pcr: u64,

    /// Flag whether enable eventlog recording
    pub enable_eventlog: bool,
}

impl Default for EventlogConfig {
    fn default() -> Self {
        Self {
            eventlog_algorithm: HashAlgorithm::Sha384,
            init_pcr: DEFAULT_PCR_INDEX,
            enable_eventlog: false,
        }
    }
}

/// The measurement mode for file measurement
#[derive(Clone, Debug, Deserialize, PartialEq, Default)]
#[serde(rename_all = "snake_case")]
pub enum MeasurementMode {
    /// Always measure files on every startup
    Always,
    /// Only measure files when EventLog is being created for the first time
    #[default]
    InitOnly,
}

impl FromStr for MeasurementMode {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "always" => Ok(MeasurementMode::Always),
            "init_only" => Ok(MeasurementMode::InitOnly),
            _ => Err(anyhow::anyhow!("Invalid measurement mode: {}", s)),
        }
    }
}

/// Configuration for batch file measurement
#[derive(Clone, Debug, Deserialize, Default)]
pub struct FileMeasurementConfig {
    /// Flag whether enable file measurement
    pub enable: bool,

    /// Measurement mode - when to perform file measurements
    #[serde(default)]
    pub mode: MeasurementMode,

    /// PCR Register to extend file measurement
    pub pcr_index: u64,

    /// Domain for file measurement events
    pub domain: String,

    /// Operation for file measurement events
    pub operation: String,

    /// List of file paths or glob patterns to measure
    /// Supports standard glob patterns:
    /// - `*`: Matches any sequence of characters (except path separators)
    /// - `?`: Matches any single character (except path separators)
    /// - `[abc]`: Matches any of the specified characters
    /// - `[a-z]`: Matches any character in the specified range
    #[serde(default)]
    pub files: Vec<String>,
}

impl Config {
    pub fn new() -> Result<Self> {
        Ok(Self {
            token_configs: TokenConfigs::new()?,
            eventlog_config: EventlogConfig::default(),
            file_measurement_config: FileMeasurementConfig::default(),
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
    pub fn new() -> Result<Self> {
        Ok(Self {
            #[cfg(feature = "coco_as")]
            coco_as: coco_as::CoCoASConfig::new()?,

            #[cfg(feature = "kbs")]
            kbs: kbs::KbsConfig::new()?,
        })
    }
}

impl TryFrom<&str> for Config {
    type Error = config::ConfigError;
    fn try_from(config_path: &str) -> Result<Self, Self::Error> {
        let c = config::Config::builder()
            .add_source(config::File::with_name(config_path))
            .set_default("eventlog_config.eventlog_algorithm", DEFAULT_EVENTLOG_HASH)?
            .set_default("eventlog_config.init_pcr", DEFAULT_PCR_INDEX)?
            .set_default("eventlog_config.enable_eventlog", "false")?
            .set_default("file_measurement_config.enable", "false")?
            .set_default("file_measurement_config.mode", "init_only")?
            .set_default("file_measurement_config.pcr_index", DEFAULT_PCR_INDEX)?
            .set_default("file_measurement_config.domain", "file")?
            .set_default("file_measurement_config.operation", "measure")?
            .build()?;

        let cfg = c.try_deserialize()?;
        Ok(cfg)
    }
}

#[cfg(test)]
mod tests {
    #[rstest::rstest]
    #[case("config.example.toml")]
    #[case("config.example.json")]
    fn parse_config(#[case] config: &str) {
        let _config = super::Config::try_from(config).expect("failed to parse config file");
    }

    #[test]
    fn test_config_default() {
        let config = super::Config::new().expect("failed to create config");
        assert_eq!(
            config.eventlog_config.eventlog_algorithm,
            super::HashAlgorithm::Sha384
        );
        assert_eq!(config.eventlog_config.init_pcr, super::DEFAULT_PCR_INDEX);
        assert_eq!(config.eventlog_config.enable_eventlog, false);
    }
}
