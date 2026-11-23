// Copyright (c) 2026 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0

use anyhow::{ensure, Result};
use serde::Deserialize;

/// Defaults for the attested KMS client, independent of CDH's transport layer.
#[derive(Clone, Deserialize, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct KmsConfig {
    #[serde(default)]
    pub instance_id: Option<String>,
    pub ecs_ram_role_name: Option<String>,
    /// Request regions take priority. If both are absent, use ECS IMDS.
    #[serde(default)]
    pub region_id: Option<String>,
    /// Linux interface for KMS instance HTTPS connections only.
    pub data_plane_interface: Option<String>,
}

impl KmsConfig {
    pub(crate) fn validate(&self) -> Result<()> {
        if let Some(instance_id) = &self.instance_id {
            ensure!(
                valid_kms_instance_id(instance_id),
                "kbc.instance_id must be a bare KMS instance ID (kst-...)"
            );
        }
        if let Some(role) = &self.ecs_ram_role_name {
            ensure!(
                valid_identifier(role),
                "kbc.ecs_ram_role_name must be a nonempty RAM role name, not an ARN or URL"
            );
        }
        if let Some(region) = &self.region_id {
            ensure!(valid_region_id(region), "kbc.region_id is invalid");
        }
        if let Some(interface) = &self.data_plane_interface {
            ensure!(
                cfg!(target_os = "linux"),
                "kbc.data_plane_interface is only supported on Linux"
            );
            // Linux IFNAMSIZ includes the terminating NUL.
            ensure!(
                interface.len() < 16 && valid_identifier(interface),
                "kbc.data_plane_interface must be a valid interface name of at most 15 bytes"
            );
        }
        Ok(())
    }
}

pub(crate) fn valid_region_id(region: &str) -> bool {
    !region.is_empty()
        && region.len() <= 64
        && region
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

pub(crate) fn valid_kms_instance_id(instance_id: &str) -> bool {
    instance_id.starts_with("kst-")
        && instance_id.len() > 4
        && instance_id.len() <= 128
        && instance_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value != "."
        && value != ".."
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_optional_but_explicit_invalid_values_are_rejected() {
        let default = KmsConfig {
            instance_id: None,
            ecs_ram_role_name: None,
            region_id: None,
            data_plane_interface: None,
        };
        assert!(default.validate().is_ok());
        for invalid in [
            KmsConfig {
                instance_id: Some("".into()),
                ..default.clone()
            },
            KmsConfig {
                ecs_ram_role_name: Some("role/invalid".into()),
                ..default.clone()
            },
            KmsConfig {
                region_id: Some("cn/beijing".into()),
                ..default.clone()
            },
        ] {
            assert!(invalid.validate().is_err());
        }
        assert!(KmsConfig {
            instance_id: Some("kst-test".into()),
            ecs_ram_role_name: Some("product-role".into()),
            region_id: Some("cn-beijing".into()),
            data_plane_interface: None,
        }
        .validate()
        .is_ok());
    }

    #[test]
    fn data_plane_interface_is_optional_and_validated() {
        let default: KmsConfig = toml::from_str("").unwrap();
        assert_eq!(default.data_plane_interface, None);
        let configured: KmsConfig = toml::from_str(r#"data_plane_interface = "eth1.200""#).unwrap();
        assert_eq!(configured.data_plane_interface.as_deref(), Some("eth1.200"));
        assert_eq!(configured.validate().is_ok(), cfg!(target_os = "linux"));
        for interface in ["", "eth 1", "eth1/eth2", ".", "abcdefghijklmnop"] {
            assert!(KmsConfig {
                data_plane_interface: Some(interface.into()),
                ..default.clone()
            }
            .validate()
            .is_err());
        }
    }
}
