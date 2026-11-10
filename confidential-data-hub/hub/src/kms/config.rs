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
            region_id: Some("cn-beijing".into())
        }
        .validate()
        .is_ok());
    }
}
