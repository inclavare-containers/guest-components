// Copyright (c) 2024 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::Result;
use serde::Deserialize;

use super::aa_kbc_params::AaKbcParams;

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct CoCoASConfig {
    /// URL Address of Attestation Service.
    pub url: String,
}

impl CoCoASConfig {
    pub fn new() -> Result<Self> {
        let aa_kbc_params = AaKbcParams::new()?;
        Ok(Self {
            url: aa_kbc_params.uri,
        })
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_coco_as_config() {
        let config = super::CoCoASConfig::new();
        assert!(config.is_ok());
    }
}
