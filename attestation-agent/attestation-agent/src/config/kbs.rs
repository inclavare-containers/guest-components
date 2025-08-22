// Copyright (c) 2024 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::Result;
use serde::Deserialize;

use super::aa_kbc_params::AaKbcParams;

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct KbsConfig {
    /// URL Address of KBS.
    pub url: String,

    /// Cert of KBS
    pub cert: Option<String>,
}

impl KbsConfig {
    pub fn new() -> Result<Self> {
        let aa_kbc_params = AaKbcParams::new()?;
        Ok(Self {
            url: aa_kbc_params.uri,
            cert: None,
        })
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_kbs_config() {
        let kbs_config = super::KbsConfig::new().unwrap();
        assert_eq!(kbs_config.url, "");
        assert_eq!(kbs_config.cert, None);
    }
}
