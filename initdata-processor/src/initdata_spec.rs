// Copyright (c) 2025 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//
// Aligned with kata-containers `kata_types::initdata::InitData` for parsing guest initdata TOML.

use anyhow::{anyhow, Result};
use serde::Deserialize;
use std::collections::HashMap;

const INITDATA_VERSION: &str = "0.1.0";
const SUPPORTED_ALGORITHMS: [&str; 3] = ["sha256", "sha384", "sha512"];

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct InitData {
    version: String,
    algorithm: String,
    data: HashMap<String, String>,
}

impl InitData {
    pub fn validate(&self) -> Result<()> {
        if self.version != INITDATA_VERSION {
            return Err(anyhow!(
                "unsupported version: {}, expected: {}",
                self.version,
                INITDATA_VERSION
            ));
        }

        if !SUPPORTED_ALGORITHMS
            .iter()
            .any(|&alg| alg == self.algorithm)
        {
            return Err(anyhow!(
                "unsupported algorithm: {}, supported algorithms: {}",
                self.algorithm,
                SUPPORTED_ALGORITHMS.join(", ")
            ));
        }

        Ok(())
    }

    pub fn algorithm(&self) -> &str {
        &self.algorithm
    }

    pub fn data(&self) -> &HashMap<String, String> {
        &self.data
    }
}
