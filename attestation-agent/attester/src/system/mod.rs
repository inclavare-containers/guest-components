// Copyright (c) 2024 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//
mod inner;
pub mod sysinfo;
use super::Attester;
use crate::TeeEvidence;
use anyhow::*;
use base64::Engine;
use inner::SystemAttesterdInner;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;

const TRUSTEE_API_KEY_ENV: &str = "TRUSTEE_API_KEY";

// System attester is always supported
pub fn detect_platform() -> bool {
    if let Result::Ok(system_attestation) = std::env::var("SYSTEM_ATTESTATION") {
        system_attestation.to_lowercase() == "true"
    } else {
        false
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct SystemQuote {
    system_report: String,
    measurements: String,
    mr_register: String,
    environment: HashMap<String, String>,
    report_data: String,
}

pub struct SystemAttester {
    inner: SystemAttesterdInner,
}

impl SystemAttester {
    pub fn new() -> Result<Self> {
        let mut inner = SystemAttesterdInner::default();
        inner.init()?;
        Ok(Self { inner })
    }
}

#[async_trait::async_trait]
impl Attester for SystemAttester {
    async fn get_evidence(&self, report_data: Vec<u8>) -> Result<TeeEvidence> {
        let system_report = self.inner.read_sys_report()?;
        let measurements = serde_json::to_string(&self.inner.get_measurements())?;
        let mr_register = self.inner.read_mr_register();
        let mut environment: HashMap<String, String> = HashMap::new();
        for (env_name, env_value) in env::vars() {
            if env_name == TRUSTEE_API_KEY_ENV {
                continue;
            }
            environment.insert(env_name, env_value);
        }

        let evidence = SystemQuote {
            system_report,
            measurements,
            mr_register,
            environment,
            report_data: base64::engine::general_purpose::STANDARD.encode(report_data),
        };
        serde_json::to_value(evidence).context("Serialize system evidence failed")
    }
}

#[cfg(test)]
mod tests {
    use crate::{system::SystemAttester, Attester};

    #[tokio::test]
    async fn test_system_get_evidence() {
        let attester = SystemAttester::new().unwrap(); // Update for sync
        let report_data: Vec<u8> = vec![0; 48];
        let evidence = attester.get_evidence(report_data).await;
        assert!(evidence.is_ok());
    }
}
