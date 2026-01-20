// Copyright (c) 2024 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//
mod measure_register;
pub mod sysinfo;
use super::Attester;
use crate::TeeEvidence;
use anyhow::*;
use base64::Engine;
use kbs_types::HashAlgorithm;
use log::warn;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::utils::read_eventlog;
use measure_register::{MeasureRegister, HASH_ALG, MEASURE_DIGEST_LEN, MEASURE_REGISTER_PATH};

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
    rtmr_register: String,
    cc_eventlog: Option<String>,
    environment: HashMap<String, String>,
    report_data: String,
}

pub struct SystemAttester {
    runtime_register: Arc<Mutex<MeasureRegister>>,
}

impl SystemAttester {
    pub fn new() -> Result<Self> {
        Ok(Self {
            runtime_register: Arc::new(Mutex::new(MeasureRegister::new(MEASURE_REGISTER_PATH))),
        })
    }
}

#[async_trait::async_trait]
impl Attester for SystemAttester {
    async fn get_evidence(&self, report_data: Vec<u8>) -> Result<TeeEvidence> {
        let machine_info = sysinfo::get_machine_info()?;
        let system_report = serde_json::to_string(&machine_info)?;
        // Hold the register lock while reading both measurement and eventlog to keep them consistent.
        let (rtmr_register, cc_eventlog) = {
            let reg = self.runtime_register.lock().await;
            let bytes = reg
                .current_value()
                .await
                .map_err(|e| anyhow!("Read system runtime register: {e}"))?;
            let cc_eventlog = read_eventlog().await?;
            (hex::encode(bytes), cc_eventlog)
        };
        let mut environment: HashMap<String, String> = HashMap::new();
        for (env_name, env_value) in env::vars() {
            if env_name == TRUSTEE_API_KEY_ENV {
                continue;
            }
            environment.insert(env_name, env_value);
        }

        let evidence = SystemQuote {
            system_report,
            rtmr_register,
            cc_eventlog,
            environment,
            report_data: base64::engine::general_purpose::STANDARD.encode(report_data),
        };
        serde_json::to_value(evidence).context("Serialize system evidence failed")
    }

    async fn extend_runtime_measurement(
        &self,
        event_digest: Vec<u8>,
        _register_index: u64,
    ) -> Result<()> {
        if event_digest.len() != MEASURE_DIGEST_LEN {
            bail!(
                "System Attester requires {}-byte digest (SHA384), got {}",
                MEASURE_DIGEST_LEN,
                event_digest.len()
            );
        }
        let digest: [u8; MEASURE_DIGEST_LEN] = event_digest
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("Failed to convert digest to fixed 48-byte array"))?;

        let reg = self.runtime_register.lock().await;
        reg.extend(&digest)
            .await
            .map_err(|e| anyhow!("Extend system runtime register: {e}"))?;

        Ok(())
    }

    async fn get_runtime_measurement(&self, _pcr_index: u64) -> Result<Vec<u8>> {
        let reg = self.runtime_register.lock().await;
        reg.current_value()
            .await
            .map_err(|e| anyhow!("Load system runtime register: {e}"))
    }

    fn pcr_to_ccmr(&self, pcr_index: u64) -> u64 {
        warn!("System Attester maps all PCR indexes to a single CCMR slot.");
        let _ = pcr_index;
        1
    }

    fn ccel_hash_algorithm(&self) -> HashAlgorithm {
        HASH_ALG
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
