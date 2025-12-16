// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use super::{Attester, TeeEvidence};
use anyhow::*;
use base64::Engine;
use kbs_types::HashAlgorithm;
use log::warn;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::utils::read_eventlog;

mod measure_register;
use measure_register::{MeasureRegister, MEASURE_DIGEST_LEN, MEASURE_REGISTER_PATH};

// Sample attester is always supported
pub fn detect_platform() -> bool {
    true
}

// A simple example of TEE evidence.
#[derive(Serialize, Deserialize, Debug)]
struct SampleQuote {
    svn: String,
    report_data: String,
    measure_register: String,
    cc_eventlog: Option<String>,
}

#[derive(Debug)]
pub struct SampleAttester {
    measure_register: Arc<Mutex<MeasureRegister>>,
}

impl Default for SampleAttester {
    fn default() -> Self {
        Self {
            measure_register: Arc::new(Mutex::new(MeasureRegister::new(MEASURE_REGISTER_PATH))),
        }
    }
}

#[async_trait::async_trait]
impl Attester for SampleAttester {
    async fn get_evidence(&self, report_data: Vec<u8>) -> Result<TeeEvidence> {
        // Hold the register lock while reading both measurement and eventlog to keep them consistent.
        let (measure_register, cc_eventlog) = {
            let reg = self.measure_register.lock().await;
            let bytes = reg
                .current_value()
                .await
                .map_err(|e| anyhow!("Read sample measure register: {e}"))?;
            let cc_eventlog = read_eventlog().await?;
            (hex::encode(bytes), cc_eventlog)
        };

        let evidence = SampleQuote {
            svn: "1".to_string(),
            report_data: base64::engine::general_purpose::STANDARD.encode(report_data),
            measure_register,
            cc_eventlog,
        };

        serde_json::to_value(evidence).map_err(|e| anyhow!("Serialize sample evidence failed: {e}"))
    }

    async fn extend_runtime_measurement(
        &self,
        event_digest: Vec<u8>,
        _register_index: u64,
    ) -> Result<()> {
        if event_digest.len() != MEASURE_DIGEST_LEN {
            bail!(
                "Sample Attester requires {}-byte digest (SHA256), got {}",
                MEASURE_DIGEST_LEN,
                event_digest.len()
            );
        }
        let digest: [u8; MEASURE_DIGEST_LEN] = event_digest
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("Failed to convert digest to fixed 32-byte array"))?;

        let reg = self.measure_register.lock().await;
        reg.extend(&digest)
            .await
            .map_err(|e| anyhow!("Extend sample measure register: {e}"))?;

        Ok(())
    }

    async fn get_runtime_measurement(&self, _pcr_index: u64) -> Result<Vec<u8>> {
        let reg = self.measure_register.lock().await;
        reg.current_value()
            .await
            .map_err(|e| anyhow!("Load sample measure register: {e}"))
    }

    fn pcr_to_ccmr(&self, pcr_index: u64) -> u64 {
        warn!("Sample Attester maps all PCR indexes to a single CCMR slot.");
        // All PCR indices are mapped to the same simulated register.
        let _ = pcr_index;
        1
    }

    fn ccel_hash_algorithm(&self) -> HashAlgorithm {
        HashAlgorithm::Sha256
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_sample_attester() {
        let attester = SampleAttester::default();
        let report_data = vec![1, 2, 3, 4, 5];
        let evidence = attester.get_evidence(report_data).await.unwrap();
        println!("{}", evidence);
    }
}
