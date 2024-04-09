// Copyright (c) 2024 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use crate::tpm::utils::*;
use crate::Attester;
use anyhow::*;
use base64::Engine;
use rsa as rust_rsa;
use rust_rsa::pkcs8::EncodePublicKey;
use serde::{Deserialize, Serialize};
use std::path::Path;

mod utils;

const TPM_EVENTLOG_FILE_PATH: &str = "/sys/kernel/security/tpm0/binary_bios_measurements";
const TPM_REPORT_DATA_SIZE: usize = 64;

#[derive(Serialize, Deserialize)]
struct TpmEvidence {
    // PEM format of EK certificate
    pub ek_cert: String,
    // PEM format of AK public key
    pub ak_pubkey: String,
    // TPM Quote
    pub quote: TpmQuote,
    // PCR digests
    pub pcrs: Vec<String>,
    // Base64 encoded Eventlog ACPI table
    pub eventlog: Option<String>,
}

pub fn detect_platform() -> bool {
    Path::new("/dev/tpm0").exists()
}

#[derive(Debug, Default)]
pub struct TpmAttester {}

#[async_trait::async_trait]
impl Attester for TpmAttester {
    async fn get_evidence(&self, mut report_data: Vec<u8>) -> Result<String> {
        if report_data.len() > TPM_REPORT_DATA_SIZE {
            bail!("TPM Attester: Report data must be no more than {TPM_REPORT_DATA_SIZE} bytes");
        }

        report_data.resize(TPM_REPORT_DATA_SIZE, 0);

        let attestation_key = generate_rsa_ak()?;

        let quote = get_quote(attestation_key.clone(), &report_data)?;

        let engine = base64::engine::general_purpose::STANDARD;

        let eventlog = match std::fs::read(TPM_EVENTLOG_FILE_PATH) {
            Result::Ok(el) => Some(engine.encode(el)),
            Result::Err(e) => {
                log::warn!("Read TPM Eventlog failed: {:?}", e);
                None
            }
        };

        let evidence = TpmEvidence {
            ek_cert: dump_ek_cert_pem()?,
            ak_pubkey: get_ak_pub(attestation_key)?
                .to_public_key_pem(rust_rsa::pkcs8::LineEnding::LF)?,
            quote,
            pcrs: dump_pcr_sha256_digests()?,
            eventlog,
        };

        serde_json::to_string(&evidence)
            .map_err(|e| anyhow!("Serialize TPM evidence failed: {:?}", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[ignore]
    #[tokio::test]
    async fn test_tpm_get_evidence() {
        let attester = TpmAttester::default();
        let report_data: Vec<u8> = vec![0; 48];

        let evidence = attester.get_evidence(report_data).await;
        assert!(evidence.is_ok());
    }
}
