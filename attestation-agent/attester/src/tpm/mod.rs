// Copyright (c) 2024 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//
use crate::tpm::utils::*;
use crate::types::TpmEvidence;
use crate::utils::read_eventlog;
use crate::{Attester, TeeEvidence};
use anyhow::*;
use base64::Engine;
use kbs_types::HashAlgorithm;
use rsa as rust_rsa;
use rsa::pkcs8::EncodePublicKey;
use std::collections::HashMap;
use std::path::Path;

mod utils;

const TPM_EVENTLOG_FILE_PATH: &str = "/sys/kernel/security/tpm0/binary_bios_measurements";
const TPM_REPORT_DATA_SIZE: usize = 32;

const KEYLIME_AGENT_INFO_URL: &str = "http://127.0.0.1:9002/v2.2/agent/info";

#[derive(serde::Deserialize)]
struct KeylimeAgentResults {
    agent_uuid: Option<String>,
    ak_handle: Option<u32>,
}

#[derive(serde::Deserialize)]
struct KeylimeAgentResp {
    results: Option<KeylimeAgentResults>,
}

async fn try_get_keylime_info() -> Option<(String, u32)> {
    let resp = reqwest::get(KEYLIME_AGENT_INFO_URL).await.ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let info: KeylimeAgentResp = resp.json().await.ok()?;
    let r = info.results?;
    Some((r.agent_uuid?, r.ak_handle?))
}

pub fn detect_platform() -> bool {
    Path::new("/dev/tpm0").exists()
}

#[derive(Debug, Default)]
pub struct TpmAttester {}

#[async_trait::async_trait]
impl Attester for TpmAttester {
    async fn get_evidence(&self, mut report_data: Vec<u8>) -> Result<TeeEvidence> {
        if report_data.len() > TPM_REPORT_DATA_SIZE {
            log::warn!(
                "TPM Attester: Report data truncated from {} to {} bytes",
                report_data.len(),
                TPM_REPORT_DATA_SIZE
            );
            report_data.truncate(TPM_REPORT_DATA_SIZE);
        }
        report_data.resize(TPM_REPORT_DATA_SIZE, 0);

        let mut keylime_uuid: Option<String> = None;
        let mut quote = HashMap::new();
        let mut ak_pubkey_pem: Option<String> = None;

        if let Some((uuid, akh)) = try_get_keylime_info().await {
            keylime_uuid = Some(uuid);
            let mut ctx = create_ctx_with_session()?;
            if let Result::Ok(handle) = load_ak_handle_from_persistent(&mut ctx, akh) {
                quote.insert(
                    "SHA1".to_string(),
                    get_quote(&mut ctx, handle, &report_data, "SHA1")?,
                );
                quote.insert(
                    "SHA256".to_string(),
                    get_quote(&mut ctx, handle, &report_data, "SHA256")?,
                );
                ak_pubkey_pem = Some(
                    get_ak_pub_from_persistent(akh)?
                        .to_public_key_pem(rust_rsa::pkcs8::LineEnding::LF)?,
                );
            }
        }

        if ak_pubkey_pem.is_none() {
            let attestation_key = generate_rsa_ak()?;
            let mut ctx = create_ctx_with_session()?;
            let handle = import_ak_handle(&mut ctx, attestation_key.clone())?;
            quote.insert(
                "SHA1".to_string(),
                get_quote(&mut ctx, handle, &report_data, "SHA1")?,
            );
            quote.insert(
                "SHA256".to_string(),
                get_quote(&mut ctx, handle, &report_data, "SHA256")?,
            );
            ak_pubkey_pem = Some(
                get_ak_pub(attestation_key)?.to_public_key_pem(rust_rsa::pkcs8::LineEnding::LF)?,
            );
        }

        let engine = base64::engine::general_purpose::STANDARD;
        let eventlog = match std::fs::read(TPM_EVENTLOG_FILE_PATH) {
            Result::Ok(el) => Some(engine.encode(el)),
            Result::Err(e) => {
                log::warn!("Read TPM Eventlog failed: {:?}", e);
                None
            }
        };
        let aa_eventlog = read_eventlog().await?;

        let evidence = TpmEvidence {
            ek_cert: dump_ek_cert_pem().ok(),
            ak_pubkey: ak_pubkey_pem.ok_or_else(|| anyhow!("AK pubkey must be set"))?,
            keylime_agent_uuid: keylime_uuid,
            quote,
            eventlog,
            aa_eventlog,
        };

        serde_json::to_value(evidence)
            .map_err(|e| anyhow!("Serialize TPM evidence failed: {:?}", e))
    }

    async fn extend_runtime_measurement(&self, digest: Vec<u8>, index: u64) -> Result<()> {
        pcr_extend(digest, index)
    }

    async fn get_runtime_measurement(&self, index: u64) -> Result<Vec<u8>> {
        let pcr_index = index as usize;

        // Now only support SHA256 runtime measurement
        let pcrs = dump_pcrs("SHA256")?;
        let target_pcr = pcrs
            .get(pcr_index)
            .ok_or_else(|| anyhow::anyhow!("Register index out of bounds"))?;
        let pcr_value = hex::decode(target_pcr)?;

        Ok(pcr_value)
    }

    fn pcr_to_ccmr(&self, pcr_index: u64) -> u64 {
        pcr_index
    }

    fn ccel_hash_algorithm(&self) -> HashAlgorithm {
        HashAlgorithm::Sha256
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
