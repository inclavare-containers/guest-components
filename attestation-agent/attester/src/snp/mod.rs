// Copyright (c) 2022 IBM
//
// SPDX-License-Identifier: Apache-2.0
//

use crate::utils::pad;
use crate::InitDataResult;

#[cfg(feature = "tsm-report")]
use crate::tsm_report::{TsmReportData, TsmReportPath, TsmReportProvider};

use super::{Attester, TeeEvidence};
use anyhow::*;
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Serialize};
use sev::firmware::guest::AttestationReport;
use sev::firmware::guest::Firmware;
use sev::firmware::host::CertTableEntry;
use std::path::Path;

mod hostdata;

const SVSM_VTPM_SERVICE_GUID: &str = "c476f1eb-0123-45a5-9641-b4e7dde5bfe3";

pub fn detect_platform() -> bool {
    Path::new("/sys/devices/platform/sev-guest").exists()
}

#[derive(Serialize, Deserialize)]
struct SnpEvidence {
    attestation_report: AttestationReport,
    cert_chain: Option<Vec<CertTableEntry>>,
    /// Base64-encoded SVSM vTPM manifest (manifest version 0 is the EK
    /// TPMT_PUBLIC). The VMPL0 report binds SHA-512(nonce || manifest).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    svsm_manifest: Option<String>,
}

#[derive(Debug, Default)]
pub struct SnpAttester {}

#[async_trait::async_trait]
impl Attester for SnpAttester {
    async fn get_evidence(&self, mut report_data: Vec<u8>) -> Result<TeeEvidence> {
        if report_data.len() > 64 {
            bail!("SNP Attester: Report data must be no more than 64 bytes");
        }

        report_data.resize(64, 0);

        #[cfg(feature = "tsm-report")]
        if let std::result::Result::Ok(tsm) = TsmReportPath::new(TsmReportProvider::Sev) {
            if tsm.supports_svsm_attestation() {
                let report_bytes = tsm
                    .attestation_report(TsmReportData::SevSvsm {
                        inblob: report_data,
                        service_guid: SVSM_VTPM_SERVICE_GUID.to_string(),
                        manifest_version: 0,
                    })
                    .context("Failed to get VMPL0 SNP report from SVSM")?;
                let attestation_report: AttestationReport = bincode::deserialize(&report_bytes)
                    .context("Failed to parse the SNP report returned by SVSM")?;

                let manifest = tsm
                    .manifest_data()
                    .context("Failed to read the SVSM vTPM manifest")?;
                if manifest.is_empty() {
                    bail!("SVSM returned an empty vTPM manifest");
                }

                let mut cert_bytes = tsm
                    .supplemental_data()
                    .context("Failed to read the SNP certificate table returned by SVSM")?;
                let cert_chain = if cert_bytes.is_empty() {
                    None
                } else {
                    Some(
                        CertTableEntry::vec_bytes_to_cert_table(&mut cert_bytes).context(
                            "Failed to parse the SNP certificate table returned by SVSM",
                        )?,
                    )
                };

                let evidence = SnpEvidence {
                    attestation_report,
                    cert_chain,
                    svsm_manifest: Some(STANDARD.encode(manifest)),
                };

                return serde_json::to_value(evidence)
                    .context("Serialize SVSM-backed SNP evidence failed");
            }
        }

        let mut firmware = Firmware::open()?;
        let data = report_data.as_slice().try_into()?;

        let (report, certs) = firmware
            .get_ext_report(None, Some(data), Some(0))
            .context("Failed to get attestation report")?;

        let evidence = SnpEvidence {
            attestation_report: report,
            cert_chain: certs,
            svsm_manifest: None,
        };

        serde_json::to_value(evidence).context("Serialize SNP evidence failed")
    }

    async fn bind_init_data(&self, init_data_digest: &[u8]) -> Result<InitDataResult> {
        let hostdata = hostdata::get_snp_host_data().context("Get HOSTDATA failed")?;
        let init_data: [u8; 32] = pad(init_data_digest);
        if init_data != hostdata {
            bail!("HOSTDATA does not match.");
        }

        Ok(InitDataResult::Ok)
    }
}
