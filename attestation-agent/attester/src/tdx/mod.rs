// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use self::gpu::{GpuEvidenceCollector, GpuEvidenceList};

use super::tsm_report::*;
use super::{Attester, TeeEvidence};
use crate::utils::{pad, read_eventlog};
use crate::InitDataResult;
use anyhow::*;
use base64::Engine;
use iocuddle::{Group, Ioctl, WriteRead};
use kbs_types::HashAlgorithm;
use report::TdReport;
use scroll::Pread;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

mod report;
mod rtmr;

mod gpu;

const TDX_REPORT_DATA_SIZE: usize = 64;
const TDX_MEASUREMENT_SIZE: usize = 48;

const TDX_RTMR_PATH: &str = "/sys/devices/virtual/misc/tdx_guest/measurements";
const TDX_GUEST_IOCTL: &str = "/dev/tdx_guest";

pub fn detect_platform() -> bool {
    TsmReportPath::new(TsmReportProvider::Tdx).is_ok() || Path::new(TDX_GUEST_IOCTL).exists()
}

fn get_quote_ioctl(report_data: &[u8]) -> Result<Vec<u8>> {
    let tdx_report_data = tdx_attest_rs::tdx_report_data_t {
        // report_data.resize() ensures copying report_data to
        // tdx_attest_rs::tdx_report_data_t cannot panic.
        d: report_data.try_into().unwrap(),
    };

    match tdx_attest_rs::tdx_att_get_quote(Some(&tdx_report_data), None, None, 0) {
        (tdx_attest_rs::tdx_attest_error_t::TDX_ATTEST_SUCCESS, Some(q)) => Ok(q),
        (error_code, _) => Err(anyhow!(
            "TDX DCAP get_quote: failed with error code: {error_code:?}"
        )),
    }
}

fn rtmr_sysfs_path(measurement_dir: &Path, rtmr_index: u64) -> PathBuf {
    measurement_dir.join(format!("rtmr{rtmr_index}:sha384"))
}

fn sysfs_runtime_measurements_available(measurement_dir: &Path) -> bool {
    (0..4).all(|index| rtmr_sysfs_path(measurement_dir, index).is_file())
}

// Return true if the TD environment can extend and read runtime measurements.
fn runtime_measurement_available() -> bool {
    sysfs_runtime_measurements_available(Path::new(TDX_RTMR_PATH))
        || Path::new(TDX_GUEST_IOCTL).exists()
}

fn read_measurement_via_sysfs(path: &Path) -> Result<Vec<u8>> {
    let measurement = std::fs::read(path)
        .with_context(|| format!("TDX Attester: failed to read measurement from {path:?}"))?;
    ensure!(
        measurement.len() == TDX_MEASUREMENT_SIZE,
        "TDX Attester: measurement from {path:?} has invalid size {}, expected {TDX_MEASUREMENT_SIZE}",
        measurement.len()
    );
    Ok(measurement)
}

fn extend_rtmr_via_sysfs(rtmr_index: u64, extend_data: &[u8; TDX_MEASUREMENT_SIZE]) -> Result<()> {
    let path = rtmr_sysfs_path(Path::new(TDX_RTMR_PATH), rtmr_index);
    std::fs::write(&path, extend_data)
        .with_context(|| format!("TDX Attester: failed to extend RTMR via {path:?}"))?;
    log::debug!("TDX extend runtime measurement via sysfs succeeded.");
    Ok(())
}

fn extend_rtmr_via_ioctl(rtmr_index: u64, extend_data: &[u8; TDX_MEASUREMENT_SIZE]) -> Result<()> {
    let event: Vec<u8> = rtmr::TdxRtmrEvent::default()
        .with_extend_data(*extend_data)
        .with_rtmr_index(rtmr_index)
        .into();

    match tdx_attest_rs::tdx_att_extend(&event) {
        tdx_attest_rs::tdx_attest_error_t::TDX_ATTEST_SUCCESS => {
            log::debug!("TDX extend runtime measurement via ioctl succeeded.");
            Ok(())
        }
        error_code => {
            bail!("TDX Attester: Failed to extend RTMR via ioctl. Error code: {error_code:?}")
        }
    }
}

pub const DEFAULT_EVENTLOG_PATH: &str = "/run/attestation-agent/eventlog";

#[derive(Serialize, Deserialize)]
struct TdxEvidence {
    // Base64 encoded TD quote.
    quote: String,

    /// Base64 encoded Eventlog
    /// This might include the
    /// - CCEL: <https://uefi.org/specs/ACPI/6.5/05_ACPI_Software_Programming_Model.html#cc-event-log-acpi-table>
    /// - AAEL in TCG2 encoding: <https://github.com/confidential-containers/trustee/blob/main/kbs/docs/confidential-containers-eventlog.md>
    cc_eventlog: Option<String>,

    // GPU evidence (optional)
    gpu_evidence: Option<GpuEvidenceList>,
}

#[derive(Debug, Default)]
pub struct TdxAttester {}

#[repr(C)]
struct TdxReportReq {
    report_data: [u8; 64],

    d: [u8; 1024],
}

impl Default for TdxReportReq {
    fn default() -> Self {
        Self {
            report_data: [0; 64],
            d: [0; 1024],
        }
    }
}

const TDX: Group = Group::new(b'T');
const TDX_CMD_GET_REPORT0: Ioctl<WriteRead, &TdxReportReq> = unsafe { TDX.write_read(0x1) };

impl TdxAttester {
    fn get_report() -> Result<TdReport> {
        let mut report = TdxReportReq::default();
        let mut fd =
            std::fs::File::open(TDX_GUEST_IOCTL).context("Open TD report ioctl() failed")?;

        TDX_CMD_GET_REPORT0
            .ioctl(&mut fd, &mut report)
            .context("Get TD report ioctl() failed")?;

        let td_report = report
            .d
            .pread::<report::TdReport>(0)
            .context("Parse TD report failed")?;

        Ok(td_report)
    }
}

#[async_trait::async_trait]
impl Attester for TdxAttester {
    async fn get_evidence(&self, mut report_data: Vec<u8>) -> Result<TeeEvidence> {
        if report_data.len() > TDX_REPORT_DATA_SIZE {
            bail!("TDX Attester: Report data must be no more than {TDX_REPORT_DATA_SIZE} bytes");
        }

        report_data.resize(TDX_REPORT_DATA_SIZE, 0);

        let quote_bytes = TsmReportPath::new(TsmReportProvider::Tdx).map_or_else(
            |notsm| {
                get_quote_ioctl(&report_data)
                    .context(format!("TDX Attester: quote generation using ioctl() fallback failed after a TSM report error ({notsm})"))
            },
            |tsm| {
                tsm.attestation_report(TsmReportData::Tdx(report_data.clone()))
                    .context("TDX Attester: quote generation using TSM reports failed")
            },
        )?;

        let engine = base64::engine::general_purpose::STANDARD;
        let quote = engine.encode(quote_bytes);

        let cc_eventlog = read_eventlog().await?;

        // Try to collect GPU evidence
        #[allow(unused_assignments)]
        let mut gpu_evidence: Option<GpuEvidenceList> = None;
        if let Result::Ok(gpu_collector) = GpuEvidenceCollector::new() {
            match gpu_collector.has_gpu_devices() {
                true => match gpu_collector.collect_gpu_evidence(&report_data) {
                    Result::Ok(gpu_evidence_list) => {
                        log::info!(
                            "GPU evidence collected successfully, found {} GPU devices",
                            gpu_evidence_list.gpu_count()
                        );
                        gpu_evidence = Some(gpu_evidence_list);
                    }
                    Result::Err(e) => {
                        log::warn!("Failed to collect GPU evidence: {e}");
                        gpu_evidence = None;
                    }
                },
                false => {
                    log::info!("No GPU devices found, skipping GPU evidence collection");
                    gpu_evidence = None;
                }
            }
        } else {
            log::warn!(
                "Failed to initialize GPU evidence collector, skipping GPU evidence collection"
            );
            gpu_evidence = None;
        }

        let evidence = TdxEvidence {
            cc_eventlog,
            quote,
            gpu_evidence,
        };

        serde_json::to_value(evidence).context("Serialize TDX evidence failed")
    }

    fn supports_runtime_measurement(&self) -> bool {
        runtime_measurement_available()
    }

    async fn extend_runtime_measurement(
        &self,
        event_digest: Vec<u8>,
        register_index: u64,
    ) -> Result<()> {
        if !runtime_measurement_available() {
            bail!("TDX Attester: runtime measurement extend is not available");
        }

        let ccmr_index = self.pcr_to_ccmr(register_index);
        let rtmr_index = ccmr_index - 1;

        let extend_data: [u8; TDX_MEASUREMENT_SIZE] = pad(&event_digest);

        log::debug!(
            "TDX Attester: extend RTMR{rtmr_index}: {}",
            hex::encode(extend_data)
        );

        if rtmr_sysfs_path(Path::new(TDX_RTMR_PATH), rtmr_index).is_file() {
            extend_rtmr_via_sysfs(rtmr_index, &extend_data)?;
        } else {
            extend_rtmr_via_ioctl(rtmr_index, &extend_data)?;
        }

        Ok(())
    }

    async fn bind_init_data(&self, init_data_digest: &[u8]) -> Result<InitDataResult> {
        let mrconfigid_path = Path::new(TDX_RTMR_PATH).join("mrconfigid");
        let mrconfigid = if mrconfigid_path.is_file() {
            read_measurement_via_sysfs(&mrconfigid_path)?
        } else {
            Self::get_report()?.tdinfo.mrconfigid.to_vec()
        };
        let init_data: [u8; TDX_MEASUREMENT_SIZE] = pad(init_data_digest);
        if init_data.as_slice() != mrconfigid.as_slice() {
            bail!("Init data does not match!");
        }

        Ok(InitDataResult::Ok)
    }

    async fn get_runtime_measurement(&self, pcr_index: u64) -> Result<Vec<u8>> {
        let ccmr = self.pcr_to_ccmr(pcr_index) as usize;
        let rtmr_index = ccmr - 1;
        let rtmr_path = rtmr_sysfs_path(Path::new(TDX_RTMR_PATH), rtmr_index as u64);

        if rtmr_path.is_file() {
            return read_measurement_via_sysfs(&rtmr_path);
        }

        Ok(Self::get_report()?.get_rtmr(rtmr_index))
    }

    fn pcr_to_ccmr(&self, pcr_index: u64) -> u64 {
        // The match follows https://github.com/confidential-containers/td-shim/blob/main/doc/tdshim_spec.md#td-event-log
        // and https://uefi.org/specs/UEFI/2.11/38_Confidential_Computing.html#intel-trust-domain-extension
        match pcr_index {
            1 | 7 => 1,
            2..=6 => 2,
            8..=15 => 3,
            _ => 4,
        }
    }

    fn ccel_hash_algorithm(&self) -> HashAlgorithm {
        HashAlgorithm::Sha384
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sysfs_runtime_measurements_available() {
        let dir = tempfile::tempdir().unwrap();
        assert!(!sysfs_runtime_measurements_available(dir.path()));

        for index in 0..4 {
            std::fs::write(rtmr_sysfs_path(dir.path(), index), [0_u8; 48]).unwrap();
        }
        assert!(sysfs_runtime_measurements_available(dir.path()));

        std::fs::remove_file(rtmr_sysfs_path(dir.path(), 2)).unwrap();
        assert!(!sysfs_runtime_measurements_available(dir.path()));
    }

    #[test]
    fn test_read_measurement_via_sysfs_validates_size() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("measurement");
        let expected = vec![0x5a; TDX_MEASUREMENT_SIZE];

        std::fs::write(&path, &expected).unwrap();
        assert_eq!(read_measurement_via_sysfs(&path).unwrap(), expected);

        std::fs::write(&path, [0_u8; TDX_MEASUREMENT_SIZE - 1]).unwrap();
        assert!(read_measurement_via_sysfs(&path).is_err());
    }

    #[ignore]
    #[tokio::test]
    async fn test_tdx_get_evidence() {
        let attester = TdxAttester::default();
        let report_data: Vec<u8> = vec![0; 48];

        let evidence = attester.get_evidence(report_data).await;
        assert!(evidence.is_ok());
    }
    #[ignore]
    #[tokio::test]
    async fn test_tdx_get_report() {
        assert!(TdxAttester::get_report().is_ok());
    }
}
