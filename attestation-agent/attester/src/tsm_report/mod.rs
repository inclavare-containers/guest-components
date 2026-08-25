// Copyright (c) 2024 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use std::cell::Cell;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use strum::EnumString;
use tempfile::tempdir_in;
use thiserror::Error;

const TSM_REPORT_PATH: &str = "/sys/kernel/config/tsm/report";

#[derive(Error, Debug)]
pub enum TsmReportError {
    #[error("Failed to access TSM Report path")]
    NoTsmReports,
    #[error("Failed to create TSM Report path instance: {0}")]
    Open(#[from] std::io::Error),
    #[error("Failed to access TSM Report attribute: {0} ({1})")]
    Access(&'static str, #[source] std::io::Error),
    #[error("Failed to parse TSM Report attribute 'generation': {0}")]
    Parse(#[source] std::num::ParseIntError),
    #[error("Failed to open TSM Report path: missing provider {0:?} (provider={1:?})")]
    MissingProvider(TsmReportProvider, TsmReportProvider),
    #[error("Failed to open TSM Report path: unknown provider ({0})")]
    UnknownProvider(#[from] strum::ParseError),
    #[error("Failed to generate TSM Report: missing inblob (len=0)")]
    InblobLen,
    #[error(
        "Failed to generate TSM Report: concurrent attribute write (generation={0}, expected {1})"
    )]
    GenerationConflict(u32, u32),
}

#[derive(PartialEq, Debug, EnumString)]
pub enum TsmReportProvider {
    #[strum(serialize = "arm_cca_guest\n")]
    Cca,
    #[strum(serialize = "tdx_guest\n")]
    Tdx,
    #[strum(serialize = "sev_guest\n")]
    Sev,
}

pub enum TsmReportData {
    Cca(Vec<u8>),
    Tdx(Vec<u8>),
    Sev(u8, Vec<u8>),
    /// Request a VMPL0 report from an SVSM and bind the selected service
    /// manifest into REPORT_DATA.
    SevSvsm {
        inblob: Vec<u8>,
        service_guid: String,
        manifest_version: u32,
    },
}

/// TsmReportPath instance represents a unique path on ConfigFS
/// provided by the TSM_REPORT attestation ABI. Currently, each
/// instance is a one-shot attestation request and the path is
/// automatically removed when the instance goes out of scope.
pub struct TsmReportPath {
    path: PathBuf,
    expected_generation: Cell<u32>,
}

impl Drop for TsmReportPath {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir(self.path.as_path())
            .map_err(|e| log::error!("Failed to remove TSM Report directory: {}", e));
    }
}

impl TsmReportPath {
    pub fn new(wanted: TsmReportProvider) -> Result<Self, TsmReportError> {
        if !Path::new(TSM_REPORT_PATH).exists() {
            return Err(TsmReportError::NoTsmReports);
        }

        let p = tempdir_in(TSM_REPORT_PATH).map_err(TsmReportError::Open)?;

        // Remove the Drop set by tempdir_in() since it errors on ConfigFS
        // and leaks the created path. We implement our own Drop that removes the
        // path (rmdir way) when TsmReportPath instance goes out of scope.
        let path = p.keep();

        if let Err(e) = check_tsm_report_provider(path.as_path(), wanted) {
            let _ = std::fs::remove_dir(path.as_path());
            return Err(e);
        }

        Ok(Self {
            path,
            expected_generation: Cell::new(0),
        })
    }

    fn write_attribute(
        &self,
        name: &'static str,
        value: impl AsRef<[u8]>,
    ) -> Result<(), TsmReportError> {
        std::fs::write(self.path.join(name), value).map_err(|e| TsmReportError::Access(name, e))?;
        self.expected_generation
            .set(self.expected_generation.get() + 1);
        Ok(())
    }

    /// Whether this TSM provider exposes the SVSM service attestation ABI.
    pub fn supports_svsm_attestation(&self) -> bool {
        self.path.join("service_provider").exists()
            && self.path.join("service_guid").exists()
            && self.path.join("manifestblob").exists()
    }

    pub fn attestation_report(
        &self,
        provider_data: TsmReportData,
    ) -> Result<Vec<u8>, TsmReportError> {
        let report_path = self.path.as_path();

        let report_data = match provider_data {
            TsmReportData::Cca(inblob) => inblob,
            TsmReportData::Tdx(inblob) => inblob,
            TsmReportData::Sev(privlevel, inblob) => {
                // TODO: untested
                self.write_attribute("privlevel", privlevel.to_string())?;
                inblob
            }
            TsmReportData::SevSvsm {
                inblob,
                service_guid,
                manifest_version,
            } => {
                self.write_attribute("service_provider", "svsm")?;
                self.write_attribute("service_guid", service_guid)?;
                self.write_attribute("service_manifest_version", manifest_version.to_string())?;
                inblob
            }
        };

        if report_data.is_empty() {
            return Err(TsmReportError::InblobLen);
        }

        self.write_attribute("inblob", report_data)?;

        let q = std::fs::read(report_path.join("outblob"))
            .map_err(|e| TsmReportError::Access("outblob", e))?;

        check_inblob_write_race(report_path, self.expected_generation.get())?;

        Ok(q)
    }
    pub fn supplemental_data(&self) -> Result<Vec<u8>, TsmReportError> {
        let report_path = self.path.as_path();

        let aux = std::fs::read(report_path.join("auxblob"))
            .map_err(|e| TsmReportError::Access("auxblob", e))?;

        check_inblob_write_race(report_path, self.expected_generation.get())?;

        Ok(aux)
    }

    pub fn manifest_data(&self) -> Result<Vec<u8>, TsmReportError> {
        let report_path = self.path.as_path();
        let manifest = std::fs::read(report_path.join("manifestblob"))
            .map_err(|e| TsmReportError::Access("manifestblob", e))?;

        check_inblob_write_race(report_path, self.expected_generation.get())?;

        Ok(manifest)
    }
}

/// check_inblob_write_race checks that the returned outblob/auxblob
/// matches the quote generation request originally triggered when
/// inblob was written by the TsmReportPath instance. It prevents
/// the race condition that someone else could use the same temporary
/// directory to generate a quote.
fn check_inblob_write_race(
    report_path: &Path,
    expected_generation: u32,
) -> Result<(), TsmReportError> {
    let g = std::fs::read_to_string(report_path.join("generation"))
        .map_err(|e| TsmReportError::Access("generation", e))?;

    let generation = g
        .trim_matches('\n')
        .to_string()
        .parse::<u32>()
        .map_err(TsmReportError::Parse)?;

    if generation != expected_generation {
        return Err(TsmReportError::GenerationConflict(
            generation,
            expected_generation,
        ));
    }

    Ok(())
}

/// check_tsm_report_provider checks that the TEE is
/// the requested TsmReportProvider.
fn check_tsm_report_provider(
    report_path: &Path,
    wanted: TsmReportProvider,
) -> Result<(), TsmReportError> {
    let report_provider = std::fs::read_to_string(report_path.join("provider"))
        .map_err(|e| TsmReportError::Access("provider", e))?;

    match TsmReportProvider::from_str(&report_provider) {
        Ok(provider) => {
            if provider == wanted {
                Ok(())
            } else {
                Err(TsmReportError::MissingProvider(wanted, provider))
            }
        }
        Err(e) => Err(TsmReportError::UnknownProvider(e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::*;

    #[rstest]
    #[case("provider", "tdx_guest\n", false)]
    #[case("provider", "sev_guest\n", true)]
    #[case("provider", "foo_guest\n", true)]
    #[case("generation", "1\n", false)]
    #[case("generation", "2\n", true)]
    #[case("generation", "parseerror\n", true)]
    fn test_tsm_report(#[case] file: &str, #[case] file_data: &str, #[case] expect_error: bool) {
        let tsm_dir = tempfile::tempdir().unwrap();

        std::fs::write(tsm_dir.path().join(file), file_data).unwrap();

        match file {
            "provider" => assert_eq!(
                expect_error,
                check_tsm_report_provider(tsm_dir.path(), TsmReportProvider::Tdx).is_err()
            ),
            "generation" => assert_eq!(
                expect_error,
                check_inblob_write_race(tsm_dir.path(), 1).is_err(),
            ),
            _ => unimplemented!(),
        }
    }
}
