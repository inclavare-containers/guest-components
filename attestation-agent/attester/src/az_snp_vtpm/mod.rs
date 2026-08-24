// Copyright (c) 2023 Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use super::{Attester, InitDataResult, TeeEvidence};
use anyhow::{bail, Context, Result};
use az_snp_vtpm::{imds, is_snp_cvm, vtpm};
use kbs_types::HashAlgorithm;
use log::{debug, info};
use serde::{Deserialize, Serialize};

pub fn detect_platform() -> bool {
    match is_snp_cvm() {
        Ok(is_snp) => is_snp,
        Err(err) => {
            debug!("Failed to retrieve Azure HCL data from vTPM: {err}");
            false
        }
    }
}

#[derive(Debug, Default)]
pub struct AzSnpVtpmAttester;

#[derive(Serialize, Deserialize)]
struct Evidence {
    quote: vtpm::Quote,
    report: Vec<u8>,
    vcek: String,
}

#[async_trait::async_trait]
impl Attester for AzSnpVtpmAttester {
    async fn get_evidence(&self, report_data: Vec<u8>) -> anyhow::Result<TeeEvidence> {
        let report = vtpm::get_report()?;
        let quote = vtpm::get_quote(&report_data)?;
        let certs = imds::get_certs()?;
        let vcek = certs.vcek;

        let evidence = Evidence {
            quote,
            report,
            vcek,
        };

        Ok(serde_json::to_value(evidence)?)
    }

    fn supports_runtime_measurement(&self) -> bool {
        true
    }

    async fn bind_init_data(&self, init_data_digest: &[u8]) -> anyhow::Result<InitDataResult> {
        utils::extend_pcr(init_data_digest, utils::INIT_DATA_PCR)?;
        Ok(InitDataResult::Ok)
    }

    async fn extend_runtime_measurement(
        &self,
        event_digest: Vec<u8>,
        register_index: u64,
    ) -> Result<()> {
        utils::extend_pcr(&event_digest, register_index as u8)?;
        Ok(())
    }

    async fn get_runtime_measurement(&self, pcr_index: u64) -> Result<Vec<u8>> {
        utils::read_pcr(pcr_index)
    }

    fn pcr_to_ccmr(&self, pcr_index: u64) -> u64 {
        pcr_index
    }

    fn ccel_hash_algorithm(&self) -> HashAlgorithm {
        HashAlgorithm::Sha256
    }
}

pub(crate) mod utils {
    use super::*;

    pub const INIT_DATA_PCR: u8 = 8;

    pub fn extend_pcr(digest: &[u8], pcr: u8) -> Result<()> {
        let sha256_digest: [u8; 32] = digest.try_into().context("expected sha256 digest")?;
        if pcr > 23 {
            bail!("Invalid PCR index: {pcr}");
        }
        info!("Extending PCR {} with {}", pcr, hex::encode(sha256_digest));
        vtpm::extend_pcr(pcr, &sha256_digest)?;

        Ok(())
    }

    /// Read a SHA-256 PCR through the quote interface exposed by the current
    /// `az-cvm-vtpm` dependency. The quote contains all 24 PCR values in index
    /// order, so this also works on releases that do not expose a direct PCR
    /// read API.
    pub fn read_pcr(pcr_index: u64) -> Result<Vec<u8>> {
        let index = usize::try_from(pcr_index).context("PCR index does not fit usize")?;
        if index > 23 {
            bail!("Invalid PCR index: {pcr_index}");
        }

        let quote = vtpm::get_quote(&[]).context("quote vTPM while reading PCR")?;
        let digest = quote
            .pcrs_sha256()
            .nth(index)
            .map(|digest| digest.to_vec())
            .context("vTPM quote did not contain the requested PCR")?;
        Ok(digest)
    }
}
