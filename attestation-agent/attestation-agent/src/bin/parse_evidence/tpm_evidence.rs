// Copyright (c) 2025 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::*;
use attester::types::TpmEvidence;
use base64::Engine;
use eventlog::CcEventLog;

pub fn parse_tpm_ev(evidence: String) -> Result<String> {
    let ev = serde_json::from_str::<TpmEvidence>(&evidence)?;

    let mut output = String::new();
    output.push_str("\n==================\nBoot TCG Eventlogs\n==================\n");

    let eventlog_bytes = base64::engine::general_purpose::STANDARD.decode(
        ev.eventlog
            .ok_or_else(|| anyhow!("No Eventlog in evidence"))?,
    )?;

    if let Result::Ok(eventlog) = eventlog_rs::Eventlog::try_from(eventlog_bytes.clone()) {
        output.push_str(&format!("{eventlog}"));
    } else {
        let bios_eventlog = eventlog_rs::BiosEventlog::try_from(eventlog_bytes.clone())
            .expect("Parse Eventlog Failed");
        output.push_str(&format!("{bios_eventlog}"));
    }

    if let Some(ek_cert) = ev.ek_cert {
        output.push_str("\n==================\nTPM EK Certificate\n==================\n");
        output.push_str(&ek_cert);
    }

    output.push_str("\n===================\nPCR Register Values\n===================\n");
    output.push_str("SHA1:\n");

    if let Some(sha1_pcrs) = ev.quote.get("SHA1") {
        for (pcr_index, pcr_value) in sha1_pcrs.pcrs.iter().enumerate() {
            output.push_str(&format!("\t{pcr_index}: {pcr_value}\n"));
        }
    } else {
        output.push_str("SHA1 PCRs not found in evidence.\n");
    }

    output.push_str("SHA256:\n");

    if let Some(sha256_pcrs) = ev.quote.get("SHA256") {
        for (pcr_index, pcr_value) in sha256_pcrs.pcrs.iter().enumerate() {
            output.push_str(&format!("\t{pcr_index}: {pcr_value}\n"));
        }
    } else {
        output.push_str("SHA256 PCRs not found in evidence.\n");
    }

    output.push_str("\n================================\nAA Runtime Measurement Eventlogs\n================================\n");

    let aael = ev
        .aa_eventlog
        .ok_or_else(|| anyhow!("No AA Eventlog in evidence"))?;
    let aa_ccel_data = base64::engine::general_purpose::STANDARD.decode(aael)?;
    let aa_ccel = CcEventLog::try_from(aa_ccel_data)?;
    let aa_ccel_string = serde_json::to_string_pretty(&aa_ccel.clone().log)?;
    output.push_str(&aa_ccel_string);

    Ok(output)
}
