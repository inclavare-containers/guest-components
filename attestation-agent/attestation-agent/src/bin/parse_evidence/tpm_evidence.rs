// Copyright (c) 2025 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::*;
use attester::tpm::TpmEvidence;
use base64::Engine;

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

    output.push_str("\n==================\nTPM EK Certificate\n==================\n");
    output.push_str(&ev.ek_cert);

    output.push_str("\n===================\nPCR Register Values\n===================\n");
    output.push_str("SHA1:\n");

    for (pcr_index, pcr_value) in ev
        .pcrs
        .get("SHA1")
        .expect("Cannot find SHA1 pcrs in evidence")
        .iter()
        .enumerate()
    {
        output.push_str(&format!("\t{pcr_index}: {pcr_value}\n"));
    }

    output.push_str("SHA256:\n");

    for (pcr_index, pcr_value) in ev
        .pcrs
        .get("SHA256")
        .expect("Cannot find SHA256 pcrs in evidence")
        .iter()
        .enumerate()
    {
        output.push_str(&format!("\t{pcr_index}: {pcr_value}\n"));
    }

    output.push_str("\n================================\nAA Runtime Measurement Eventlogs\n================================\n");

    let aael = ev
        .aa_eventlog
        .ok_or_else(|| anyhow!("No AA Eventlog in evidence"))?;
    let aa_eventlog: Vec<&str> = aael.split('\n').collect();

    for event in aa_eventlog.iter() {
        let event_split: Vec<&str> = event.splitn(3, ' ').collect();

        if event_split[0] == "INIT" {
            output.push_str(&format!(
                "\nEvent Entry\n\tOperation: {}\n\tContent: {}\n\t",
                event_split[0], event_split[1]
            ));
            continue;
        } else if event_split[0].to_string().is_empty() {
            break;
        }

        if event_split.len() != 3 {
            bail!("Illegal AA eventlog format");
        }

        output.push_str(&format!(
            "\nEvent Entry\n\tDomain: {}\n\tOperation: {}\n\tContent: {}\n\t",
            event_split[0], event_split[1], event_split[2]
        ));
    }

    Ok(output)
}
