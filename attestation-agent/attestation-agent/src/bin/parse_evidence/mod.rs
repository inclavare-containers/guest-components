use anyhow::*;

#[cfg(feature = "tpm-attester")]
mod tpm_evidence;

pub fn parse_evidence(tee_type: String, evidence: String) -> Result<String> {
    match tee_type.as_str() {
        #[cfg(feature = "tpm-attester")]
        "tpm" => tpm_evidence::parse_tpm_ev(evidence),
        _ => {
            log::warn!("Not support parse this evidence, print origin evidence");
            Ok(evidence)
        }
    }
}
