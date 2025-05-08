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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_evidence() {
        let tee_type = "others".to_string();
        let evidence = "evidence".to_string();
        let result = parse_evidence(tee_type, evidence);
        assert!(result.is_ok());
    }
}
