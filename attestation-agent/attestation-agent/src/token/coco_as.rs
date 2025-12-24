// Copyright (c) 2024 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use crate::config::coco_as::CoCoASConfig;

use anyhow::*;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

#[derive(Default)]
pub struct CoCoASTokenGetter {
    as_uri: String,
}

impl CoCoASTokenGetter {
    pub async fn get_token(&self, additional_data: Option<&str>) -> Result<Vec<u8>> {
        let primary_tee = attester::detect_tee_type();
        let attester = attester::BoxedAttester::try_from(primary_tee)?;
        let evidence = attester.get_evidence(vec![]).await?;

        let tee_string = serde_json::to_string(&primary_tee)?
            .trim_end_matches('"')
            .trim_start_matches('"')
            .to_string();

        let request_body = serde_json::json!({
            "verification_requests": [{
                "tee": tee_string,
                "evidence": URL_SAFE_NO_PAD.encode(serde_json::to_string(&evidence)?.as_bytes()),
                "additional_data": additional_data,
            }],
            "policy_ids": std::env::var("COCO_AS_POLICY_ID")
                .unwrap_or_default()
                .split(',')
                .filter(|s| !s.is_empty())
                .map(|s| s.trim().to_string())
                .collect::<Vec<String>>(),
        });

        let client = reqwest::Client::new();
        let attest_endpoint = format!("{}/attestation", self.as_uri);
        let mut request_builder = client
            .post(attest_endpoint)
            .header("Content-Type", "application/json");

        // Add AAInstanceInfo header if the environment variable is set
        if let Result::Ok(aa_instance_info) = std::env::var("AA_INSTANCE_INFO") {
            request_builder = request_builder.header("AAInstanceInfo", aa_instance_info);
        }

        let res = request_builder.json(&request_body).send().await?;

        match res.status() {
            reqwest::StatusCode::OK => {
                let token = res.text().await?;
                Ok(token.as_bytes().to_vec())
            }
            _ => {
                bail!(
                    "Remote Attestation Failed, AS Response: {:?}",
                    res.text().await?
                );
            }
        }
    }
}

impl CoCoASTokenGetter {
    pub fn new(config: &CoCoASConfig) -> Self {
        let as_uri = match std::env::var("TRUSTEE_URL") {
            Result::Err(_) => config.url.clone(),
            // This URL points to the trustee gateway,
            // We need to add the /attestation-service path to the URL.
            // If we want to access the restful attestation service directly,
            // now only support via config file.
            Result::Ok(env_url) => format!("{}/attestation-service", env_url),
        };
        Self { as_uri }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_coco_as_token_getter() {
        let config = CoCoASConfig {
            url: "http://localhost:8080".to_string(),
        };
        let getter = CoCoASTokenGetter::new(&config);
        let result = getter.get_token(None).await;
        assert!(result.is_err());
    }
}
