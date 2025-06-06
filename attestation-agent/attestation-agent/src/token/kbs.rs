// Copyright (c) 2024 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use crate::config::kbs::KbsConfig;

use super::GetToken;
use anyhow::*;
use async_trait::async_trait;
use kbs_protocol::{evidence_provider::NativeEvidenceProvider, KbsClientBuilder};
use serde::Serialize;

#[derive(Serialize)]
struct Message {
    token: String,
    tee_keypair: String,
}

#[derive(Default)]
pub struct KbsTokenGetter {
    kbs_host_url: String,
    cert: Option<String>,
}

#[async_trait]
impl GetToken for KbsTokenGetter {
    async fn get_token(&self) -> Result<Vec<u8>> {
        let evidence_provider = Box::new(NativeEvidenceProvider::new()?);

        let mut builder =
            KbsClientBuilder::with_evidence_provider(evidence_provider, &self.kbs_host_url);

        if let Some(cert) = &self.cert {
            builder = builder.add_kbs_cert(cert);
        }

        let mut client = builder.build()?;

        let (token, tee_keypair) = client.get_token().await?;
        let message = Message {
            token: token.content,
            tee_keypair: tee_keypair.to_pkcs1_pem()?.to_string(),
        };

        let res = serde_json::to_vec(&message)?;
        Ok(res)
    }
}

impl KbsTokenGetter {
    pub fn new(config: &KbsConfig) -> Self {
        let kbs_host_url = std::env::var("TRUSTEE_URL").unwrap_or_else(|_| config.url.clone());
        Self {
            kbs_host_url,
            cert: config.cert.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_kbs_token_getter() {
        let config = KbsConfig {
            url: "http://127.0.0.1:8080".to_string(),
            cert: None,
        };
        let getter = KbsTokenGetter::new(&config);
        let token = getter.get_token().await;
        assert!(token.is_err());
    }
}
