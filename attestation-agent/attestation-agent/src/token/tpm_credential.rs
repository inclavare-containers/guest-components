// Copyright (c) 2024 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use super::GetToken;
use crate::config::kbs::KbsConfig;
use anyhow::*;
use async_trait::async_trait;
use attester::tpm::utils;
use reqwest::Client;
use rsa::pkcs8::EncodePublicKey;
use serde::Serialize;
use std::fs;
use std::path::Path;

const DEFAULT_AK_CERT_PATH: &str = "/opt/tpm-credential/ak.cert";

#[derive(Serialize)]
struct TpmCredential {
    ak_cert_chain: String,
}

#[derive(Default)]
pub struct TpmCredentialGetter {
    kbs_host_url: String,
    cert: Option<String>,
}

#[async_trait]
impl GetToken for TpmCredentialGetter {
    async fn get_token(&self) -> Result<Vec<u8>> {
        // Generate AK
        let _ = utils::generate_rsa_ak()?;

        // Get AK public key
        let ak_pub = utils::get_ak_pub()?;
        let ak_pubkey = ak_pub.to_public_key_pem(rsa::pkcs8::LineEnding::LF)?;

        // Try to get EK certificate
        let ek_cert = utils::dump_ek_cert_pem().ok();

        // Construct request URL and parameters
        let url = format!("{}/kbs/v0/tpm_pca/ak_credential", self.kbs_host_url);
        let mut query = format!("ak_pubkey={}", urlencoding::encode(&ak_pubkey));

        // If EK certificate is successfully obtained, add it to query parameters
        if let Some(ek_cert) = ek_cert {
            query = format!("{}&ek_cert={}", query, urlencoding::encode(&ek_cert));
        }

        // Create HTTP client
        let client = if let Some(cert) = &self.cert {
            let cert = reqwest::Certificate::from_pem(cert.as_bytes())?;
            Client::builder().add_root_certificate(cert).build()?
        } else {
            Client::new()
        };

        // Send request
        let response = client.get(&url).query(&query).send().await?;

        if !response.status().is_success() {
            bail!("Failed to get AK credential: {}", response.status());
        }

        let ak_credential = response.text().await?;

        // Save certificate to file
        let cert_path = Path::new(DEFAULT_AK_CERT_PATH);
        if let Some(parent) = cert_path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(cert_path, &ak_credential)?;

        let credential = TpmCredential {
            ak_cert_chain: ak_credential,
        };

        let res = serde_json::to_vec(&credential)?;
        Ok(res)
    }
}

impl TpmCredentialGetter {
    pub fn new(config: &KbsConfig) -> Self {
        Self {
            kbs_host_url: config.url.clone(),
            cert: config.cert.clone(),
        }
    }
}
