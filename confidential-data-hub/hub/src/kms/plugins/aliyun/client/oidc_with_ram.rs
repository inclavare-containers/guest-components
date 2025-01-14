// Copyright (c) 2024 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! # Aliyun OIDC with RAM KMS plugin
//!
//! This plugin uses OIDC to authenticate with RAM and then use the STS token to access KMS.

use std::collections::HashMap;

use anyhow::{Context, Result};
use reqwest::header::HeaderMap;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::kms::{Annotations, ProviderSettings};

use super::sts_token_client::{credential::StsCredential, StsTokenClient};

/// Default RoleSessionName to request for RAM
pub const ROLE_SESSION_NAME: &str = "zero-trust-session";

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct OidcTokenInfo {
    pub subject: String,
    pub issuer: String,
    pub client_ids: String,
    pub expiration_time: String,
    pub issuance_time: String,
    pub verification_info: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct RoleUser {
    pub assumed_role_id: String,
    pub arn: String,
}

#[derive(Deserialize)]
pub struct AssumeRoleWithOidcResponse {
    #[serde(rename = "RequestId")]
    pub request_id: String,

    #[serde(rename = "OIDCTokenInfo")]
    pub oidc_token_info: OidcTokenInfo,

    #[serde(rename = "AssumedRoleUser")]
    pub assumed_role_user: RoleUser,

    #[serde(rename = "Credentials")]
    pub credentials: StsCredential,
}

#[derive(Deserialize, Serialize)]
pub struct OidcRamProviderSettings {
    id_token: String,
    oidc_provider_arn: String,
    role_arn: String,
    region_id: String,
}

#[derive(Clone, Debug)]
pub struct OidcRamClient {
    client: reqwest::Client,
    id_token: String,
    oidc_provider_arn: String,
    role_arn: String,
    region_id: String,
}

impl OidcRamClient {
    pub fn from_provider_settings(provider_settings: &ProviderSettings) -> Result<Self> {
        let provider_settings: OidcRamProviderSettings =
            serde_json::from_value(Value::Object(provider_settings.clone()))
                .context("parse aliyun oidc ram provider settings failed: {e}")?;
        Ok(Self {
            client: reqwest::Client::new(),
            oidc_provider_arn: provider_settings.oidc_provider_arn,
            role_arn: provider_settings.role_arn,
            region_id: provider_settings.region_id,
            id_token: provider_settings.id_token,
        })
    }

    pub fn export_provider_settings(&self) -> Result<ProviderSettings> {
        let provider_settings = OidcRamProviderSettings {
            id_token: self.id_token.clone(),
            oidc_provider_arn: self.oidc_provider_arn.clone(),
            role_arn: self.role_arn.clone(),
            region_id: self.region_id.clone(),
        };

        let provider_settings = serde_json::to_value(&provider_settings)
            .context("serialize ProviderSettings failed: {e}")?
            .as_object()
            .expect("must be an object")
            .to_owned();

        Ok(provider_settings)
    }

    async fn get_sts(&self, id_token: String) -> anyhow::Result<StsCredential> {
        let host = match &self.region_id[..] {
            "cn-hangzhou-finance" | "cn-shenzhen-finance-1" => "sts.aliyuncs.com".into(),
            others => format!("sts.{others}.aliyuncs.com"),
        };

        let now = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();

        let query = [
            ("Action", "AssumeRoleWithOIDC".into()),
            ("Format", "json".into()),
            ("RoleArn", self.role_arn.clone()),
            ("OIDCProviderArn", self.oidc_provider_arn.clone()),
            ("OIDCToken", id_token),
            ("RoleSessionName", ROLE_SESSION_NAME.into()),
            ("Timestamp", now),
        ];

        let headers: HashMap<String, String> = [
            (
                "user-agent",
                concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION")),
            ),
            ("x-acs-version", "2015-04-01"),
            ("x-acs-action", "AssumeRoleWithOIDC"),
            ("host", &host),
            ("accept", "application/json"),
            ("content-type", "application/x-www-form-urlencoded"),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();

        let url = format!("https://{host}/");
        let header_map = HeaderMap::try_from(&headers)?;
        let response: AssumeRoleWithOidcResponse = self
            .client
            .post(url)
            .headers(header_map)
            .query(&query)
            .send()
            .await
            .context("failed to assume Role with OIDC")?
            .json()
            .await
            .context("failed to call AssumeRoleWithOIDC")?;

        Ok(response.credentials)
    }

    pub async fn get_secret(&self, name: &str, annotations: &Annotations) -> Result<Vec<u8>> {
        let sts = self
            .get_sts(self.id_token.clone())
            .await
            .context("failed to get STS credential")?;
        let endpoint = format!("kms.{}.aliyuncs.com", self.region_id);
        let client = StsTokenClient::from_sts_token(sts, endpoint, self.region_id.clone())?;
        let secret = client.get_secret(name, annotations).await?;

        Ok(secret)
    }
}
