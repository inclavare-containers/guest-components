// Copyright (c) 2026 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0

//! ECS IMDSv2 credentials and request-scoped STS decoding. Only IMDS credentials
//! enter the shared refresh cache; caller-provided credentials never do.
use std::time::Duration;

use anyhow::{anyhow, ensure, Context, Result};
use base64::{
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD},
    Engine,
};
use chrono::{DateTime, Utc};
use log::warn;
use rand::Rng;
use serde::Deserialize;
use tokio::sync::Mutex;

use super::sts_token_client::credential::StsCredential;

const IMDS: &str = "http://100.100.100.200/latest";
const MAX_ENCODED_STS: usize = 16 * 1024;

pub(super) struct SessionClient {
    client: reqwest::Client,
    endpoint: String,
    role: Option<String>,
    cached: Mutex<Option<Session>>,
}

struct Session {
    credential: StsCredential,
    expires: DateTime<Utc>,
    refresh_at: DateTime<Utc>,
}

#[derive(Deserialize)]
struct SessionResponse {
    #[serde(rename = "Code")]
    code: String,
    #[serde(rename = "Expiration")]
    expiration: String,
    #[serde(flatten)]
    credential: StsCredential,
}

#[derive(Deserialize)]
struct RequestCredential {
    #[serde(flatten)]
    credential: StsCredential,
    #[serde(rename = "Expiration")]
    expiration: Option<String>,
    #[serde(rename = "Code")]
    code: Option<String>,
}

/// Decode complete caller-provided STS material without retaining a parse error
/// that could echo secret field values. Expiration is checked when supplied;
/// the KMS always validates the actual STS session, even without this field.
pub(super) fn parse_request_sts(encoded: &str) -> Result<StsCredential> {
    ensure!(
        !encoded.is_empty() && encoded.len() <= MAX_ENCODED_STS,
        "sts must be nonempty Base64, at most 16 KiB"
    );
    let bytes = [STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD]
        .iter()
        .find_map(|engine| engine.decode(encoded).ok())
        .context("sts is not valid Base64; URL-encode standard Base64 query values")?;
    let text =
        String::from_utf8(bytes).map_err(|_| anyhow!("sts must encode UTF-8 STS credentials"))?;
    let credential = if text.trim_start().starts_with('{') {
        let input: RequestCredential = serde_json::from_str(&text).map_err(|_| {
            anyhow!("sts JSON must contain AccessKeyId, AccessKeySecret and SecurityToken strings")
        })?;
        ensure!(
            input.code.as_deref().is_none_or(|code| code == "Success"),
            "sts JSON contains an unsuccessful credential response"
        );
        if let Some(expiration) = input.expiration {
            let expires = DateTime::parse_from_rfc3339(&expiration)
                .map_err(|_| anyhow!("invalid STS Expiration"))?;
            ensure!(expires > Utc::now(), "request STS credentials have expired");
        }
        input.credential
    } else {
        let mut sections = text.splitn(3, ':');
        StsCredential {
            ak: sections.next().unwrap_or_default().to_owned(),
            sk: sections.next().unwrap_or_default().to_owned(),
            sts: sections.next().unwrap_or_default().to_owned(),
        }
    };
    validate_credential(&credential)?;
    Ok(credential)
}

fn validate_credential(credential: &StsCredential) -> Result<()> {
    ensure!(
        [&credential.ak, &credential.sk, &credential.sts]
            .iter()
            .all(|value| !value.trim().is_empty() && !value.bytes().any(|b| b.is_ascii_control())),
        "STS credentials require nonempty AccessKeyId, AccessKeySecret and SecurityToken"
    );
    Ok(())
}

impl SessionClient {
    pub(super) fn new(role: Option<String>) -> Result<Self> {
        Ok(Self {
            client: reqwest::Client::builder()
                .use_rustls_tls()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .connect_timeout(Duration::from_secs(1))
                .timeout(Duration::from_secs(2))
                .build()?,
            endpoint: IMDS.to_string(),
            role,
            cached: Mutex::new(None),
        })
    }

    async fn get(&self, path: &str) -> Result<String> {
        let response = self
            .client
            .put(format!("{}/api/token", self.endpoint))
            .header("X-aliyun-ecs-metadata-token-ttl-seconds", "60")
            .send()
            .await
            .context("request IMDSv2 access token")?;
        ensure!(
            response.status().is_success(),
            "IMDSv2 token request failed: {}",
            response.status()
        );
        let token = response.text().await.context("read IMDSv2 token")?;
        ensure!(
            !token.is_empty() && token.len() <= 4096,
            "invalid IMDSv2 token"
        );
        let response = self
            .client
            .get(format!("{}/meta-data/{path}", self.endpoint))
            .header("X-aliyun-ecs-metadata-token", token)
            .send()
            .await
            .context("request instance metadata")?;
        ensure!(
            response.status().is_success(),
            "IMDS metadata request failed: {}",
            response.status()
        );
        response.text().await.context("read metadata response")
    }

    pub(super) async fn region(&self) -> Result<String> {
        let region = self.get("region-id").await?;
        let region = region.trim();
        ensure!(
            !region.is_empty()
                && region
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-'),
            "IMDS returned an invalid region-id"
        );
        Ok(region.to_owned())
    }

    pub(super) async fn invalidate(&self, rejected: &StsCredential) {
        let mut cached = self.cached.lock().await;
        if cached
            .as_ref()
            .is_some_and(|s| s.credential.ak == rejected.ak && s.credential.sts == rejected.sts)
        {
            *cached = None;
        }
    }

    pub(super) async fn credential(&self) -> Result<StsCredential> {
        let role = self
            .role
            .as_deref()
            .context("provide request sts or configure kbc.ecs_ram_role_name for IMDSv2")?;
        let mut cached = self.cached.lock().await;
        if let Some(session) = cached.as_ref() {
            if Utc::now() < session.refresh_at {
                return Ok(session.credential.clone());
            }
        }
        let refreshed = async {
            let body = self
                .get(&format!("ram/security-credentials/{role}"))
                .await?;
            parse_session(&body, Utc::now())
        }
        .await;
        match refreshed {
            Ok(session) => {
                let result = session.credential.clone();
                *cached = Some(session);
                Ok(result)
            }
            Err(error) => {
                if let Some(session) = cached.as_ref() {
                    if Utc::now() < session.expires {
                        warn!("Session credential refresh failed; retaining the still-valid cached session");
                        return Ok(session.credential.clone());
                    }
                }
                Err(error)
            }
        }
    }
}

fn parse_session(body: &str, now: DateTime<Utc>) -> Result<Session> {
    let response: SessionResponse =
        serde_json::from_str(body).map_err(|_| anyhow!("invalid session credential response"))?;
    ensure!(
        response.code == "Success",
        "credential source did not return a successful session credential"
    );
    validate_credential(&response.credential)?;
    let expires = DateTime::parse_from_rfc3339(&response.expiration)
        .map_err(|_| anyhow!("invalid session credential expiration"))?
        .with_timezone(&Utc);
    let lifetime = (expires - now).num_seconds();
    ensure!(
        lifetime > 0,
        "credential source returned expired session credentials"
    );
    let margin = (lifetime / 5).clamp(0, 300);
    let jitter = rand::rng().random_range(0..=margin.min(30));
    let refresh_at = expires - chrono::Duration::seconds(margin + jitter);
    Ok(Session {
        credential: response.credential,
        expires,
        refresh_at,
    })
}

