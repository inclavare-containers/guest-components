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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn response(expiration: &str) -> String {
        json!({"Code":"Success", "Expiration":expiration,
            "AccessKeyId":"test-ak", "AccessKeySecret":"test-sk", "SecurityToken":"test-token"})
        .to_string()
    }

    #[test]
    fn request_sts_accepts_complete_json_and_legacy_representation() {
        for text in [
            response(&(Utc::now() + chrono::Duration::hours(1)).to_rfc3339()),
            "test-ak:test-sk:test-token".to_string(),
        ] {
            for engine in [STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD] {
                let credential = parse_request_sts(&engine.encode(&text)).unwrap();
                assert_eq!(credential.ak, "test-ak");
                assert_eq!(credential.sk, "test-sk");
                assert_eq!(credential.sts, "test-token");
            }
        }
        assert!(parse_request_sts(
            &STANDARD.encode(r#"{"AccessKeyId":"a","AccessKeySecret":"b","SecurityToken":"c"}"#)
        )
        .is_ok());
    }

    #[test]
    fn request_sts_rejects_invalid_empty_and_expired_values_without_echoing_them() {
        for text in [
            "private-credential".to_owned(),
            "a::private-credential".to_owned(),
            r#"{"AccessKeyId":{"secret":"private-credential"}}"#.to_owned(),
            response(&(Utc::now() - chrono::Duration::minutes(1)).to_rfc3339()),
        ] {
            let error = parse_request_sts(&STANDARD.encode(text)).err().unwrap();
            assert!(!format!("{error:#}").contains("private-credential"));
        }
        for encoded in [
            "".to_owned(),
            "not base64!".to_owned(),
            "A".repeat(MAX_ENCODED_STS + 1),
        ] {
            assert!(parse_request_sts(&encoded).is_err());
        }
    }

    #[test]
    fn validates_imds_expiration_and_refreshes_early() {
        let now = Utc::now();
        let session = parse_session(
            &response(&(now + chrono::Duration::hours(1)).to_rfc3339()),
            now,
        )
        .unwrap();
        assert!(session.refresh_at > now);
        assert!(session.refresh_at <= session.expires - chrono::Duration::seconds(300));
        assert!(parse_session(
            &response(&(now - chrono::Duration::seconds(1)).to_rfc3339()),
            now
        )
        .is_err());
        assert!(parse_session("{}", now).is_err());
    }

    #[tokio::test]
    async fn request_credentials_do_not_populate_the_imds_cache() {
        let client = SessionClient::new(None).unwrap();
        let credential = parse_request_sts(&STANDARD.encode("a:b:c")).unwrap();
        assert_eq!(credential.ak, "a");
        assert!(client.cached.lock().await.is_none());
        assert!(client.credential().await.is_err());
    }

    #[tokio::test]
    async fn concurrent_requests_share_one_imdsv2_refresh() {
        use std::{
            io::{Read, Write},
            net::TcpListener,
            sync::Arc,
        };
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}/latest", listener.local_addr().unwrap());
        let body = response(&(Utc::now() + chrono::Duration::hours(1)).to_rfc3339());
        let server = std::thread::spawn(move || {
            for (expected, response) in [
                ("PUT /latest/api/token", "metadata-test-token".to_string()),
                (
                    "GET /latest/meta-data/ram/security-credentials/test-role",
                    body,
                ),
            ] {
                let (mut socket, _) = listener.accept().unwrap();
                socket
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut buf = [0; 8192];
                let n = socket.read(&mut buf).unwrap();
                let request = String::from_utf8_lossy(&buf[..n]);
                assert!(
                    request.starts_with(expected),
                    "unexpected metadata request path"
                );
                if expected.starts_with("GET") {
                    assert!(request
                        .to_lowercase()
                        .contains("x-aliyun-ecs-metadata-token: metadata-test-token"));
                }
                write!(
                    socket,
                    "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{}",
                    response.len(),
                    response
                )
                .unwrap();
            }
        });
        let mut client = SessionClient::new(Some("test-role".into())).unwrap();
        client.endpoint = endpoint;
        let client = Arc::new(client);
        let mut tasks = tokio::task::JoinSet::new();
        for _ in 0..10 {
            let client = client.clone();
            tasks.spawn(async move { client.credential().await.unwrap().ak });
        }
        while let Some(result) = tasks.join_next().await {
            assert_eq!(result.unwrap(), "test-ak");
        }
        let mut other = client.credential().await.unwrap();
        other.ak = "different-session".into();
        client.invalidate(&other).await;
        assert!(client.cached.lock().await.is_some());
        let credential = client.credential().await.unwrap();
        client.invalidate(&credential).await;
        assert!(client.cached.lock().await.is_none());
        server.join().unwrap();
    }
}
