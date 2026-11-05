// Copyright (c) 2026 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0

//! Explicit ECS IMDSv2 or EAS credentials-URI source, with shared STS refresh.
//! Metadata tokens and session credentials never leave this client
//! except as in-memory credentials passed to the signed KMS request builder.
use std::time::Duration;

use anyhow::{bail, ensure, Context, Result};
use chrono::{DateTime, Utc};
use log::warn;
use rand::Rng;
use serde::Deserialize;
use tokio::sync::Mutex;

use super::sts_token_client::credential::StsCredential;
use crate::config::{KmsConfig, KmsCredentialSource};

const IMDS: &str = "http://100.100.100.200/latest";

pub(super) struct SessionClient {
    client: reqwest::Client,
    endpoint: String,
    source: Source,
    cached: Mutex<Option<Session>>,
}

enum Source {
    EcsRamRole(String),
    CredentialsUri(reqwest::Url),
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

impl SessionClient {
    pub(super) fn new(config: &KmsConfig) -> Result<Self> {
        config.validate()?;
        let source = match config.credential_source {
            KmsCredentialSource::EcsRamRole => Source::EcsRamRole(
                config
                    .ecs_ram_role_name
                    .clone()
                    .context("missing ECS role")?,
            ),
            KmsCredentialSource::CredentialsUri => {
                let uri = config.credentials_uri.clone().or_else(||
                    std::env::var("ALIBABA_CLOUD_CREDENTIALS_URI").ok())
                    .context("credentials_uri requires kbc.credentials_uri or ALIBABA_CLOUD_CREDENTIALS_URI in the CDH process")?;
                Source::CredentialsUri(credential_uri(&uri)?)
            }
        };
        Self::with_source(source)
    }

    fn with_source(source: Source) -> Result<Self> {
        Ok(Self {
            client: reqwest::Client::builder()
                .use_rustls_tls()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .connect_timeout(Duration::from_secs(1))
                .timeout(Duration::from_secs(2))
                .build()?,
            endpoint: IMDS.to_string(),
            source,
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
        if matches!(self.source, Source::CredentialsUri(_)) {
            bail!("kbc.region_id is required for credentials_uri; ECS IMDS is not used");
        }
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
        // A delayed error from another request must not invalidate a session
        // which has already been refreshed by a concurrent caller.
        if cached
            .as_ref()
            .is_some_and(|s| s.credential.ak == rejected.ak && s.credential.sts == rejected.sts)
        {
            *cached = None;
        }
    }

    pub(super) async fn credential(&self) -> Result<StsCredential> {
        // The lock coalesces concurrent refreshes. No request gets an expired
        // credential, including when the metadata service is unavailable.
        let mut cached = self.cached.lock().await;
        if let Some(session) = cached.as_ref() {
            if Utc::now() < session.refresh_at {
                return Ok(session.credential.clone());
            }
        }
        let refreshed = async {
            let body = match &self.source {
                Source::EcsRamRole(role) => {
                    self.get(&format!("ram/security-credentials/{role}"))
                        .await?
                }
                Source::CredentialsUri(uri) => {
                    let response = self
                        .client
                        .get(uri.clone())
                        .send()
                        .await
                        .map_err(|e| e.without_url())
                        .context("request platform credentials URI")?;
                    ensure!(
                        response.status() == reqwest::StatusCode::OK,
                        "credentials URI request failed: {}",
                        response.status()
                    );
                    response
                        .text()
                        .await
                        .map_err(|e| e.without_url())
                        .context("read platform session credential")?
                }
            };
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
    // Do not retain serde errors: a mismatched field type can quote credential values.
    let response: SessionResponse = serde_json::from_str(body)
        .map_err(|_| anyhow::anyhow!("invalid session credential response"))?;
    ensure!(
        response.code == "Success",
        "credential source did not return a successful session credential"
    );
    let credential = response.credential;
    ensure!(
        !credential.ak.is_empty() && !credential.sk.is_empty() && !credential.sts.is_empty(),
        "credential source returned incomplete session credentials"
    );
    let expires = DateTime::parse_from_rfc3339(&response.expiration)
        .context("invalid session credential expiration")?
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
        credential,
        expires,
        refresh_at,
    })
}

fn credential_uri(value: &str) -> Result<reqwest::Url> {
    let url = reqwest::Url::parse(value).map_err(|_| anyhow::anyhow!("invalid credentials URI"))?;
    ensure!(
        matches!(url.scheme(), "http" | "https")
            && url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && url.fragment().is_none(),
        "credentials URI must be an HTTP(S) URL without userinfo or fragment"
    );
    Ok(url)
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
    fn validates_expiration_and_refreshes_early() {
        let now = Utc::now();
        let body = response(&(now + chrono::Duration::hours(1)).to_rfc3339());
        let session = parse_session(&body, now).unwrap();
        assert!(session.refresh_at > now);
        assert!(session.refresh_at <= session.expires - chrono::Duration::seconds(300));
        assert!(parse_session(
            &response(&(now - chrono::Duration::seconds(1)).to_rfc3339()),
            now
        )
        .is_err());
        assert!(parse_session("{}", now).is_err());
        let secret_error = json!({"Code":"Success", "Expiration":"invalid",
            "AccessKeyId": {"private":"never-echo"}, "AccessKeySecret":"private", "SecurityToken":"private"});
        assert!(!format!(
            "{:#}",
            parse_session(&secret_error.to_string(), now).err().unwrap()
        )
        .contains("never-echo"));
    }

    #[test]
    fn credential_uri_validation_does_not_disclose_uri() {
        assert!(credential_uri("http://127.0.0.1:8080/credentials").is_ok());
        assert!(credential_uri("https://example.test/credentials").is_ok());
        for invalid in [
            "file:///etc/passwd",
            "http://user:private@localhost/",
            "http://localhost/#private",
            "not-a-url",
        ] {
            assert!(credential_uri(invalid).is_err());
        }
    }

    #[tokio::test]
    async fn uri_credentials_are_cached_refreshed_and_never_use_imds() {
        use std::{
            io::{Read, Write},
            net::TcpListener,
            sync::Arc,
        };
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let uri = format!(
            "http://{}/credentials?opaque=private",
            listener.local_addr().unwrap()
        );
        let body = response(&(Utc::now() + chrono::Duration::hours(1)).to_rfc3339());
        let server = std::thread::spawn(move || {
            for _ in 0..2 {
                let (mut socket, _) = listener.accept().unwrap();
                socket
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut buf = [0; 8192];
                let n = socket.read(&mut buf).unwrap();
                assert!(String::from_utf8_lossy(&buf[..n])
                    .starts_with("GET /credentials?opaque=private "));
                write!(
                    socket,
                    "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{}",
                    body.len(),
                    body
                )
                .unwrap();
            }
        });
        let client = Arc::new(
            SessionClient::with_source(Source::CredentialsUri(credential_uri(&uri).unwrap()))
                .unwrap(),
        );
        assert!(client.region().await.is_err());
        let mut tasks = tokio::task::JoinSet::new();
        for _ in 0..10 {
            let client = client.clone();
            tasks.spawn(async move { client.credential().await.unwrap().ak });
        }
        while let Some(result) = tasks.join_next().await {
            assert_eq!(result.unwrap(), "test-ak");
        }
        client.cached.lock().await.as_mut().unwrap().refresh_at =
            Utc::now() - chrono::Duration::seconds(1);
        assert_eq!(client.credential().await.unwrap().ak, "test-ak");
        // Rejection of a different session must not invalidate the fresh cache.
        let mut other = client.credential().await.unwrap();
        other.ak = "different-session".into();
        client.invalidate(&other).await;
        assert!(client.cached.lock().await.is_some());
        client.invalidate(&client.credential().await.unwrap()).await;
        assert!(client.cached.lock().await.is_none());
        server.join().unwrap();
    }

    #[tokio::test]
    async fn uri_redirect_is_not_followed_and_url_is_not_logged() {
        use std::{
            io::{Read, Write},
            net::TcpListener,
        };
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let uri = format!("http://{}/private-token", listener.local_addr().unwrap());
        let server = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut buf = [0; 4096];
            assert!(socket.read(&mut buf).unwrap() > 0);
            write!(socket, "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:1/never-follow\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
        });
        let client =
            SessionClient::with_source(Source::CredentialsUri(credential_uri(&uri).unwrap()))
                .unwrap();
        let error = format!("{:#}", client.credential().await.err().unwrap());
        assert!(error.contains("302"));
        assert!(!error.contains("private-token"));
        server.join().unwrap();
        let client = SessionClient::with_source(Source::CredentialsUri(
            credential_uri("http://127.0.0.1:1/private-token").unwrap(),
        ))
        .unwrap();
        assert!(
            !format!("{:#}", client.credential().await.err().unwrap()).contains("private-token")
        );
    }

    #[tokio::test]
    async fn uri_refresh_failure_never_returns_expired_credentials() {
        use std::{
            io::{Read, Write},
            net::TcpListener,
        };
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let uri = format!("http://{}/credentials", listener.local_addr().unwrap());
        let body = response(&(Utc::now() + chrono::Duration::hours(1)).to_rfc3339());
        let server = std::thread::spawn(move || {
            for status in [
                "200 OK",
                "500 Internal Server Error",
                "500 Internal Server Error",
            ] {
                let (mut socket, _) = listener.accept().unwrap();
                socket
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut buf = [0; 4096];
                assert!(socket.read(&mut buf).unwrap() > 0);
                write!(
                    socket,
                    "HTTP/1.1 {status}\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{}",
                    body.len(),
                    body
                )
                .unwrap();
            }
        });
        let client =
            SessionClient::with_source(Source::CredentialsUri(credential_uri(&uri).unwrap()))
                .unwrap();
        assert_eq!(client.credential().await.unwrap().ak, "test-ak");
        client.cached.lock().await.as_mut().unwrap().refresh_at =
            Utc::now() - chrono::Duration::seconds(1);
        assert_eq!(client.credential().await.unwrap().ak, "test-ak");
        client.cached.lock().await.as_mut().unwrap().expires =
            Utc::now() - chrono::Duration::seconds(1);
        assert!(client.credential().await.is_err());
        server.join().unwrap();
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
        let mut client =
            SessionClient::with_source(Source::EcsRamRole("test-role".into())).unwrap();
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
        server.join().unwrap();
    }
}
