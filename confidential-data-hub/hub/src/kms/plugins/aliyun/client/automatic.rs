// Copyright (c) 2026 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0

//! GetResource-specific identity and trust bootstrap. The legacy Vault provider
//! remains file/inline-CA compatible and does not implicitly enable this path.
use std::{
    collections::BTreeMap,
    time::{Duration, Instant},
};

use anyhow::{bail, ensure, Context, Result};
use async_trait::async_trait;
use log::{info, warn};
use reqwest::{Certificate, Client, ClientBuilder};
use serde_json::Value;
use tokio::sync::{Mutex, OnceCell};

use super::super::annotations::AliSecretAnnotations;
use super::{
    attestation_client::{ApiError, AttestationClient},
    session::{parse_request_sts, SessionClient},
    sts_token_client::credential::StsCredential,
};
use crate::kms::{self, valid_kms_instance_id, valid_region_id, Annotations, Getter, KmsConfig};

const CA_REFRESH: Duration = Duration::from_secs(24 * 3600);
const REFRESH_BACKOFF: Duration = Duration::from_secs(60);

pub struct AutomaticKmsClient {
    config: KmsConfig,
    aa_socket: String,
    session: SessionClient,
    region: OnceCell<String>,
    transport: Mutex<Option<Transport>>,
    management_client: Client,
}

struct Transport {
    instance_id: String,
    region_id: String,
    client: Client,
    refreshed: Instant,
    refresh_after: Instant,
}

impl Transport {
    fn matches(&self, instance_id: &str, region_id: &str) -> bool {
        self.instance_id == instance_id && self.region_id == region_id
    }
}

impl AutomaticKmsClient {
    pub fn new(config: KmsConfig, aa_socket: String) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            session: SessionClient::new(config.ecs_ram_role_name.clone())?,
            management_client: http_builder().build()?,
            config,
            aa_socket,
            region: OnceCell::new(),
            transport: Mutex::new(None),
        })
    }

    async fn region(&self, provided: Option<&str>) -> Result<String> {
        if let Some(region) = provided {
            return Ok(region.to_owned());
        }
        self.region
            .get_or_try_init(|| async {
                match &self.config.region_id {
                    Some(region) => Ok(region.clone()),
                    None => self.session.region().await,
                }
            })
            .await
            .cloned()
    }

    async fn transport(
        &self,
        instance_id: &str,
        region: &str,
        credential: &StsCredential,
        refresh_unknown_issuer: bool,
    ) -> Result<Client> {
        let mut state = self.transport.lock().await;
        if let Some(cached) = state.as_ref() {
            if cached.matches(instance_id, region)
                && ((!refresh_unknown_issuer && Instant::now() < cached.refresh_after)
                    || (refresh_unknown_issuer && cached.refreshed.elapsed() < REFRESH_BACKOFF))
            {
                return Ok(cached.client.clone());
            }
        }
        let loaded = self
            .fetch_instance_ca(instance_id, region, credential)
            .await
            .and_then(|pem| tls_client(&pem));
        match loaded {
            Ok(client) => {
                info!("aliyun KMS GetResource: TLS CA source=GetKmsInstance, region={region}");
                let now = Instant::now();
                *state = Some(Transport {
                    instance_id: instance_id.to_owned(),
                    region_id: region.to_owned(),
                    client: client.clone(),
                    refreshed: now,
                    refresh_after: now + CA_REFRESH,
                });
                Ok(client)
            }
            Err(error) => {
                if !refresh_unknown_issuer {
                    if let Some(cached) = state
                        .as_mut()
                        .filter(|cached| cached.matches(instance_id, region))
                    {
                        // TLS still validates the cached chain on connection.
                        cached.refresh_after = Instant::now() + REFRESH_BACKOFF;
                        warn!("KMS CA refresh failed; retaining the previously authenticated CA cache");
                        return Ok(cached.client.clone());
                    }
                }
                Err(error).context("automatic KMS CA resolution")
            }
        }
    }

    async fn fetch_instance_ca(
        &self,
        instance_id: &str,
        region: &str,
        credential: &StsCredential,
    ) -> Result<String> {
        // Bootstrap through the region's ordinary, system-trusted HTTPS endpoint,
        // NEVER by trusting an unauthenticated certificate from the data plane.
        let response = AttestationClient::call_api(
            &self.management_client,
            &format!("kms-vpc.{region}.aliyuncs.com"),
            credential,
            "GetKmsInstance",
            BTreeMap::from([("KmsInstanceId".into(), instance_id.to_owned())]),
        )
        .await
        .context("GetKmsInstance for automatic CA")?;
        instance_ca(&response, instance_id).map(str::to_owned)
    }

    async fn fetch(
        &self,
        name: &str,
        annotations: &Annotations,
        instance_id: &str,
        provided: Option<&StsCredential>,
        region: &str,
    ) -> Result<Vec<u8>> {
        let settings: AliSecretAnnotations =
            serde_json::from_value(Value::Object(annotations.clone()))
                .context("parse KMS secret annotations")?;
        for attempt in 0..2 {
            let credential = match provided {
                Some(credential) => credential.clone(),
                None => self.session.credential().await?,
            };
            let result = async {
                let transport = self.transport(instance_id, region, &credential, false).await?;
                let client = AttestationClient::from_session(
                    instance_id.to_owned(),
                    credential.clone(),
                    transport,
                    self.aa_socket.clone(),
                );
                let result = client.get_secret_bytes(name, &settings).await;
                // The cached CA may predate an instance CA rotation. Re-fetch
                // only for UnknownIssuer, with a refresh backoff; the rebuilt
                // transport must still validate the certificate chain and name.
                if result.as_ref().err().is_some_and(is_unknown_issuer) {
                    info!("KMS data-plane issuer is unknown; refreshing the CA through GetKmsInstance");
                    let transport = self.transport(instance_id, region, &credential, true).await?;
                    let client = AttestationClient::from_session(
                        instance_id.to_owned(), credential.clone(), transport,
                        self.aa_socket.clone(),
                    );
                    return client.get_secret_bytes(name, &settings).await;
                }
                result
            }.await;
            match result {
                Ok(secret) => return Ok(secret),
                Err(error) if attempt == 0 && provided.is_none() && expired_credential(&error) => {
                    self.session.invalidate(&credential).await;
                }
                Err(error) if attempt == 0 && transient(&error) => {}
                Err(error) => return Err(error),
            }
        }
        bail!("KMS request retry budget exhausted")
    }

    /// Request parameters override the deployment defaults independently. Caller
    /// STS is never cached, refreshed through IMDS, or used by another request.
    pub async fn get_secret_with_options(
        &self,
        name: &str,
        annotations: &Annotations,
        kms_id: Option<&str>,
        sts: Option<&str>,
        region_id: Option<&str>,
    ) -> kms::Result<Vec<u8>> {
        if region_id.is_some_and(|region| !valid_region_id(region)) {
            return Err(kms::Error::InvalidResourceOptions("region_id is invalid"));
        }
        let instance_id = kms_id
            .or(self.config.instance_id.as_deref())
            .filter(|id| valid_kms_instance_id(id))
            .ok_or(kms::Error::InvalidResourceOptions(
                "provide a valid kms_id or configure kbc.instance_id",
            ))?;
        let provided = sts.map(parse_request_sts).transpose()
            .map_err(|_| kms::Error::InvalidResourceOptions("sts must be Base64 of complete, valid STS credentials (JSON or AK:SK:STS); expired credentials are rejected"))?;
        if provided.is_none() && self.config.ecs_ram_role_name.is_none() {
            return Err(kms::Error::InvalidResourceOptions(
                "provide sts or configure kbc.ecs_ram_role_name for IMDSv2",
            ));
        }
        // Stay below the REST->ttRPC 50s deadline, including all refresh/retries.
        match tokio::time::timeout(Duration::from_secs(45), async {
            let region = self.region(region_id).await?;
            self.fetch(name, annotations, instance_id, provided.as_ref(), &region)
                .await
        })
        .await
        {
            Ok(result) => {
                result.map_err(|e| kms::Error::AliyunKmsError(format!("GetResource: {e:#}")))
            }
            Err(_) => Err(kms::Error::AliyunKmsError(
                "KMS GetResource exceeded its 45s budget".into(),
            )),
        }
    }
}

#[async_trait]
impl Getter for AutomaticKmsClient {
    async fn get_secret(&self, name: &str, annotations: &Annotations) -> kms::Result<Vec<u8>> {
        self.get_secret_with_options(name, annotations, None, None, None)
            .await
    }
}

fn http_builder() -> ClientBuilder {
    Client::builder()
        .use_rustls_tls()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(3))
        .timeout(Duration::from_secs(10))
}

fn tls_client(pem: &str) -> Result<Client> {
    let certificates =
        Certificate::from_pem_bundle(pem.as_bytes()).context("parse KMS CA chain")?;
    ensure!(!certificates.is_empty(), "KMS CA chain is empty");
    let mut builder = http_builder();
    for certificate in certificates {
        builder = builder.add_root_certificate(certificate);
    }
    builder
        .build()
        .context("build strictly verified KMS TLS client")
}

fn instance_ca<'a>(response: &'a Value, instance_id: &str) -> Result<&'a str> {
    let instance = response
        .get("KmsInstance")
        .context("GetKmsInstance response is missing KmsInstance")?;
    ensure!(
        instance.get("InstanceId").and_then(Value::as_str) == Some(instance_id),
        "GetKmsInstance returned a different instance ID"
    );
    instance
        .get("CaCertificateChainPem")
        .and_then(Value::as_str)
        .filter(|s| !s.trim().is_empty())
        .context("GetKmsInstance response is missing a CA chain")
}

fn is_unknown_issuer(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        // hyper-rustls wraps tokio-rustls' io::Error in another io::Error.
        // io::Error::source() delegates to the inner error's source, so the
        // ordinary anyhow chain can skip the rustls error entirely. Inspect
        // each nested io payload, without matching untrusted error strings.
        let mut payload = cause;
        while let Some(inner) = payload
            .downcast_ref::<std::io::Error>()
            .and_then(std::io::Error::get_ref)
        {
            payload = inner;
        }
        matches!(
            payload.downcast_ref::<rustls::Error>(),
            Some(rustls::Error::InvalidCertificate(
                rustls::CertificateError::UnknownIssuer
            ))
        )
    })
}

fn expired_credential(error: &anyhow::Error) -> bool {
    error.downcast_ref::<ApiError>().is_some_and(|e| {
        matches!(
            e.code.as_str(),
            "InvalidSecurityToken.Expired" | "SecurityTokenExpired" | "ExpiredToken"
        )
    })
}

fn transient(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<ApiError>()
        .is_some_and(|e| matches!(e.status, 429 | 500 | 502 | 503 | 504))
        || error
            .chain()
            .filter_map(|e| e.downcast_ref::<reqwest::Error>())
            .any(|e| e.is_timeout())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[tokio::test]
    async fn missing_or_invalid_request_options_fail_without_network_or_identity_fallback() {
        let client = AutomaticKmsClient::new(
            KmsConfig {
                instance_id: None,
                ecs_ram_role_name: None,
                region_id: Some("cn-beijing".into()),
            },
            "unix:///unused-aa".into(),
        )
        .unwrap();
        for (id, sts) in [
            (None, None),
            (Some("kst-test"), None),
            (Some("kst-test"), Some("")),
            (Some("https://kms.example"), Some("YWJj")),
        ] {
            assert!(matches!(
                client
                    .get_secret_with_options("secret", &Annotations::default(), id, sts, None)
                    .await,
                Err(kms::Error::InvalidResourceOptions(_))
            ));
        }
        assert!(client.transport.lock().await.is_none());
    }

    #[tokio::test]
    async fn request_region_is_independent_and_does_not_change_cached_default() {
        let client = AutomaticKmsClient::new(
            KmsConfig {
                instance_id: Some("kst-test".into()),
                ecs_ram_role_name: Some("product-role".into()),
                region_id: Some("cn-beijing".into()),
            },
            "unix:///unused-aa".into(),
        )
        .unwrap();
        assert_eq!(client.region(None).await.unwrap(), "cn-beijing");
        assert_eq!(
            client.region(Some("cn-hangzhou")).await.unwrap(),
            "cn-hangzhou"
        );
        assert_eq!(client.region(None).await.unwrap(), "cn-beijing");
        for region in ["", "https://example.test", "cn/beijing", "cn_beijing"] {
            assert!(matches!(
                client
                    .get_secret_with_options(
                        "secret",
                        &Annotations::default(),
                        None,
                        None,
                        Some(region)
                    )
                    .await,
                Err(kms::Error::InvalidResourceOptions(_))
            ));
        }
        let no_default = AutomaticKmsClient::new(
            KmsConfig {
                instance_id: None,
                ecs_ram_role_name: None,
                region_id: None,
            },
            "unix:///unused-aa".into(),
        )
        .unwrap();
        assert_eq!(
            no_default.region(Some("cn-beijing")).await.unwrap(),
            "cn-beijing"
        );
        assert!(no_default.region.get().is_none());
        let transport = Transport {
            instance_id: "kst-test".into(),
            region_id: "cn-beijing".into(),
            client: http_builder().build().unwrap(),
            refreshed: Instant::now(),
            refresh_after: Instant::now() + CA_REFRESH,
        };
        assert!(transport.matches("kst-test", "cn-beijing"));
        assert!(!transport.matches("kst-other", "cn-beijing"));
        assert!(!transport.matches("kst-test", "cn-hangzhou"));
    }

    #[test]
    fn ca_response_must_match_requested_instance() {
        let response =
            json!({"KmsInstance":{"InstanceId":"kst-test", "CaCertificateChainPem":"pem"}});
        assert_eq!(instance_ca(&response, "kst-test").unwrap(), "pem");
        assert!(instance_ca(&response, "kst-other").is_err());
        assert!(instance_ca(
            &json!({"KmsInstance":{"InstanceId":"kst-test"}}),
            "kst-test"
        )
        .is_err());
        assert!(tls_client("").is_err());
        assert!(tls_client("not a certificate").is_err());
    }

    #[test]
    fn only_unknown_issuer_allows_ca_bootstrap() {
        let unknown = anyhow::Error::new(rustls::Error::InvalidCertificate(
            rustls::CertificateError::UnknownIssuer,
        ));
        assert!(is_unknown_issuer(&unknown));
        let wrapped = |error| {
            anyhow::Error::new(std::io::Error::other(std::io::Error::other(error)))
                .context("GetChallenge")
        };
        assert!(is_unknown_issuer(&wrapped(
            rustls::Error::InvalidCertificate(rustls::CertificateError::UnknownIssuer)
        )));
        let bad_name = anyhow::Error::new(rustls::Error::InvalidCertificate(
            rustls::CertificateError::NotValidForName,
        ));
        assert!(!is_unknown_issuer(&bad_name));
        assert!(!is_unknown_issuer(&wrapped(
            rustls::Error::InvalidCertificate(rustls::CertificateError::NotValidForName)
        )));
        assert!(!is_unknown_issuer(&anyhow::anyhow!("network timeout")));
    }

    /// Run on a disposable ECS VM with a bound test role. The environment
    /// contains identifiers and an expected digest only, never credentials.
    #[tokio::test]
    #[ignore = "requires a real KMS instance and ECS IMDSv2"]
    async fn live_management_ca_bootstrap_and_refresh() {
        use sha2::{Digest, Sha256};
        let required = |name| std::env::var(name).expect(name);
        let client = AutomaticKmsClient::new(
            KmsConfig {
                instance_id: Some(required("KMS_TEST_INSTANCE_ID")),
                ecs_ram_role_name: Some(required("KMS_TEST_RAM_ROLE")),
                region_id: std::env::var("KMS_TEST_REGION").ok(),
            },
            "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock".into(),
        )
        .unwrap();
        let secret_name = required("KMS_TEST_SECRET_NAME");
        let check_result = |result: Result<Vec<u8>>| {
            let secret = result.expect("TLS and remote attestation must succeed");
            assert_eq!(
                hex::encode(Sha256::digest(&secret)),
                required("KMS_TEST_SECRET_SHA256")
            );
            println!("TLS and attested secret digest verified");
        };
        check_result(
            client
                .get_secret(&secret_name, &Annotations::default())
                .await
                .map_err(anyhow::Error::from),
        );
        // Expire the transport cache to exercise authenticated management refresh.
        client
            .transport
            .lock()
            .await
            .as_mut()
            .unwrap()
            .refresh_after = Instant::now();
        check_result(
            client
                .get_secret(&secret_name, &Annotations::default())
                .await
                .map_err(anyhow::Error::from),
        );
        println!("Authenticated GetKmsInstance bootstrap and refresh verified");
    }
}
