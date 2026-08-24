// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use std::{collections::HashMap, path::Path};

use async_trait::async_trait;
use image_rs::{builder::ClientBuilder, config::ImageConfig, image::ImageClient};
use log::{debug, info, warn};
use tokio::sync::{Mutex, OnceCell};

#[cfg(feature = "ttrpc")]
use protos::ttrpc::aa::attestation_agent::{
    ExtendRuntimeMeasurementRequest, RuntimeMeasurementResult,
};
#[cfg(feature = "ttrpc")]
use protos::ttrpc::aa::attestation_agent_ttrpc::AttestationAgentServiceClient;

use crate::kms;
use crate::kms::{Annotations, ProviderSettings};
#[cfg(feature = "resource_injection")]
use crate::resource_injection::ResourceInjection;
use crate::storage::volume_type::Storage;
use crate::{image, secret, CdhConfig, DataHub, Error, PrepareResourceInjectionResult, Result};

pub struct Hub {
    #[allow(dead_code)]
    pub(crate) credentials: HashMap<String, String>,
    image_client: OnceCell<Mutex<ImageClient>>,
    #[cfg(feature = "ttrpc")]
    aa_client: OnceCell<Option<AttestationAgentServiceClient>>,
    config: CdhConfig,
    #[cfg(feature = "resource_injection")]
    resource_injection: ResourceInjection,
}

impl Hub {
    pub async fn new(config: CdhConfig) -> Result<Self> {
        config.set_configuration_envs().map_err(|error| {
            Error::InitializationFailed(format!("set configuration envs: {error:#}"))
        })?;
        let credentials = config
            .credentials
            .iter()
            .map(|it| (it.path.clone(), it.resource_uri.clone()))
            .collect();
        #[cfg(feature = "resource_injection")]
        let resource_injection = ResourceInjection::new(config.aa_socket.clone());

        let mut hub = Self {
            credentials,
            config,
            image_client: OnceCell::const_new(),
            #[cfg(feature = "ttrpc")]
            aa_client: OnceCell::const_new(),
            #[cfg(feature = "resource_injection")]
            resource_injection,
        };

        hub.init().await?;
        Ok(hub)
    }
}

#[async_trait]
impl DataHub for Hub {
    async fn unseal_secret(&self, secret: Vec<u8>) -> Result<Vec<u8>> {
        info!("unseal secret called");

        let res = secret::unseal_secret(&secret).await?;

        Ok(res)
    }

    async fn unwrap_key(&self, annotation_packet: &[u8]) -> Result<Vec<u8>> {
        info!("unwrap key called");

        let lek = image::unwrap_key(annotation_packet).await?;
        Ok(lek)
    }

    async fn get_resource(&self, uri: String) -> Result<Vec<u8>> {
        info!("get resource called: {uri}");
        // to initialize a get_resource_provider client we do not need the ProviderSettings.
        let client = kms::new_getter("kbs", ProviderSettings::default())
            .await
            .map_err(|e| Error::KbsClient { source: e })?;

        // to get resource using a get_resource_provider client we do not need the Annotations.
        let res = client
            .get_secret(&uri, &Annotations::default())
            .await
            .map_err(|e| Error::GetResource { source: e })?;
        Ok(res)
    }

    async fn prepare_resource_injection(
        &self,
        resource_path: String,
        nonce: String,
    ) -> Result<PrepareResourceInjectionResult> {
        #[cfg(not(feature = "resource_injection"))]
        {
            let _ = (&resource_path, &nonce);
            return Err(Error::ResourceInjection(
                "resource injection requires the `resource_injection` feature".to_string(),
            ));
        }

        #[cfg(feature = "resource_injection")]
        self.resource_injection.prepare(resource_path, nonce).await
    }

    async fn commit_resource_injection(
        &self,
        session_id: String,
        resource_path: String,
        encrypted_resource: Vec<u8>,
    ) -> Result<()> {
        #[cfg(not(feature = "resource_injection"))]
        {
            let _ = (&session_id, &resource_path, &encrypted_resource);
            return Err(Error::ResourceInjection(
                "resource injection requires the `resource_injection` feature".to_string(),
            ));
        }

        #[cfg(feature = "resource_injection")]
        self.resource_injection
            .commit(session_id, resource_path, encrypted_resource)
            .await
    }

    async fn secure_mount(&self, storage: Storage) -> Result<String> {
        info!("secure mount called");
        let res = storage.mount().await?;
        Ok(res)
    }

    async fn pull_image(&self, image_url: &str, bundle_path: &str) -> Result<String> {
        let client = self
            .image_client
            .get_or_try_init(
                || async move { initialize_image_client(self.config.image.clone()).await },
            )
            .await?;
        let image_info = client
            .lock()
            .await
            .pull_image(image_url, Path::new(bundle_path), &None, &None)
            .await
            .map_err(|e| Error::ImagePull { source: e })?;

        #[cfg(not(feature = "ttrpc"))]
        warn!("ttrpc is disabled; skipping the PullImage runtime measurement event");

        #[cfg(feature = "ttrpc")]
        {
            use anyhow::anyhow;
            use ttrpc::context::with_timeout;

            const EXTEND_TIMEOUT_NANOS: i64 = 10 * 1000 * 1000 * 1000;

            let aa_client = self
                .aa_client
                .get_or_try_init(|| async { initialize_aa_client(&self.config.aa_socket).await })
                .await?;

            let Some(aa_client) = aa_client else {
                warn!(
                    "attestation-agent socket {} is absent; skipping the PullImage runtime measurement event",
                    self.config.aa_socket
                );
                return Ok(image_info.manifest_digest);
            };

            let request = pull_image_event(image_url, &image_info.manifest_digest);
            debug!("extending AA runtime measurement with {request:?}");
            let response = aa_client
                .extend_runtime_measurement(with_timeout(EXTEND_TIMEOUT_NANOS), &request)
                .await
                .map_err(|error| Error::AttestationAgentClient {
                    source: anyhow!("extend PullImage runtime measurement failed: {error}"),
                })?;

            match response.Result.enum_value().map_err(|error| {
                Error::AttestationAgentClient {
                    source: anyhow!("invalid runtime measurement result: {error}"),
                }
            })? {
                RuntimeMeasurementResult::OK => {
                    info!("PullImage runtime measurement event extended successfully")
                }
                RuntimeMeasurementResult::NOT_SUPPORTED => warn!(
                    "the current platform does not support runtime measurement; PullImage remains successful"
                ),
                RuntimeMeasurementResult::NOT_ENABLED => warn!(
                    "AA runtime measurement is disabled; PullImage remains successful"
                ),
            }
        }

        Ok(image_info.manifest_digest)
    }
}

#[cfg(feature = "ttrpc")]
fn pull_image_event(image_url: &str, manifest_digest: &str) -> ExtendRuntimeMeasurementRequest {
    ExtendRuntimeMeasurementRequest {
        Domain: "github.com/confidential-containers".into(),
        Operation: "PullImage".into(),
        Content: serde_json::json!({
            "image": image_url,
            "digest": manifest_digest,
        })
        .to_string(),
        ..Default::default()
    }
}

#[cfg(feature = "ttrpc")]
fn aa_socket_path(aa_socket: &str) -> &str {
    aa_socket.strip_prefix("unix://").unwrap_or(aa_socket)
}

#[cfg(feature = "ttrpc")]
async fn initialize_aa_client(aa_socket: &str) -> Result<Option<AttestationAgentServiceClient>> {
    use anyhow::anyhow;

    if !Path::new(aa_socket_path(aa_socket)).exists() {
        return Ok(None);
    }

    let client = ttrpc::r#async::Client::connect(aa_socket).map_err(|error| {
        Error::AttestationAgentClient {
            source: anyhow!("connect to attestation-agent at {aa_socket} failed: {error}"),
        }
    })?;
    Ok(Some(AttestationAgentServiceClient::new(client)))
}

#[cfg(all(test, feature = "ttrpc"))]
mod tests {
    use super::*;

    #[test]
    fn pull_image_event_is_well_formed_and_escaped() {
        let request = pull_image_event("registry.example/repo:\"tag\"", "sha256:0123456789abcdef");
        assert_eq!(request.Domain, "github.com/confidential-containers");
        assert_eq!(request.Operation, "PullImage");
        assert!(request.RegisterIndex.is_none());
        let content: serde_json::Value = serde_json::from_str(&request.Content).unwrap();
        assert_eq!(content["image"], "registry.example/repo:\"tag\"");
        assert_eq!(content["digest"], "sha256:0123456789abcdef");
    }

    #[test]
    fn aa_socket_path_accepts_uri_and_plain_path() {
        assert_eq!(aa_socket_path("unix:///run/aa.sock"), "/run/aa.sock");
        assert_eq!(aa_socket_path("/run/aa.sock"), "/run/aa.sock");
    }
}

async fn initialize_image_client(config: ImageConfig) -> Result<Mutex<ImageClient>> {
    debug!("Image client lazy initializing...");

    let image_client = Into::<ClientBuilder>::into(config)
        .build()
        .await
        .map_err(|e| {
            Error::InitializationFailed(format!("failed to initialize image pull client :{e:?}"))
        })?;

    Ok(Mutex::new(image_client))
}
