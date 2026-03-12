// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use std::{collections::HashMap, path::Path};

use async_trait::async_trait;
use attestation_agent::{AttestationAPIs, AttestationAgent};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use image_rs::{builder::ClientBuilder, config::ImageConfig, image::ImageClient};
use kbs_protocol::TeeKeyPair;
use kbs_types::Response as EncryptedResponse;
use log::{debug, info};
use rand::RngCore;
use tokio::fs;
use tokio::sync::{Mutex, OnceCell};

use crate::kms;
use crate::kms::{Annotations, ProviderSettings};
use crate::storage::volume_type::Storage;
use crate::{image, secret, CdhConfig, DataHub, Error, PrepareResourceInjectionResult, Result};

const KBS_RESOURCE_STORAGE_DIR: &str = "/run/confidential-containers/cdh";

struct InjectionSession {
    resource_path: String,
    tee_key: TeeKeyPair,
}

fn is_relative_resource_path_valid(path: &str) -> bool {
    !path.is_empty()
        && !path.starts_with('/')
        && !path
            .split('/')
            .any(|it| it.is_empty() || it == ".." || it == ".")
}

pub struct Hub {
    #[allow(dead_code)]
    pub(crate) credentials: HashMap<String, String>,
    image_client: OnceCell<Mutex<ImageClient>>,
    config: CdhConfig,
    injection_sessions: Mutex<HashMap<String, InjectionSession>>,
}

impl Hub {
    pub async fn new(config: CdhConfig) -> Result<Self> {
        config.set_configuration_envs();
        let credentials = config
            .credentials
            .iter()
            .map(|it| (it.path.clone(), it.resource_uri.clone()))
            .collect();

        let mut hub = Self {
            credentials,
            config,
            image_client: OnceCell::const_new(),
            injection_sessions: Mutex::new(HashMap::new()),
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
        info!("prepare resource injection called: {resource_path}");
        if !is_relative_resource_path_valid(&resource_path) {
            return Err(Error::ResourceInjection(format!(
                "invalid resource path: {resource_path}"
            )));
        }
        if nonce.is_empty() {
            return Err(Error::ResourceInjection(
                "nonce must not be empty".to_string(),
            ));
        }

        let tee_key = TeeKeyPair::new().map_err(|e| {
            Error::ResourceInjection(format!("create TEE key pair for injection failed: {e}"))
        })?;
        let tee_pubkey = tee_key.export_pubkey().map_err(|e| {
            Error::ResourceInjection(format!("export TEE public key for injection failed: {e}"))
        })?;
        let runtime_data = serde_json::json!({
            "nonce": nonce,
            "tee-pubkey": tee_pubkey,
        });
        let runtime_data = serde_json::to_vec(&runtime_data).map_err(|e| {
            Error::ResourceInjection(format!("serialize runtime_data for injection failed: {e}"))
        })?;

        let mut aa = AttestationAgent::new(None).map_err(|e| {
            Error::ResourceInjection(format!(
                "initialize attestation agent for injection failed: {e}"
            ))
        })?;
        aa.init().await.map_err(|e| {
            Error::ResourceInjection(format!("initialize attestation agent runtime failed: {e}"))
        })?;
        let evidence = aa.get_evidence(&runtime_data).await.map_err(|e| {
            Error::ResourceInjection(format!("generate attestation evidence failed: {e}"))
        })?;

        let mut session_id_raw = [0_u8; 16];
        rand::rng().fill_bytes(&mut session_id_raw);
        let session_id = URL_SAFE_NO_PAD.encode(session_id_raw);

        self.injection_sessions.lock().await.insert(
            session_id.clone(),
            InjectionSession {
                resource_path,
                tee_key,
            },
        );

        let tee_pubkey = serde_json::to_string(&tee_pubkey).map_err(|e| {
            Error::ResourceInjection(format!(
                "serialize TEE public key for injection failed: {e}"
            ))
        })?;

        Ok(PrepareResourceInjectionResult {
            session_id,
            nonce,
            tee_pubkey,
            evidence,
        })
    }

    async fn commit_resource_injection(
        &self,
        session_id: String,
        resource_path: String,
        encrypted_resource: Vec<u8>,
    ) -> Result<()> {
        info!("commit resource injection called: {resource_path}");
        if !is_relative_resource_path_valid(&resource_path) {
            return Err(Error::ResourceInjection(format!(
                "invalid resource path: {resource_path}"
            )));
        }

        let session = self
            .injection_sessions
            .lock()
            .await
            .remove(&session_id)
            .ok_or_else(|| {
                Error::ResourceInjection(format!(
                    "resource injection session not found or already used: {session_id}"
                ))
            })?;
        if session.resource_path != resource_path {
            return Err(Error::ResourceInjection(format!(
                "resource path mismatch for session {session_id}"
            )));
        }

        let encrypted_response: EncryptedResponse = serde_json::from_slice(&encrypted_resource)
            .map_err(|e| {
                Error::ResourceInjection(format!("parse encrypted resource payload failed: {e}"))
            })?;
        let plaintext = session
            .tee_key
            .decrypt_response(encrypted_response)
            .map_err(|e| {
                Error::ResourceInjection(format!("decrypt injected resource failed: {e}"))
            })?;

        let target_path = format!("{KBS_RESOURCE_STORAGE_DIR}/{resource_path}");
        let target_path = std::path::PathBuf::from(&target_path);
        if let Some(parent) = target_path.parent() {
            fs::create_dir_all(parent).await.map_err(|e| {
                Error::ResourceInjection(format!(
                    "create target directory for injected resource failed: {e}"
                ))
            })?;
        }
        fs::write(&target_path, plaintext).await.map_err(|e| {
            Error::ResourceInjection(format!(
                "write injected resource to {} failed: {e}",
                target_path.display()
            ))
        })?;

        Ok(())
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
        let manifest_digest = client
            .lock()
            .await
            .pull_image(image_url, Path::new(bundle_path), &None, &None)
            .await
            .map_err(|e| Error::ImagePull { source: e })?;
        Ok(manifest_digest)
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
