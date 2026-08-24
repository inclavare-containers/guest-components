// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use std::{collections::HashMap, path::Path};

use async_trait::async_trait;
use image_rs::{builder::ClientBuilder, config::ImageConfig, image::ImageClient};
use log::{debug, info};
use tokio::sync::{Mutex, OnceCell};

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
