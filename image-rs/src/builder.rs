// Copyright (c) 2024 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use std::{path::PathBuf, sync::Arc};

use log::{info, warn};
use tokio::sync::RwLock;

use crate::{
    auth::Auth,
    config::{ImageConfig, NydusConfig},
    image::ImageClient,
    layer_store::LayerStore,
    meta_store::{MetaStore, METAFILE},
    registry::RegistryHandler,
    resource::ResourceProvider,
    signature::SignatureValidator,
    snapshots::SnapshotType,
};

use anyhow::Result;

#[derive(Default)]
pub struct ClientBuilder {
    config: ImageConfig,
}

macro_rules! __impl_config {
    ($name: ident, $type: ident) => {
        pub fn $name(mut self, $name: $type) -> Self {
            self.config.$name = $name;
            self
        }
    };
    ($name: ident, $value: expr, $type: ident) => {
        pub fn $name(mut self, $name: $type) -> Self {
            self.config.$name = $value;
            self
        }
    };
}

impl ClientBuilder {
    __impl_config!(work_dir, PathBuf);
    __impl_config!(default_snapshot, SnapshotType);
    __impl_config!(
        image_security_policy_uri,
        Some(image_security_policy_uri),
        String
    );
    __impl_config!(sigstore_config_uri, Some(sigstore_config_uri), String);
    __impl_config!(sigstore_config, Some(sigstore_config), String);
    __impl_config!(image_security_policy, Some(image_security_policy), String);
    __impl_config!(
        authenticated_registry_credentials_uri,
        Some(authenticated_registry_credentials_uri),
        String
    );
    __impl_config!(max_concurrent_layer_downloads_per_image, usize);
    __impl_config!(
        registry_configuration_uri,
        Some(registry_configuration_uri),
        String
    );
    __impl_config!(nydus_config, Some(nydus_config), NydusConfig);

    #[cfg(feature = "keywrap-native")]
    __impl_config!(kbc, String);

    #[cfg(feature = "keywrap-native")]
    __impl_config!(kbs_uri, kbs_uri, String);

    pub async fn build(self) -> Result<ImageClient> {
        #[cfg(feature = "keywrap-native")]
        let resource_provider = Arc::new(ResourceProvider::new(
            &self.config.kbc,
            &self.config.kbs_uri,
            &self.config.work_dir,
        )?);

        #[cfg(not(feature = "keywrap-native"))]
        let resource_provider = Arc::new(ResourceProvider::new("", "", &self.config.work_dir)?);

        let registry_auth = match &self.config.authenticated_registry_credentials_uri {
            Some(uri) => {
                info!("getting registry auth from {uri} ...");
                let auth_bytes = resource_provider.get_resource(uri).await?;
                let auth = Auth::new(&auth_bytes)?;
                Some(auth)
            }
            None => None,
        };

        let sigstore_config = match &self.config.sigstore_config_uri {
            Some(uri) => {
                info!("getting simple-signing sigstore configuration from {uri} ...");
                let cfg_bytes = resource_provider.get_resource(uri).await?;
                Some(cfg_bytes)
            }
            None => self
                .config
                .sigstore_config
                .as_ref()
                .map(|cfg| cfg.as_bytes().to_vec()),
        };

        let policy = match &self.config.image_security_policy_uri {
            Some(uri) => {
                info!("getting image security policy from {uri} ...");
                let policy_bytes = resource_provider.get_resource(uri).await?;
                Some(policy_bytes)
            }
            None => self
                .config
                .image_security_policy
                .as_ref()
                .map(|policy| policy.as_bytes().to_vec()),
        };

        let signature_validator = match policy {
            Some(policy) => Some(
                SignatureValidator::new(
                    &policy,
                    sigstore_config,
                    &self.config.work_dir,
                    self.config.effective_proxy_config(),
                    self.config.extra_root_certificates.clone(),
                    resource_provider.clone(),
                )
                .await?,
            ),
            None => {
                warn!("No image security policy given, thus all images can be pulled by the image client without filtering.");
                None
            }
        };

        let registry_handler = if let Some(config) = &self.config.registry_config {
            Some(RegistryHandler::new(config.clone())?)
        } else if let Some(uri) = &self.config.registry_configuration_uri {
            info!("getting registry configuration from {uri} ...");
            let registry_configuration = resource_provider.get_resource(uri).await?;
            Some(RegistryHandler::from_vec(registry_configuration)?)
        } else {
            None
        };

        let meta_store = match MetaStore::try_from(self.config.work_dir.join(METAFILE).as_path()) {
            Ok(ms) => {
                info!("Existing metadata found. Using previous ones.");
                ms
            }
            Err(_) => {
                info!("Initialize new metadata.");
                MetaStore::default()
            }
        };

        let snapshots = ImageClient::init_snapshots(&self.config.work_dir, &meta_store);
        let layer_store = LayerStore::new(self.config.work_dir.clone())?;
        info!("image work directory: {:?}", self.config.work_dir);

        let meta_store = Arc::new(RwLock::new(meta_store));

        Ok(ImageClient {
            registry_auth,
            signature_validator,
            registry_handler,
            meta_store,
            snapshots,
            config: self.config,
            layer_store,
        })
    }
}

impl From<ImageConfig> for ClientBuilder {
    fn from(config: ImageConfig) -> Self {
        Self { config }
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use oci_client::Reference;

    use crate::registry::{Config as RegistryConfig, Mirror, Registry};

    use super::*;

    const ACCEPT_POLICY: &str =
        r#"{"default":[{"type":"insecureAcceptAnything"}],"transports":{}}"#;

    #[tokio::test]
    async fn inline_policy_and_registry_config_are_initialized() {
        let work_dir = tempfile::tempdir().unwrap();
        let config = ImageConfig {
            work_dir: work_dir.path().to_path_buf(),
            image_security_policy: Some(ACCEPT_POLICY.into()),
            registry_configuration_uri: Some("file:///does/not/exist".into()),
            registry_config: Some(RegistryConfig {
                unqualified_search_registries: vec!["docker.io".into()],
                registry: vec![Registry {
                    prefix: "example.com".into(),
                    location: "mirror.example.com".into(),
                    mirror: vec![Mirror {
                        location: "first.example.com".into(),
                        insecure: false,
                    }],
                    insecure: false,
                    blocked: false,
                }],
            }),
            ..Default::default()
        };

        let client = ClientBuilder::from(config).build().await.unwrap();
        assert!(client.signature_validator.is_some());
        let tasks = client
            .registry_handler
            .unwrap()
            .process(Reference::from_str("example.com/repo:tag").unwrap())
            .unwrap();
        assert_eq!(tasks[0].image_reference.registry(), "first.example.com");
        assert_eq!(tasks[1].image_reference.registry(), "mirror.example.com");
    }

    #[tokio::test]
    async fn policy_uri_takes_precedence_over_inline_policy() {
        let work_dir = tempfile::tempdir().unwrap();
        let policy_path = work_dir.path().join("policy.json");
        std::fs::write(&policy_path, ACCEPT_POLICY).unwrap();
        let config = ImageConfig {
            work_dir: work_dir.path().to_path_buf(),
            image_security_policy_uri: Some(format!("file://{}", policy_path.display())),
            image_security_policy: Some("not-json".into()),
            ..Default::default()
        };

        let client = ClientBuilder::from(config).build().await.unwrap();
        assert!(client.signature_validator.is_some());
    }

    #[tokio::test]
    async fn registry_configuration_uri_is_loaded() {
        let work_dir = tempfile::tempdir().unwrap();
        let registry_path = work_dir.path().join("registries.conf");
        std::fs::write(
            &registry_path,
            r#"[[registry]]
prefix = "blocked.example.com"
blocked = true
"#,
        )
        .unwrap();
        let config = ImageConfig {
            work_dir: work_dir.path().to_path_buf(),
            registry_configuration_uri: Some(format!("file://{}", registry_path.display())),
            ..Default::default()
        };

        let client = ClientBuilder::from(config).build().await.unwrap();
        let error = client
            .registry_handler
            .unwrap()
            .process(Reference::from_str("blocked.example.com/repo:tag").unwrap())
            .unwrap_err();
        assert!(error.to_string().contains("blocked by registry rule"));
    }
}
