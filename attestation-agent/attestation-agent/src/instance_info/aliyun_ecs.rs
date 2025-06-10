use anyhow::{Context, Result};
use reqwest::header::{HeaderMap, HeaderValue};
use serde::{Deserialize, Serialize};
use log::debug;

use super::InstanceInfoFetcher;

const BASE_URL: &str = "http://100.100.100.200/latest";
const TTL_SECONDS: &str = "300";

pub struct AliyunEcsInfo {}

#[async_trait::async_trait]
impl InstanceInfoFetcher for AliyunEcsInfo {
    async fn get_instance_info(&self) -> Result<String> {
        let metadata_client = MetadataClient::new();
        let ecs_info = metadata_client.get_ecs_info().await?;
        let ecs_info_str = serde_json::to_string(&ecs_info)?;
        Ok(ecs_info_str)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EcsInfo {
    pub instance_id: Option<String>,
    pub instance_name: Option<String>,
    pub owner_account_id: Option<String>,
    pub image_id: Option<String>,
}

pub struct MetadataClient {
    client: reqwest::Client,
}

impl MetadataClient {
    pub fn new() -> Self {
        MetadataClient {
            client: reqwest::Client::new(),
        }
    }

    pub async fn get_ecs_info(&self) -> Result<Option<EcsInfo>> {
        let token = match self.get_metadata_token().await {
            Ok(token) => token,
            Err(e) => {
                debug!("Error getting token: {}, maybe not in ecs", e);
                return Ok(None);
            },
        };

        let instance_id = self.get_instance_metadata(&token, "instance-id").await?;
        let instance_name = self.get_instance_metadata(&token, "instance/instance-name").await?;
        let owner_account_id = self.get_instance_metadata(&token, "owner-account-id").await?;
        let image_id = self.get_instance_metadata(&token, "image-id").await?;

        Ok(Some(EcsInfo {
            instance_id,
            instance_name,
            owner_account_id,
            image_id,
        }))
    }

    async fn get_metadata_token(&self) -> Result<String> {
        let mut headers = HeaderMap::new();
        headers.insert(
            "X-aliyun-ecs-metadata-token-ttl-seconds",
            HeaderValue::from_static(TTL_SECONDS),
        );

        let response = self
            .client
            .put(&format!("{}/api/token", BASE_URL))
            .headers(headers)
            .send()
            .await
            .context("Failed to send request for metadata token")?;

        if response.status().is_success() {
            let token = response.text().await.context("Failed to read token response text")?;
            Ok(token)
        } else {
            Err(anyhow::anyhow!("Failed to get metadata token: {}", response.status()))
        }
    }

    async fn get_instance_metadata(
        &self,
        token: &str,
        metadata_field: &str,
    ) -> Result<Option<String>> {
        let response = self
            .client
            .get(&format!("{}/meta-data/{}", BASE_URL, metadata_field))
            .header("X-aliyun-ecs-metadata-token", token)
            .send()
            .await
            .context(format!("Failed to send request for instance metadata: {}", metadata_field))?;

        let mut metadata = None;
        if response.status().is_success() {
            metadata = Some(response.text().await.context("Failed to read metadata response text")?);
        } else {
            debug!("Failed to get instance metadata: {}, reason: {}", metadata_field, response.status())
        }

        return Ok(metadata)
    }
}