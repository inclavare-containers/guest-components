use anyhow::{Context, Result};
use log::{debug, warn};
use reqwest::header::{HeaderMap, HeaderValue};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::ErrorKind;
use std::process::Command;

use super::InstanceInfoFetcher;

const BASE_URL: &str = "http://100.100.100.200/latest";
const TTL_SECONDS: &str = "300";
const PRODUCT_SERIAL_PATHS: [&str; 2] = [
    "/sys/devices/virtual/dmi/id/product_serial",
    "/sys/class/dmi/id/product_serial",
];

pub struct AliyunEcsInfo {}

#[async_trait::async_trait]
impl InstanceInfoFetcher for AliyunEcsInfo {
    async fn get_instance_info(&self) -> Result<String> {
        let metadata_client = MetadataClient::new();
        let ecs_info = match metadata_client.get_ecs_info().await {
            Ok(Some(info)) => Some(info),
            Ok(None) => {
                warn!("ECS metadata is unavailable; falling back to local system information");
                build_local_ecs_info()
            }
            Err(err) => {
                warn!(
                    "Failed to retrieve ECS metadata: {err}. Falling back to local system information"
                );
                build_local_ecs_info()
            }
        };
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

impl Default for MetadataClient {
    fn default() -> Self {
        Self::new()
    }
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
            }
        };

        let instance_id = self.get_instance_metadata(&token, "instance-id").await?;
        let instance_name = self
            .get_instance_metadata(&token, "instance/instance-name")
            .await?;
        let owner_account_id = self
            .get_instance_metadata(&token, "owner-account-id")
            .await?;
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
            .put(format!("{BASE_URL}/api/token"))
            .headers(headers)
            .send()
            .await
            .context("Failed to send request for metadata token")?;

        if response.status().is_success() {
            let token = response
                .text()
                .await
                .context("Failed to read token response text")?;
            Ok(token)
        } else {
            Err(anyhow::anyhow!(
                "Failed to get metadata token: {}",
                response.status()
            ))
        }
    }

    async fn get_instance_metadata(
        &self,
        token: &str,
        metadata_field: &str,
    ) -> Result<Option<String>> {
        let response = self
            .client
            .get(format!("{BASE_URL}/meta-data/{metadata_field}"))
            .header("X-aliyun-ecs-metadata-token", token)
            .send()
            .await
            .context(format!(
                "Failed to send request for instance metadata: {}",
                metadata_field
            ))?;

        let mut metadata = None;
        if response.status().is_success() {
            metadata = Some(
                response
                    .text()
                    .await
                    .context("Failed to read metadata response text")?,
            );
        } else {
            debug!(
                "Failed to get instance metadata: {}, reason: {}",
                metadata_field,
                response.status()
            )
        }

        Ok(metadata)
    }
}

fn build_local_ecs_info() -> Option<EcsInfo> {
    let instance_id = match get_system_serial_number() {
        Some(id) => Some(id),
        None => {
            warn!("Unable to read system serial number for instance id fallback");
            None
        }
    };

    let instance_name = match get_system_fqdn() {
        Some(name) => Some(name),
        None => {
            warn!("Unable to read system FQDN for instance name fallback");
            None
        }
    };

    if instance_id.is_none() && instance_name.is_none() {
        None
    } else {
        Some(EcsInfo {
            instance_id,
            instance_name,
            owner_account_id: None,
            image_id: None,
        })
    }
}

fn get_system_serial_number() -> Option<String> {
    for path in PRODUCT_SERIAL_PATHS {
        match fs::read_to_string(path) {
            Ok(serial) => {
                let trimmed = serial.trim();
                if !trimmed.is_empty() && trimmed != "None" {
                    return Some(trimmed.to_string());
                }
            }
            Err(err) if err.kind() == ErrorKind::NotFound => {}
            Err(err) => debug!("Failed to read serial number from {path}: {err}"),
        }
    }

    match Command::new("dmidecode")
        .args(["-s", "system-serial-number"])
        .output()
    {
        Ok(output) if output.status.success() => {
            let serial = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !serial.is_empty() {
                return Some(serial);
            }
        }
        Ok(output) => debug!("dmidecode returned status {}", output.status),
        Err(err) => debug!("Failed to execute dmidecode for serial number: {err}"),
    }

    None
}

fn get_system_fqdn() -> Option<String> {
    if let Some(fqdn) = run_hostname_command(&["-f"]) {
        if fqdn.contains('.') {
            return Some(fqdn);
        }
    }

    run_hostname_command(&[])
}

fn run_hostname_command(args: &[&str]) -> Option<String> {
    match Command::new("hostname").args(args).output() {
        Ok(output) if output.status.success() => {
            let value = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !value.is_empty() {
                return Some(value);
            }
        }
        Ok(output) => {
            debug!(
                "hostname command {:?} failed with status {}",
                args, output.status
            );
        }
        Err(err) => {
            debug!("Failed to execute hostname command {:?}: {err}", args);
        }
    }

    None
}
