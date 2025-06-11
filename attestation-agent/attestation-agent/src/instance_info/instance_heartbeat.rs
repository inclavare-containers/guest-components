// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::{bail, Context, Result};
use log::{debug, warn};

use crate::config::{Config, HeartbeatConfig};

/// Instance heartbeat handler for sending heartbeat to trustee server
pub struct InstanceHeartbeat {
    pub heartbeat_config: HeartbeatConfig,
}

impl InstanceHeartbeat {
    /// Create a new instance of InstanceHeartbeat from config file path
    pub fn new_from_config_path(config_path: Option<&str>) -> Result<Self> {
        let config = match config_path {
            Some(config_path) => Config::try_from(config_path)?,
            None => Config::new()?,
        };
        Ok(Self {
            heartbeat_config: config.aa_instance.heartbeat,
        })
    }

    /// Create a new instance of InstanceHeartbeat from heartbeat config
    pub fn new(heartbeat_config: HeartbeatConfig) -> Self {
        Self { heartbeat_config }
    }

    /// Send heartbeat to the trustee server
    pub async fn send_heartbeat(&self) -> Result<()> {
        // Get trustee URL: prioritize environment variable, then config file
        let trustee_url = std::env::var("TRUSTEE_URL")
            .or_else(|_| {
                self.heartbeat_config
                    .trustee_url
                    .clone()
                    .ok_or(std::env::VarError::NotPresent)
            })
            .with_context(|| "TRUSTEE_URL not found in environment variable or config file")?;

        // Construct heartbeat URL
        let heartbeat_url = format!(
            "{}/aa-instance/heartbeat",
            trustee_url.trim_end_matches('/')
        );

        // Read AA instance info from environment variable
        let aa_instance_info = std::env::var("AA_INSTANCE_INFO").unwrap_or_else(|_| {
            warn!("AA_INSTANCE_INFO environment variable not set, using empty value");
            String::new()
        });

        // Create HTTP client
        let client = reqwest::Client::new();

        // Send POST request with AAInstanceInfo header
        let response = client
            .post(&heartbeat_url)
            .header("AAInstanceInfo", aa_instance_info)
            .send()
            .await
            .with_context(|| format!("Failed to send heartbeat to {}", heartbeat_url))?;

        if response.status().is_success() {
            debug!("Heartbeat sent successfully to {}", heartbeat_url);
            Ok(())
        } else {
            bail!(
                "Heartbeat failed with status: {} for URL: {}",
                response.status(),
                heartbeat_url
            );
        }
    }

    /// Get heartbeat configuration
    pub fn get_heartbeat_config(&self) -> &HeartbeatConfig {
        &self.heartbeat_config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[serial_test::serial]
    async fn test_send_heartbeat_missing_trustee_url() {
        // Clear environment variables and test in isolated scope
        let original_trustee = std::env::var("TRUSTEE_URL").ok();
        let original_aa_info = std::env::var("AA_INSTANCE_INFO").ok();

        std::env::remove_var("TRUSTEE_URL");
        std::env::remove_var("AA_INSTANCE_INFO");

        let heartbeat = InstanceHeartbeat::new_from_config_path(None).unwrap();
        let result = heartbeat.send_heartbeat().await;
        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();

        // Check if the error contains the expected message (more flexible check)
        assert!(error_msg.contains("TRUSTEE_URL not found in environment variable or config file"));

        // Restore original environment variables
        if let Some(val) = original_trustee {
            std::env::set_var("TRUSTEE_URL", val);
        }
        if let Some(val) = original_aa_info {
            std::env::set_var("AA_INSTANCE_INFO", val);
        }
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn test_send_heartbeat_with_mock_env() {
        // Set up environment variables for testing
        std::env::set_var("TRUSTEE_URL", "http://mock-trustee-server.com");
        std::env::set_var("AA_INSTANCE_INFO", r#"{"instance_id":"test-123"}"#);

        let heartbeat = InstanceHeartbeat::new_from_config_path(None).unwrap();

        // This test will fail because the server doesn't exist, but we can verify the URL construction
        let result = heartbeat.send_heartbeat().await;
        assert!(result.is_err());
        // The error should contain the constructed URL
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("http://mock-trustee-server.com/aa-instance/heartbeat"));

        // Clean up
        std::env::remove_var("TRUSTEE_URL");
        std::env::remove_var("AA_INSTANCE_INFO");
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn test_send_heartbeat_with_config_file_url() {
        // Clear environment variable but use config file
        let original_trustee = std::env::var("TRUSTEE_URL").ok();
        std::env::remove_var("TRUSTEE_URL");
        std::env::set_var("AA_INSTANCE_INFO", r#"{"instance_id":"config-test"}"#);

        let heartbeat =
            InstanceHeartbeat::new_from_config_path(Some("tests/aa_instance_info_test.toml"))
                .unwrap();

        // This test will fail because the server doesn't exist, but we can verify the URL construction
        let result = heartbeat.send_heartbeat().await;
        assert!(result.is_err());
        // The error should contain the URL from config file
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("https://test-trustee.example.com/aa-instance/heartbeat"));

        // Clean up
        std::env::remove_var("AA_INSTANCE_INFO");
        if let Some(val) = original_trustee {
            std::env::set_var("TRUSTEE_URL", val);
        }
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn test_send_heartbeat_env_priority_over_config() {
        // Set both environment variable and config file, env should take priority
        std::env::set_var("TRUSTEE_URL", "http://env-priority-server.com");
        std::env::set_var("AA_INSTANCE_INFO", r#"{"instance_id":"priority-test"}"#);

        let heartbeat =
            InstanceHeartbeat::new_from_config_path(Some("tests/aa_instance_info_test.toml"))
                .unwrap();

        // This test will fail because the server doesn't exist, but we can verify the URL construction
        let result = heartbeat.send_heartbeat().await;
        assert!(result.is_err());
        // The error should contain the URL from environment variable, not config file
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("http://env-priority-server.com/aa-instance/heartbeat"));

        // Clean up
        std::env::remove_var("TRUSTEE_URL");
        std::env::remove_var("AA_INSTANCE_INFO");
    }
}
