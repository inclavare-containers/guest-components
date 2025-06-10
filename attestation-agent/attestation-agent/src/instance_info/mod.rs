use anyhow::{bail, Result};

pub mod aliyun_ecs;
pub mod instance_heartbeat;

/// InstanceInfoFetcher trait for getting AA instance information
#[async_trait::async_trait]
pub trait InstanceInfoFetcher {
    /// Get AA instance information
    ///
    /// # Returns
    ///
    /// Returns a Result<String> containing AA instance information
    /// - Ok(String): Returns instance information string on success
    /// - Err: Returns error information on failure
    async fn get_instance_info(&self) -> Result<String>;
}

/// Get AA instance info by type
pub async fn get_instance_info(instance_type: &str) -> Result<String> {
    match instance_type {
        "aliyun_ecs" => {
            let aliyun_ecs = aliyun_ecs::AliyunEcsInfo {};
            aliyun_ecs.get_instance_info().await
        }
        _ => bail!("Unsupported instance type: {}", instance_type),
    }
}

pub use instance_heartbeat::InstanceHeartbeat;

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_aa_instance_info_get_instance_info_invalid_type() {
        let result = get_instance_info("invalid_type").await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Unsupported instance type"));
    }
}
