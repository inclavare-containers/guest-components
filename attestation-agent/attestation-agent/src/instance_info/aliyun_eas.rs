// Copyright (c) 2024 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0

use anyhow::Result;
use serde::{Deserialize, Serialize};

use super::InstanceInfoFetcher;

pub struct AliyunEasInfo {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EasInfo {
    pub eas_model_id: String,
    pub eas_instance_id: String,
}

impl EasInfo {
    fn from_env() -> Self {
        let eas_model_id = std::env::var("EAS_MODEL_ID").unwrap_or_default();
        let eas_instance_id = std::env::var("EAS_INSTANCE_ID").unwrap_or_default();

        Self {
            eas_model_id,
            eas_instance_id,
        }
    }
}

#[async_trait::async_trait]
impl InstanceInfoFetcher for AliyunEasInfo {
    async fn get_instance_info(&self) -> Result<String> {
        let eas_info = EasInfo::from_env();
        let eas_info_str = serde_json::to_string(&eas_info)?;
        Ok(eas_info_str)
    }
}
