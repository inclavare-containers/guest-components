// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use std::collections::HashMap;

use async_trait::async_trait;
use attester::{detect_attestable_devices, detect_tee_type, BoxedAttester, TeeEvidence};
use kbs_types::Tee;

use super::EvidenceProvider;

use crate::{Error, Result};

pub struct NativeEvidenceProvider {
    primary_tee: Tee,
    primary_attester: BoxedAttester,
    additional_attesters: Vec<(Tee, BoxedAttester)>,
}

impl NativeEvidenceProvider {
    pub fn new() -> Result<Self> {
        Self::new_with_device_attestation(true)
    }

    /// Create a provider, optionally skipping additional device discovery and evidence.
    /// Primary platform attestation is always enabled.
    pub fn new_with_device_attestation(enabled: bool) -> Result<Self> {
        let primary_tee = detect_tee_type();
        let primary_attester = BoxedAttester::try_from(primary_tee).map_err(|e| {
            Error::NativeEvidenceProvider(format!("failed to initialize primary attester: {e}"))
        })?;
        let additional_tees = if enabled {
            detect_attestable_devices()
        } else {
            log::info!("Device attestation is disabled; skipping additional device discovery.");
            Vec::new()
        };
        let additional_attesters = additional_tees
            .into_iter()
            .map(|tee| -> Result<_> {
                let boxed_attester = TryInto::<BoxedAttester>::try_into(tee).map_err(|e| {
                    Error::NativeEvidenceProvider(format!(
                        "failed to initialize additional attester: {e}"
                    ))
                })?;
                Ok((tee, boxed_attester))
            })
            .collect::<Result<Vec<(Tee, BoxedAttester)>>>()?;
        Ok(Self {
            primary_tee,
            primary_attester,
            additional_attesters,
        })
    }
}

#[async_trait]
impl EvidenceProvider for NativeEvidenceProvider {
    async fn primary_evidence(&self, runtime_data: Vec<u8>) -> Result<TeeEvidence> {
        self.primary_attester
            .get_evidence(runtime_data)
            .await
            .map_err(|e| Error::GetEvidence(e.to_string()))
    }

    async fn get_additional_evidence(&self, runtime_data: Vec<u8>) -> Result<String> {
        let mut additional_evidences_map = HashMap::new();

        for (tee, attester) in &self.additional_attesters {
            let evidence = attester
                .get_evidence(runtime_data.to_vec())
                .await
                .map_err(|e| Error::GetEvidence(e.to_string()))?;
            additional_evidences_map.insert(tee, evidence);
        }

        if additional_evidences_map.is_empty() {
            return Ok("".into());
        }

        let additional_evidences = serde_json::to_string(&additional_evidences_map)
            .map_err(|e| Error::GetEvidence(e.to_string()))?;

        Ok(additional_evidences)
    }

    async fn get_tee_type(&self) -> Result<Tee> {
        Ok(self.primary_tee)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn disabled_device_attestation_preserves_primary_evidence() {
        let provider = NativeEvidenceProvider::new_with_device_attestation(false).unwrap();
        assert!(provider.additional_attesters.is_empty());
        assert!(provider
            .get_additional_evidence(vec![0; 48])
            .await
            .unwrap()
            .is_empty());
        assert_eq!(provider.get_tee_type().await.unwrap(), Tee::Sample);
        assert!(provider.primary_evidence(vec![0; 64]).await.is_ok());
    }

    #[tokio::test]
    async fn test_native_evidence_provider() {
        let provider = NativeEvidenceProvider::new().unwrap();
        let tee = provider.get_tee_type().await.unwrap();
        assert_eq!(tee, Tee::Sample);

        let evidence = provider
            .get_additional_evidence(vec![])
            .await
            .expect("failed to get evidence");
        println!("evidence: {evidence}");
    }
}
