// Copyright (c) 2025 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::{bail, Context, Result};
use kbs_types::HashAlgorithm;
use log::warn;
use std::{fs as stdfs, io::Write, path::PathBuf};
use tokio::{fs as async_fs, fs::File, io::AsyncWriteExt};

/// Persistent storage for the software runtime measurement register.
pub const MEASURE_REGISTER_PATH: &str = "/run/attestation-agent/system_measure_register";

pub const HASH_ALG: HashAlgorithm = HashAlgorithm::Sha384;
pub const MEASURE_DIGEST_LEN: usize = 48;

/// A minimal software-backed measurement register used by the system attester.
#[derive(Debug)]
pub struct MeasureRegister {
    path: PathBuf,
}

impl MeasureRegister {
    pub fn new(path: &str) -> Self {
        let path: PathBuf = PathBuf::from(path);
        // If the file does not exist, create with zero digest.
        if !path.exists() {
            if let Some(parent) = path.parent() {
                if let Err(e) = stdfs::create_dir_all(parent) {
                    warn!("Create system measure register dir failed: {e}");
                }
            }
            let zeros = vec![0u8; MEASURE_DIGEST_LEN];
            if let Err(e) = stdfs::File::create(&path)
                .and_then(|mut f| f.write_all(hex::encode(zeros).as_bytes()))
            {
                warn!("Init system measure register file failed: {e}");
            }
        }

        Self { path }
    }

    /// Read current register value as hex string.
    pub async fn current_hex(&self) -> Result<String> {
        let content = tokio::fs::read(&self.path).await.with_context(|| {
            format!(
                "read system measure register file failed, Delete {} and AAEL file then restart AA to reset.",
                self.path.display()
            )
        })?;
        let trimmed = String::from_utf8_lossy(&content).trim().to_owned();
        if trimmed.is_empty() {
            bail!(
                "System measure register is empty. Delete {} and AAEL file then restart AA to reset.",
                self.path.display()
            );
        }

        Ok(trimmed)
    }

    /// Decode current register value into bytes, validating format and length.
    pub async fn current_value(&self) -> Result<Vec<u8>> {
        let hex = self.current_hex().await?;
        let decoded = hex::decode(hex)
            .with_context(|| format!("decode system measure register {}", self.path.display()))?;

        if decoded.len() != MEASURE_DIGEST_LEN {
            bail!(
                "System measure register length {} != {}. Delete {} and AAEL file then restart AA to reset.",
                decoded.len(),
                MEASURE_DIGEST_LEN,
                self.path.display()
            );
        }

        Ok(decoded)
    }

    pub async fn store(&self, value: &[u8]) -> Result<()> {
        if value.len() != MEASURE_DIGEST_LEN {
            bail!(
                "Invalid measurement length {}, expected {}",
                value.len(),
                MEASURE_DIGEST_LEN
            );
        }

        if let Some(parent) = self.path.parent() {
            async_fs::create_dir_all(parent).await.with_context(|| {
                format!("create measure register parent dir {}", parent.display())
            })?;
        }

        let mut file = File::create(&self.path)
            .await
            .with_context(|| format!("create measure register file {}", self.path.display()))?;
        let encoded = hex::encode(value);
        file.write_all(encoded.as_bytes())
            .await
            .with_context(|| format!("write measure register {}", self.path.display()))?;
        file.sync_all()
            .await
            .with_context(|| format!("sync measure register {}", self.path.display()))?;

        Ok(())
    }

    /// Extend the register with the provided digest and persist the new value.
    /// Caller guarantees the input length matches HASH_ALG.
    pub async fn extend(&self, event_digest: &[u8; MEASURE_DIGEST_LEN]) -> Result<Vec<u8>> {
        let mut material = self.current_value().await?;
        material.extend_from_slice(event_digest);

        let updated = HASH_ALG.digest(&material);
        self.store(&updated).await?;

        Ok(updated)
    }
}
