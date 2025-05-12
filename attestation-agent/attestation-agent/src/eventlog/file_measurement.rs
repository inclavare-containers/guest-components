// Copyright (c) 2025 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use std::collections::HashSet;

use anyhow::Result;
use crypto::HashAlgorithm;
use glob::glob;
use log::{debug, info, warn};
use tokio::sync::Mutex;

use crate::config;
use crate::eventlog::{Content, EventLog, LogEntry};

pub struct FileMeasurer<'a> {
    eventlog: &'a Mutex<EventLog>,
    config: config::FileMeasurementConfig,
    hash_alg: HashAlgorithm,
}

impl<'a> FileMeasurer<'a> {
    pub fn new(
        eventlog: &'a Mutex<EventLog>,
        config: config::FileMeasurementConfig,
        hash_alg: HashAlgorithm,
    ) -> Self {
        Self {
            eventlog,
            config,
            hash_alg,
        }
    }

    pub async fn measure_files_from_config(&self) -> Result<()> {
        let pcr_index = self.config.pcr_index;
        let domain = &self.config.domain;
        let operation = &self.config.operation;

        info!(
            "Starting batch file measurement with PCR index: {}",
            pcr_index
        );

        let mut measured_files = HashSet::new();

        for pattern in &self.config.files {
            debug!("Processing pattern: {}", pattern);

            match glob(pattern) {
                Ok(entries) => {
                    for entry in entries {
                        match entry {
                            Ok(path) => {
                                if path.is_file() {
                                    let path_str = path.to_string_lossy().to_string();
                                    if measured_files.insert(path_str.clone()) {
                                        self.measure_single_file(
                                            &path_str,
                                            domain,
                                            operation,
                                            pcr_index,
                                            self.hash_alg,
                                        )
                                        .await?;
                                    } else {
                                        debug!("Skipping already measured file: {}", path_str);
                                    }
                                }
                            }
                            Err(e) => {
                                warn!(
                                    "Error while accessing path matched by pattern '{}': {}",
                                    pattern, e
                                );
                            }
                        }
                    }
                }
                Err(e) => {
                    warn!("Invalid glob pattern '{}': {}", pattern, e);
                }
            }
        }

        info!(
            "Batch file measurement completed successfully. Measured {} unique files",
            measured_files.len()
        );
        Ok(())
    }

    async fn measure_single_file(
        &self,
        file_path: &str,
        domain: &str,
        operation: &str,
        pcr_index: u64,
        hash_alg: HashAlgorithm,
    ) -> Result<()> {
        debug!("Measuring file: {}", file_path);
        match tokio::fs::read(file_path).await {
            Ok(content) => {
                let file_hash = hash_alg.digest(&content);
                let content_str = format!("{}:{}", file_path, hex::encode(file_hash));

                debug!("Extending measurement for file: {}", file_path);

                let content: Content = content_str.as_str().try_into()?;
                let log_entry = LogEntry::Event {
                    domain,
                    operation,
                    content,
                };

                self.eventlog
                    .lock()
                    .await
                    .extend_entry(log_entry, pcr_index)
                    .await?;
            }
            Err(e) => {
                warn!("Failed to read file for measurement {}: {}", file_path, e);
            }
        }

        Ok(())
    }
}
