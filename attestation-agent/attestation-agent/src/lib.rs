// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use attester::{detect_tee_type, BoxedAttester};
use kbs_types::Tee;
use std::{io::Write, str::FromStr, sync::Arc};
use tokio::sync::{Mutex, RwLock};

pub use attester::InitDataResult;

pub mod config;
mod eventlog;
pub mod instance_info;
pub mod token;

use eventlog::{Content, EventLog, LogEntry};
use log::{debug, info, warn};
use token::*;

use crate::config::Config;

/// Attestation Agent (AA for short) is a rust library crate for attestation procedure
/// in confidential containers. It provides kinds of service APIs related to attestation,
/// including the following
/// - `get_token`: get attestation token from remote services, e.g. attestation services.
/// - `get_evidence`: get hardware TEE signed evidence due to given runtime_data, s.t.
/// report data.
/// - `extend_runtime_measurement`: extend the runtime measurement. This will extend the
/// current hardware runtime measurement register (if any) or PCR for (v)TPM (under
/// development) platforms
/// with a runtime event.
/// - `bind_init_data`: bind the given data slice to the current confidential
/// computing environment. This can be a verify operation or an extension of the TEE
/// evidence
///
/// # Example
///
/// ```no_run
/// use attestation_agent::AttestationAgent;
/// use attestation_agent::AttestationAPIs;
///
/// // initialize with empty config
/// let mut aa = AttestationAgent::new(None).unwrap();
///
/// let _quote = aa.get_evidence(&[0;64]);
/// ```
/// `AttestationAPIs` defines the service APIs of attestation agent that need to make requests
///  to the Relying Party (Key Broker Service) in Confidential Containers.
///
/// For every service API, the `kbc_name` and `kbs_uri` is necessary, `kbc_name` tells
/// attestation agent which KBC module it should use and `kbs_uri` specifies the KBS address.
#[async_trait]
pub trait AttestationAPIs {
    /// Get attestation Token
    async fn get_token(&self, token_type: &str) -> Result<Vec<u8>>;

    /// Get TEE hardware signed evidence that includes the runtime data.
    async fn get_evidence(&self, runtime_data: &[u8]) -> Result<Vec<u8>>;

    /// Extend runtime measurement register
    async fn extend_runtime_measurement(
        &self,
        domain: &str,
        operation: &str,
        content: &str,
        register_index: Option<u64>,
    ) -> Result<()>;

    /// Bind initdata
    async fn bind_init_data(&self, init_data: &[u8]) -> Result<InitDataResult>;

    fn get_tee_type(&self) -> Tee;
}

/// Attestation agent to provide attestation service.
pub struct AttestationAgent {
    pub config: RwLock<Config>,
    attester: Arc<BoxedAttester>,
    eventlog: Option<Mutex<EventLog>>,
    tee: Tee,
}

impl AttestationAgent {
    pub async fn init(&mut self) -> Result<()> {
        let config = self.config.read().await;

        // Initialize AA instance info based on config
        if let Some(ref instance_type) = config.aa_instance.instance_type {
            match instance_info::get_instance_info(instance_type).await {
                Ok(instance_info) => {
                    std::env::set_var("AA_INSTANCE_INFO", instance_info);
                    info!("AA instance info set for type: {}", instance_type);
                }
                Err(e) => {
                    warn!(
                        "Failed to get AA instance info for type {}: {}",
                        instance_type, e
                    );
                }
            }
        }

        if config.eventlog_config.enable_eventlog {
            let eventlog = EventLog::new(
                self.attester.clone(),
                config.eventlog_config.eventlog_algorithm,
                config.eventlog_config.init_pcr,
            )
            .await?;

            self.eventlog = Some(Mutex::new(eventlog));
        }

        Ok(())
    }

    /// Create a new instance of [AttestationAgent].
    pub fn new(config_path: Option<&str>) -> Result<Self> {
        let config = match config_path {
            Some(config_path) => {
                info!("Using AA config file: {config_path}");
                Config::try_from(config_path)?
            }
            None => {
                warn!("No AA config file specified. Using a default configuration.");
                Config::new()?
            }
        };
        let config = RwLock::new(config);

        let tee = detect_tee_type();
        let attester: BoxedAttester = tee.try_into()?;
        let attester = Arc::new(attester);

        Ok(AttestationAgent {
            config,
            attester,
            eventlog: None,
            tee,
        })
    }

    /// This is a workaround API for initdata in CoCo. Once
    /// a better design is implemented we can deprecate the API.
    /// See https://github.com/kata-containers/kata-containers/issues/9468
    pub async fn update_configuration(&self, conf: &str) -> Result<()> {
        let mut tmpfile = tempfile::NamedTempFile::new()?;
        let _ = tmpfile.write(conf.as_bytes())?;
        tmpfile.flush()?;

        let config = Config::try_from(
            tmpfile
                .path()
                .as_os_str()
                .to_str()
                .expect("tempfile will not create non-unicode char"),
            // Here we can use `expect()` because tempfile crate will generate file name
            // only including numbers and alphabet (0-9, a-z, A-Z)
        )?;
        *(self.config.write().await) = config;
        Ok(())
    }
}

#[async_trait]
impl AttestationAPIs for AttestationAgent {
    async fn get_token(&self, token_type: &str) -> Result<Vec<u8>> {
        let token_type = TokenType::from_str(token_type).context("Unsupported token type")?;

        match token_type {
            #[cfg(feature = "kbs")]
            token::TokenType::Kbs => {
                token::kbs::KbsTokenGetter::new(&self.config.read().await.token_configs.kbs)
                    .get_token()
                    .await
            }
            #[cfg(feature = "coco_as")]
            token::TokenType::CoCoAS => {
                token::coco_as::CoCoASTokenGetter::new(
                    &self.config.read().await.token_configs.coco_as,
                )
                .get_token()
                .await
            }
        }
    }

    /// Get TEE hardware signed evidence that includes the runtime data.
    async fn get_evidence(&self, runtime_data: &[u8]) -> Result<Vec<u8>> {
        let evidence = self.attester.get_evidence(runtime_data.to_vec()).await?;
        Ok(evidence.into_bytes())
    }

    /// Extend runtime measurement register. Parameters
    /// - `events`: a event slice. Any single event will be calculated into a hash digest to extend the current
    /// platform's RTMR.
    /// - `register_index`: a target PCR that will be used to extend RTMR. Note that different platform
    /// would have its own strategy to map a PCR index into a architectual RTMR index. If not given, a default one
    /// will be used.
    async fn extend_runtime_measurement(
        &self,
        domain: &str,
        operation: &str,
        content: &str,
        register_index: Option<u64>,
    ) -> Result<()> {
        let Some(ref eventlog) = self.eventlog else {
            bail!("Extend eventlog not enabled when launching!");
        };

        let (pcr, log_entry) = {
            let config = self.config.read().await;

            let pcr = register_index.unwrap_or_else(|| {
                let pcr = config.eventlog_config.init_pcr;
                debug!("No PCR index provided, use default {pcr}");
                pcr
            });

            let content: Content = content.try_into()?;

            let log_entry = LogEntry::Event {
                domain,
                operation,
                content,
            };

            (pcr, log_entry)
        };

        eventlog.lock().await.extend_entry(log_entry, pcr).await?;

        Ok(())
    }

    /// Perform the initdata binding. If current platform does not support initdata
    /// binding, return `InitdataResult::Unsupported`.
    async fn bind_init_data(&self, init_data: &[u8]) -> Result<InitDataResult> {
        self.attester.bind_init_data(init_data).await
    }

    /// Get the tee type of current platform. If no platform is detected,
    /// `Sample` will be returned.
    fn get_tee_type(&self) -> Tee {
        self.tee
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_attestation_agent() {
        let res = AttestationAgent::new(None);
        let aa = res.unwrap();
        assert_eq!(aa.get_tee_type(), Tee::Sample);
        assert!(aa.get_token("kbs").await.is_err());
        assert!(aa.get_evidence(&[]).await.is_ok());
        assert!(aa.bind_init_data(&[]).await.is_ok());
        assert!(aa
            .extend_runtime_measurement("domain", "event", "operation", None)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn test_attestation_agent_with_aa_instance_config() {
        // Clear any existing environment variable first
        std::env::remove_var("AA_INSTANCE_INFO");

        let mut aa = AttestationAgent::new(Some("tests/aa_instance_info_test.toml")).unwrap();
        // Test that initialization doesn't fail even if AA instance info retrieval fails
        // (which is expected in test environment without actual cloud metadata)
        aa.init().await.expect("init should not fail");

        // In test environment, the aliyun_ecs module should fail gracefully
        // and either not set the env var or set it to None/empty
        // Let's just verify the init() call completes successfully
    }
}
