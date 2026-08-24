// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! Abstraction for KBCs as a KMS plugin.

#[cfg(feature = "kbs")]
mod cc_kbc;

#[cfg(feature = "sev")]
mod sev;

mod offline_fs;

use std::{env, sync::Arc};

use async_trait::async_trait;
use attestation_agent::config::aa_kbc_params::AaKbcParams;
pub use resource_uri::ResourceUri;
use tokio::sync::Mutex;
#[cfg(feature = "sev")]
use tokio::sync::OnceCell;

use crate::kms::{Annotations, Error, Getter, Result};

enum RealClient {
    #[cfg(feature = "kbs")]
    Cc(cc_kbc::CcKbc),
    #[cfg(feature = "sev")]
    Sev(sev::OnlineSevKbc),
    OfflineFs(offline_fs::OfflineFsKbc),
}

#[async_trait]
pub trait Kbc: Send + Sync {
    async fn get_resource(&mut self, _rid: ResourceUri) -> Result<Vec<u8>>;
}

/// The online-SEV KBC consumes one-shot guest state while it initializes, so
/// that downstream-only provider must remain a process-wide singleton.  The
/// URI is retained with the client to prevent a later configuration from
/// silently reusing a singleton connected to a different KBS.
#[cfg(feature = "sev")]
static ONLINE_SEV_KBC: OnceCell<(String, Arc<Mutex<RealClient>>)> = OnceCell::const_new();

/// A KBC-backed [`Getter`].
///
/// The upstream cc-KBC and offline-fs-KBC implementations are independently
/// initialized for each client.  This makes construction idempotent and avoids
/// leaking the first CDH configuration into later clients.  Online-SEV keeps
/// its original one-time initialization behavior.
pub struct KbcClient {
    client: Arc<Mutex<RealClient>>,
}

#[async_trait]
impl Getter for KbcClient {
    async fn get_secret(&self, name: &str, _annotations: &Annotations) -> Result<Vec<u8>> {
        let resource_uri = ResourceUri::try_from(name)
            .map_err(|_| Error::KbsClientError(format!("illegal kbs resource uri: {name}")))?;
        let mut client = self.client.lock().await;

        match &mut *client {
            #[cfg(feature = "kbs")]
            RealClient::Cc(c) => c.get_resource(resource_uri).await,
            #[cfg(feature = "sev")]
            RealClient::Sev(c) => c.get_resource(resource_uri).await,
            RealClient::OfflineFs(c) => c.get_resource(resource_uri).await,
        }
    }
}

impl KbcClient {
    pub async fn new() -> Result<Self> {
        let params = env::var("AA_KBC_PARAMS")
            .map_err(|e| Error::KbsClientError(format!("failed to read AA_KBC_PARAMS: {e}")))?;
        let params = AaKbcParams::try_from(params)
            .map_err(|e| Error::KbsClientError(format!("Failed to parse aa_kbc_params: {e:?}")))?;

        let client = match &params.kbc[..] {
            #[cfg(feature = "kbs")]
            "cc_kbc" => {
                let aa_socket = env::var("AA_SOCKET").map_err(|e| {
                    Error::KbsClientError(format!("failed to read AA_SOCKET: {e}"))
                })?;
                Arc::new(Mutex::new(RealClient::Cc(
                    cc_kbc::CcKbc::new(&params.uri, &aa_socket).await?,
                )))
            }
            #[cfg(feature = "sev")]
            "online_sev_kbc" => {
                let (initialized_uri, client) = ONLINE_SEV_KBC
                    .get_or_try_init(|| async {
                        let client = sev::OnlineSevKbc::new(&params.uri).await?;
                        Ok::<_, Error>((
                            params.uri.clone(),
                            Arc::new(Mutex::new(RealClient::Sev(client))),
                        ))
                    })
                    .await?;
                if initialized_uri != &params.uri {
                    return Err(Error::KbsClientError(format!(
                        "online-sev-kbc is already initialized for {initialized_uri}; refusing to reuse it for {}",
                        params.uri
                    )));
                }
                client.clone()
            }
            "offline_fs_kbc" => Arc::new(Mutex::new(RealClient::OfflineFs(
                offline_fs::OfflineFsKbc::new().await?,
            ))),
            others => {
                return Err(Error::KbsClientError(format!(
                    "unknown kbc name {others}, only support `cc_kbc`(feature `kbs`), `online_sev_kbc` (feature `sev`) and `offline_fs_kbc`."
                )))
            }
        };

        Ok(Self { client })
    }
}

#[cfg(test)]
mod tests {
    use std::{env, ffi::OsString, sync::Arc};

    use serial_test::serial;

    use super::KbcClient;

    struct EnvRestore {
        kbc_params: Option<OsString>,
        aa_socket: Option<OsString>,
    }

    impl EnvRestore {
        fn capture() -> Self {
            Self {
                kbc_params: env::var_os("AA_KBC_PARAMS"),
                aa_socket: env::var_os("AA_SOCKET"),
            }
        }
    }

    impl Drop for EnvRestore {
        fn drop(&mut self) {
            match self.kbc_params.take() {
                Some(value) => env::set_var("AA_KBC_PARAMS", value),
                None => env::remove_var("AA_KBC_PARAMS"),
            }
            match self.aa_socket.take() {
                Some(value) => env::set_var("AA_SOCKET", value),
                None => env::remove_var("AA_SOCKET"),
            }
        }
    }

    #[tokio::test]
    #[serial]
    async fn offline_fs_does_not_require_aa_socket() {
        let _restore = EnvRestore::capture();
        env::set_var("AA_KBC_PARAMS", "offline_fs_kbc::");
        env::remove_var("AA_SOCKET");

        KbcClient::new()
            .await
            .expect("offline-fs-kbc must not require AA_SOCKET");
    }

    #[tokio::test]
    #[serial]
    async fn idempotent_kbcs_are_initialized_per_client() {
        let _restore = EnvRestore::capture();
        env::set_var("AA_KBC_PARAMS", "offline_fs_kbc::");
        env::remove_var("AA_SOCKET");

        let first = KbcClient::new().await.unwrap();
        let second = KbcClient::new().await.unwrap();
        assert!(!Arc::ptr_eq(&first.client, &second.client));
    }

    #[tokio::test]
    #[serial]
    async fn missing_kbc_configuration_returns_error() {
        let _restore = EnvRestore::capture();
        env::remove_var("AA_KBC_PARAMS");
        env::remove_var("AA_SOCKET");

        let error = KbcClient::new()
            .await
            .err()
            .expect("must reject missing KBC");
        assert!(error.to_string().contains("AA_KBC_PARAMS"));
    }

    #[cfg(feature = "kbs")]
    #[tokio::test]
    #[serial]
    async fn cc_kbc_requires_aa_socket() {
        let _restore = EnvRestore::capture();
        env::set_var("AA_KBC_PARAMS", "cc_kbc::http://127.0.0.1:8080");
        env::remove_var("AA_SOCKET");

        let error = KbcClient::new()
            .await
            .err()
            .expect("cc-kbc must require AA_SOCKET");
        assert!(error.to_string().contains("AA_SOCKET"));
    }
}
