// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! This module helps to get confidential resources that will be used
//! by Confidential Data Hub from KBS, i.e. credentials used by KMSes.

use std::path::PathBuf;

use log::debug;
use tokio::fs;

use crate::{hub::Hub, Error, Result};

/// This directory is used to store all the kbs resources get by CDH's init
/// function, s.t. `[[Credential]]` sections in the config.toml file.
pub const KBS_RESOURCE_STORAGE_DIR: &str = "/run/confidential-containers/cdh";

impl Hub {
    pub(crate) async fn init_kbs_resources(&self) -> Result<()> {
        if self.credentials.is_empty() {
            return Ok(());
        }
        // check the validity of the credential paths.
        for k in self.credentials.keys() {
            if !is_path_valid(k) {
                return Err(Error::InitializationFailed(format!(
                    "illegal path to put credential : {k}"
                )));
            }
        }

        fs::create_dir_all(KBS_RESOURCE_STORAGE_DIR)
            .await
            .map_err(|e| {
                Error::InitializationFailed(format!(
                    "Create {KBS_RESOURCE_STORAGE_DIR} dir failed {e:?}."
                ))
            })?;

        for (k, v) in &self.credentials {
            let content = self.resources.get_resource(v).await.map_err(|e| {
                Error::InitializationFailed(format!("initial resource fetch failed: {e:?}"))
            })?;

            let target_path = PathBuf::from(k);

            debug!(
                "Get config item {v} from the resource backend and put to {}",
                target_path.as_os_str().to_string_lossy()
            );

            if let Some(parent) = target_path.parent() {
                fs::create_dir_all(parent).await.map_err(|e| {
                    Error::InitializationFailed(format!("create dir {parent:?} failed: {e:?}"))
                })?;
            }

            fs::write(target_path, content).await.map_err(|e| {
                Error::InitializationFailed(format!("write initialization resource failed: {e:?}"))
            })?;
        }

        Ok(())
    }
}

/// This function helps to check if a path is valid, including:
/// - it does not have any `..`
/// - it does not have any `.`
/// - it starts with [`KBS_RESOURCE_STORAGE_DIR`]
///
/// The checks are done avoid unexpected path attacks, such as putting a file
/// to random path in the guest.
fn is_path_valid(path: &str) -> bool {
    path.starts_with(KBS_RESOURCE_STORAGE_DIR) && !path.split('/').any(|it| it == ".." || it == ".")
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use crate::auth::kbs::{is_path_valid, KBS_RESOURCE_STORAGE_DIR};

    #[rstest]
    #[case("/etc/config.toml".into(), false)]
    #[case(format!("{KBS_RESOURCE_STORAGE_DIR}/../../config.toml"), false)]
    #[case(format!("{KBS_RESOURCE_STORAGE_DIR}/kms-credential/../../../config.toml"), false)]
    #[case(format!("{KBS_RESOURCE_STORAGE_DIR}/kms-credential/./config.toml"), false)]
    #[case(format!("{KBS_RESOURCE_STORAGE_DIR}/kms-credential/aliyun/config.toml"), true)]
    fn path_valid(#[case] path: String, #[case] res: bool) {
        assert_eq!(is_path_valid(&path), res);
    }
}
