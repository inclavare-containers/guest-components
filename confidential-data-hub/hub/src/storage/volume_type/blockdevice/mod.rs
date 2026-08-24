// Copyright (c) 2024 Intel
// Copyright (c) 2025 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! # BlockDevice SecureStorage

pub mod error;

use super::SecureMount;
use crate::{
    secret,
    storage::drivers::zfs::{export_zpool, ZfsParameters},
};

use crate::kms;
use crate::kms::{Annotations, ProviderSettings};
use async_trait::async_trait;
use error::{BlockDeviceError, Result};
use log::{debug, info};
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use strum::Display;
use tokio::{
    fs::File,
    io::{AsyncBufReadExt, BufReader},
};
use zeroize::Zeroizing;

use resource_uri::ResourceUri;

#[derive(Serialize, Deserialize, Display, Debug, PartialEq, Eq)]
#[serde(tag = "encryptionType")]
pub enum BlockDeviceEncryptType {
    #[strum(serialize = "luks2")]
    #[serde(rename = "luks2")]
    Luks2(crate::storage::drivers::luks2::Luks2MountParameters),

    #[strum(serialize = "zfs")]
    #[serde(rename = "zfs")]
    Zfs(ZfsParameters),
}

async fn get_plaintext_key(key_uri: &str) -> Result<Zeroizing<Vec<u8>>> {
    let key = if key_uri.starts_with("sealed.") {
        debug!("get key with sealed secret");
        secret::unseal_secret(key_uri.as_bytes())
            .await
            .map_err(|source| BlockDeviceError::GetKeyFailed {
                source: source.into(),
            })?
    } else if ResourceUri::try_from(key_uri).is_ok() {
        debug!("get key from kbs");
        kms::new_getter("kbs", ProviderSettings::default())
            .await
            .map_err(|source| BlockDeviceError::GetKeyFailed {
                source: source.into(),
            })?
            .get_secret(key_uri, &Annotations::default())
            .await
            .map_err(|source| BlockDeviceError::GetKeyFailed {
                source: source.into(),
            })?
    } else if key_uri.starts_with("file://") {
        debug!("get key from local path");
        let path = key_uri.trim_start_matches("file://");
        tokio::fs::read(path).await?
    } else {
        return Err(BlockDeviceError::IllegalKeyScheme);
    };

    Ok(Zeroizing::new(key))
}

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone, Copy)]
pub enum SourceType {
    /// The source is an encrypted device.
    #[serde(rename = "encrypted")]
    Encrypted,

    /// The source is an empty device.
    #[serde(rename = "empty")]
    Empty,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct BlockDeviceParameters {
    /// The device number, formatted as "MAJ:MIN".
    /// This is used to identify the block device.
    ///
    /// At least one of `device_id` or `device_path` must be set.
    /// If both are set, `device_id` will be used.
    #[serde(rename = "deviceId")]
    pub device_id: Option<String>,

    /// The path of the source device path. The data of
    /// the device will be encrypted.
    ///
    /// At least one of `device_id` or `device_path` must be set.
    /// If both are set, `device_id` will be used.
    #[serde(rename = "devicePath")]
    pub device_path: Option<String>,

    /// The type of the source.
    #[serde(rename = "sourceType")]
    pub source_type: SourceType,

    /// The key to encrypt or decrypt the device.
    ///
    /// If not set, generate a random 4096-byte key.
    ///
    /// Legal values are starting with:
    /// - "sealed.": Get the encryption key from the sealed secret.
    /// - "kbs://": Get the encryption key from the KBS.
    /// - "file://": Get the encryption key from the local file.
    pub key: Option<String>,

    /// The encryption type. Currently, only LUKS is supported.
    #[serde(flatten)]
    pub encryption_type: BlockDeviceEncryptType,
}

#[derive(Default)]
pub struct BlockDevice {
    /// Symlinks created for device targets.
    symlinks: Vec<String>,

    /// Detached LUKS2 headers created for ephemeral storage.
    luks_headers: Vec<String>,

    /// The mount points created by the operation. This is used to
    /// clean up.
    mount_points: Vec<String>,

    /// The cryptsetup pairs created by the operation. This is used to
    /// clean up.
    ///
    cryptsetup_names: Vec<String>,

    /// The zfs pools created by the operation. This is used to
    /// clean up.
    zfs_pools: Vec<String>,
}

impl BlockDevice {
    /// The BlockDevice mount operation will be performed according to the parameters in the options.
    async fn real_mount(
        &mut self,
        options: &HashMap<String, String>,
        _flags: &[String],
        mount_point: &str,
    ) -> Result<()> {
        // construct BlockDeviceParameters
        let parameters = serde_json::to_string(options)?;
        let parameters: BlockDeviceParameters = serde_json::from_str(&parameters)?;

        // 1. get the source device path
        let device_path = match (parameters.device_id, parameters.device_path) {
            (Some(device_id), _) => {
                let (maj, min) = parse_device_id(&device_id)?;
                get_device_path(maj, min).await?
            }
            (_, Some(device_path)) => device_path,
            _ => {
                return Err(BlockDeviceError::NoDeviceSpecified);
            }
        };

        // 2. get key if the parameter is set
        let key = match &parameters.key {
            Some(key) => get_plaintext_key(key).await?,
            None => {
                debug!("generate a random key. All data on the device will be overwritten.");
                {
                    let mut key = vec![0_u8; 4096];
                    rand::rng().fill(&mut key[..]);
                    Zeroizing::new(key)
                }
            }
        };

        // 3. do the workflow according to the source type and target type according to different encryption types
        match parameters.encryption_type {
            BlockDeviceEncryptType::Luks2(luks2_parameters) => {
                let mounted = luks2_parameters
                    .do_mount(&device_path, mount_point, key, parameters.source_type)
                    .await
                    .map_err(|source| BlockDeviceError::Luks2Error { source })?;
                if mounted.target_is_device {
                    self.symlinks.push(mount_point.to_string());
                } else {
                    self.mount_points.push(mount_point.to_string());
                }
                self.cryptsetup_names.push(mounted.mapper_name);
                if let Some(header_path) = mounted.header_path {
                    self.luks_headers.push(header_path);
                }
            }
            BlockDeviceEncryptType::Zfs(zfs_parameters) => {
                self.zfs_pools.push(zfs_parameters.pool.clone());
                zfs_parameters
                    .do_mount(&device_path, mount_point, key, parameters.source_type)
                    .await
                    .map_err(|source| BlockDeviceError::ZfsError { source })?;
            }
        }
        info!("Target path {} mounted successfully", mount_point);
        Ok(())
    }

    /// Unmount the block device from the given `mount_point`.
    pub async fn umount(&mut self) -> Result<()> {
        // 1. unmount the mount points
        for mount_point in &self.mount_points {
            nix::mount::umount(&mount_point[..]).map_err(|source| {
                BlockDeviceError::UmountFailed {
                    mount_point: mount_point.to_string(),
                    source,
                }
            })?;
        }

        // 2. remove symlinks created for device targets.
        for path in &self.symlinks {
            tokio::fs::remove_file(path).await?;
        }

        // 3. close luks2 devices
        for name in &self.cryptsetup_names {
            let formatter = crate::storage::drivers::luks2::Luks2Formatter::default();
            formatter
                .close_device(name)
                .map_err(|source| BlockDeviceError::Luks2Error { source })?;
        }

        // 4. remove detached headers after closing their mappings.
        for path in &self.luks_headers {
            tokio::fs::remove_file(path).await?;
        }

        // 5. export zfs pools. This will release the zpool from the current machine.
        for pool in &self.zfs_pools {
            export_zpool(pool).map_err(|source| BlockDeviceError::ZfsError { source })?;
        }

        Ok(())
    }
}

#[async_trait]
impl SecureMount for BlockDevice {
    /// Mount the block device to the given `mount_point``.
    ///
    /// If `options.encrypt_type` is set to `LUKS2`, the device will be formated as a LUKS-encrypted device.
    /// Then use cryptsetup open the device and mount it to `mount_point` as plaintext.
    ///
    /// This is a wrapper for inner function to convert error type.
    async fn mount(
        &mut self,
        options: &HashMap<String, String>,
        flags: &[String],
        mount_point: &str,
    ) -> super::Result<()> {
        self.real_mount(options, flags, mount_point)
            .await
            .map_err(|e| e.into())
    }
}

fn parse_device_id(device_id: &str) -> Result<(u32, u32)> {
    let parts: Vec<&str> = device_id.split(':').collect();
    if parts.len() != 2 {
        return Err(BlockDeviceError::IllegalDeviceId);
    }
    let major = parts[0]
        .parse::<u32>()
        .map_err(|_| BlockDeviceError::IllegalDeviceId)?;
    let minor = parts[1]
        .parse::<u32>()
        .map_err(|_| BlockDeviceError::IllegalDeviceId)?;
    Ok((major, minor))
}

async fn get_device_path(major: u32, minor: u32) -> Result<String> {
    let uevent_path = format!("/sys/dev/block/{}:{}/uevent", major, minor);
    let file = File::open(uevent_path).await?;
    let reader = BufReader::new(file);
    let mut lines = reader.lines();
    while let Ok(Some(line)) = lines.next_line().await {
        if let Some(line) = line.strip_prefix("DEVNAME=") {
            return Ok(format!("/dev/{}", line));
        }
    }
    Err(BlockDeviceError::NoDeviceFound { major, minor })
}
