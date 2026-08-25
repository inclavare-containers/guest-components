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
        // Normalize the historical downstream request before parsing the
        // upstream block-device schema.
        let options = normalize_options(options)?;
        let parameters = serde_json::to_string(&options)?;
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
        info!("Target path {mount_point} mounted successfully");
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

/// Preserve the original inclavare CDH request while accepting the upstream
/// block-device schema.
///
/// Historical callers use `encryptType=LUKS`, `encryptKey`, and a
/// filesystem-only target. In that schema, the presence of `encryptKey`
/// means the device is already encrypted; otherwise CDH initializes an empty
/// ephemeral device.
fn normalize_options(options: &HashMap<String, String>) -> Result<HashMap<String, String>> {
    if options.contains_key("encryptionType") {
        return Ok(options.clone());
    }

    let Some(encryption_type) = options.get("encryptType") else {
        return Ok(options.clone());
    };
    if !encryption_type.eq_ignore_ascii_case("luks")
        && !encryption_type.eq_ignore_ascii_case("luks2")
    {
        return Err(BlockDeviceError::UnsupportedEncryptionType {
            encryption_type: encryption_type.clone(),
        });
    }

    let mut normalized = options.clone();
    normalized.insert("encryptionType".to_string(), "luks2".to_string());
    normalized
        .entry("targetType".to_string())
        .or_insert_with(|| "fileSystem".to_string());
    normalized
        .entry("filesystemType".to_string())
        .or_insert_with(|| "ext4".to_string());

    if let Some(key) = options.get("encryptKey") {
        normalized
            .entry("key".to_string())
            .or_insert_with(|| key.clone());
        normalized
            .entry("sourceType".to_string())
            .or_insert_with(|| "encrypted".to_string());
    } else {
        normalized
            .entry("sourceType".to_string())
            .or_insert_with(|| "empty".to_string());
    }

    Ok(normalized)
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
    let uevent_path = format!("/sys/dev/block/{major}:{minor}/uevent");
    let file = File::open(uevent_path).await?;
    let reader = BufReader::new(file);
    let mut lines = reader.lines();
    while let Ok(Some(line)) = lines.next_line().await {
        if let Some(line) = line.strip_prefix("DEVNAME=") {
            return Ok(format!("/dev/{line}"));
        }
    }
    Err(BlockDeviceError::NoDeviceFound { major, minor })
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashMap,
        io::Write,
        path::{Path, PathBuf},
    };

    use nix::mount::{mount, umount, MsFlags};
    use serial_test::serial;
    use zeroize::Zeroizing;

    use super::*;
    use crate::storage::{
        drivers::{
            filesystem::{FsFormatter, FsType},
            luks2::{luks_header_path, Luks2Formatter, TargetType},
            run_command,
        },
        volume_type::blockdevice::error::BlockDeviceError,
    };

    const TEST_KEY: &[u8] = b"correct horse battery staple";

    struct CloseDeviceOnDrop(String);

    impl Drop for CloseDeviceOnDrop {
        fn drop(&mut self) {
            let _ = Luks2Formatter::default().close_device(&self.0);
        }
    }

    struct RemoveFileOnDrop(PathBuf);

    impl Drop for RemoveFileOnDrop {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    fn cryptsetup_available() -> bool {
        run_command("cryptsetup", &["--version"], None).is_ok()
    }

    fn unique_mapper_name(prefix: &str) -> String {
        format!(
            "{prefix}-{}-{:016x}",
            std::process::id(),
            rand::random::<u64>()
        )
    }

    fn new_device(size: u64) -> tempfile::NamedTempFile {
        let device = tempfile::NamedTempFile::new().unwrap();
        device.as_file().set_len(size).unwrap();
        device
    }

    fn new_key_file() -> tempfile::NamedTempFile {
        let mut key = tempfile::NamedTempFile::new().unwrap();
        key.write_all(TEST_KEY).unwrap();
        key.flush().unwrap();
        key
    }

    fn key_uri(key: &tempfile::NamedTempFile) -> String {
        format!("file://{}", key.path().display())
    }

    fn luks_options(
        device_path: &str,
        key: &tempfile::NamedTempFile,
        source_type: &str,
        target_type: &str,
        mapper_name: &str,
    ) -> HashMap<String, String> {
        HashMap::from([
            ("devicePath".to_string(), device_path.to_string()),
            ("sourceType".to_string(), source_type.to_string()),
            ("targetType".to_string(), target_type.to_string()),
            ("encryptionType".to_string(), "luks2".to_string()),
            ("key".to_string(), key_uri(key)),
            ("mapperName".to_string(), mapper_name.to_string()),
            ("dataIntegrity".to_string(), "false".to_string()),
        ])
    }

    #[test]
    fn parse_device_id_requires_exact_major_minor_pair() {
        assert_eq!(parse_device_id("8:0").unwrap(), (8, 0));
        assert!(matches!(
            parse_device_id("8"),
            Err(BlockDeviceError::IllegalDeviceId)
        ));
        assert!(matches!(
            parse_device_id("8:0:1"),
            Err(BlockDeviceError::IllegalDeviceId)
        ));
        assert!(matches!(
            parse_device_id("major:minor"),
            Err(BlockDeviceError::IllegalDeviceId)
        ));
    }

    #[test]
    fn upstream_luks2_schema_defaults_filesystem_to_ext4() {
        let options = HashMap::from([
            ("devicePath".to_string(), "/dev/loop0".to_string()),
            ("sourceType".to_string(), "empty".to_string()),
            ("targetType".to_string(), "fileSystem".to_string()),
            ("encryptionType".to_string(), "luks2".to_string()),
        ]);
        let parameters: BlockDeviceParameters =
            serde_json::from_str(&serde_json::to_string(&options).unwrap()).unwrap();
        match parameters.encryption_type {
            BlockDeviceEncryptType::Luks2(parameters) => assert!(matches!(
                parameters.target_type,
                TargetType::FileSystem {
                    filesystem_type: FsType::Ext4,
                    ..
                }
            )),
            other => panic!("unexpected encryption type: {other:?}"),
        }
    }

    #[test]
    fn legacy_ephemeral_request_maps_to_empty_luks2_filesystem() {
        let options = HashMap::from([
            ("deviceId".to_string(), "7:0".to_string()),
            ("encryptType".to_string(), "LUKS".to_string()),
            ("dataIntegrity".to_string(), "true".to_string()),
        ]);
        let normalized = normalize_options(&options).unwrap();
        assert_eq!(normalized["encryptionType"], "luks2");
        assert_eq!(normalized["sourceType"], "empty");
        assert_eq!(normalized["targetType"], "fileSystem");
        assert_eq!(normalized["filesystemType"], "ext4");
        assert!(!normalized.contains_key("key"));
    }

    #[test]
    fn legacy_persistent_request_preserves_key_and_custom_fields() {
        let options = HashMap::from([
            ("deviceId".to_string(), "7:0".to_string()),
            ("encryptType".to_string(), "luks".to_string()),
            (
                "encryptKey".to_string(),
                "kbs:///repository/storage-key".to_string(),
            ),
            ("mapperName".to_string(), "stable-name".to_string()),
        ]);
        let normalized = normalize_options(&options).unwrap();
        assert_eq!(normalized["sourceType"], "encrypted");
        assert_eq!(normalized["key"], "kbs:///repository/storage-key");
        assert_eq!(normalized["mapperName"], "stable-name");
    }

    #[test]
    fn legacy_unknown_encryption_type_is_rejected() {
        let options = HashMap::from([("encryptType".to_string(), "unknown".to_string())]);
        assert!(matches!(
            normalize_options(&options),
            Err(BlockDeviceError::UnsupportedEncryptionType { .. })
        ));
    }

    #[tokio::test]
    async fn invalid_data_integrity_retains_the_full_error_chain() {
        let options = HashMap::from([
            ("devicePath".to_string(), "/not/a/device".to_string()),
            ("sourceType".to_string(), "empty".to_string()),
            ("targetType".to_string(), "device".to_string()),
            ("encryptionType".to_string(), "luks2".to_string()),
            ("dataIntegrity".to_string(), "invalid".to_string()),
        ]);
        let error = BlockDevice::default()
            .real_mount(&options, &[], "/tmp/not-created")
            .await
            .unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("dataIntegrity"), "{message}");
        assert!(message.contains("true"), "{message}");
        assert!(message.contains("false"), "{message}");
    }

    #[tokio::test]
    #[serial]
    async fn empty_luks2_device_target_cleans_mapper_symlink_and_header() {
        if !cryptsetup_available() {
            return;
        }

        let device = new_device(128 * 1024 * 1024);
        let key = new_key_file();
        let mapper_name = unique_mapper_name("cdh-device");
        let _mapper_guard = CloseDeviceOnDrop(mapper_name.clone());
        let header_path = PathBuf::from(luks_header_path(device.path().to_str().unwrap()));
        let _header_guard = RemoveFileOnDrop(header_path.clone());
        let target_dir = tempfile::TempDir::new().unwrap();
        let target = target_dir.path().join("plaintext-device");
        let options = luks_options(
            device.path().to_str().unwrap(),
            &key,
            "empty",
            "device",
            &mapper_name,
        );
        let mut block_device = BlockDevice::default();

        block_device
            .real_mount(&options, &[], target.to_str().unwrap())
            .await
            .unwrap();
        assert!(target.is_symlink());
        assert!(Path::new(&format!("/dev/mapper/{mapper_name}")).exists());
        assert!(header_path.exists());

        block_device.umount().await.unwrap();
        assert!(!target.exists());
        assert!(!Path::new(&format!("/dev/mapper/{mapper_name}")).exists());
        assert!(!header_path.exists());
    }

    #[tokio::test]
    #[serial]
    async fn empty_luks2_ext4_filesystem_honors_mkfs_options() {
        if !cryptsetup_available() {
            return;
        }

        let device = new_device(256 * 1024 * 1024);
        let key = new_key_file();
        let mapper_name = unique_mapper_name("cdh-ext4");
        let _mapper_guard = CloseDeviceOnDrop(mapper_name.clone());
        let header_path = PathBuf::from(luks_header_path(device.path().to_str().unwrap()));
        let _header_guard = RemoveFileOnDrop(header_path);
        let mount_point = tempfile::TempDir::new().unwrap();
        let mut options = luks_options(
            device.path().to_str().unwrap(),
            &key,
            "empty",
            "fileSystem",
            &mapper_name,
        );
        options.insert("mkfsOpts".to_string(), "-m 0".to_string());
        let mut block_device = BlockDevice::default();

        block_device
            .real_mount(&options, &[], mount_point.path().to_str().unwrap())
            .await
            .unwrap();
        tokio::fs::write(mount_point.path().join("confidential.txt"), b"secret")
            .await
            .unwrap();
        assert_eq!(
            tokio::fs::read(mount_point.path().join("confidential.txt"))
                .await
                .unwrap(),
            b"secret"
        );
        block_device.umount().await.unwrap();
    }

    #[tokio::test]
    #[serial]
    async fn preexisting_luks2_ext4_filesystem_is_reopened_without_reformatting() {
        if !cryptsetup_available() {
            return;
        }

        let device = new_device(256 * 1024 * 1024);
        let key_file = new_key_file();
        let key = Zeroizing::new(TEST_KEY.to_vec());
        let formatter = Luks2Formatter::default();
        formatter
            .encrypt_device(device.path().to_str().unwrap(), None, key.clone())
            .unwrap();

        let setup_mapper = unique_mapper_name("cdh-setup");
        formatter
            .open_device(device.path().to_str().unwrap(), None, &setup_mapper, key)
            .unwrap();
        let setup_guard = CloseDeviceOnDrop(setup_mapper.clone());
        let mapped_path = format!("/dev/mapper/{setup_mapper}");
        FsFormatter {
            fs_type: FsType::Ext4,
            force: true,
            args: vec!["-m".to_string(), "0".to_string()],
        }
        .format(&mapped_path)
        .unwrap();
        let setup_mount = tempfile::TempDir::new().unwrap();
        mount(
            Some(mapped_path.as_str()),
            setup_mount.path(),
            Some("ext4"),
            MsFlags::MS_NOATIME,
            None::<&str>,
        )
        .unwrap();
        std::fs::write(setup_mount.path().join("persistent.txt"), b"preserved").unwrap();
        umount(setup_mount.path()).unwrap();
        formatter.close_device(&setup_mapper).unwrap();
        std::mem::forget(setup_guard);

        let mapper_name = unique_mapper_name("cdh-reopen");
        let _mapper_guard = CloseDeviceOnDrop(mapper_name.clone());
        let mount_point = tempfile::TempDir::new().unwrap();
        let options = luks_options(
            device.path().to_str().unwrap(),
            &key_file,
            "encrypted",
            "fileSystem",
            &mapper_name,
        );
        let mut block_device = BlockDevice::default();
        block_device
            .real_mount(&options, &[], mount_point.path().to_str().unwrap())
            .await
            .unwrap();
        assert_eq!(
            tokio::fs::read(mount_point.path().join("persistent.txt"))
                .await
                .unwrap(),
            b"preserved"
        );
        block_device.umount().await.unwrap();
    }

    #[tokio::test]
    #[serial]
    async fn dm_integrity_ext4_supports_real_io() {
        if !cryptsetup_available() {
            return;
        }

        let device = new_device(512 * 1024 * 1024);
        let key = new_key_file();
        let mapper_name = unique_mapper_name("cdh-integrity");
        let _mapper_guard = CloseDeviceOnDrop(mapper_name.clone());
        let header_path = PathBuf::from(luks_header_path(device.path().to_str().unwrap()));
        let _header_guard = RemoveFileOnDrop(header_path);
        let mount_point = tempfile::TempDir::new().unwrap();
        let mut options = luks_options(
            device.path().to_str().unwrap(),
            &key,
            "empty",
            "fileSystem",
            &mapper_name,
        );
        options.insert("dataIntegrity".to_string(), "true".to_string());
        options.insert(
            "mkfsOpts".to_string(),
            "-O ^has_journal -m 0 -i 163840 -I 128".to_string(),
        );
        let mut block_device = BlockDevice::default();

        block_device
            .real_mount(&options, &[], mount_point.path().to_str().unwrap())
            .await
            .unwrap();
        let data = vec![0x5a; 4 * 1024 * 1024];
        tokio::fs::write(mount_point.path().join("integrity.bin"), &data)
            .await
            .unwrap();
        assert_eq!(
            tokio::fs::read(mount_point.path().join("integrity.bin"))
                .await
                .unwrap(),
            data
        );
        block_device.umount().await.unwrap();
    }
}
