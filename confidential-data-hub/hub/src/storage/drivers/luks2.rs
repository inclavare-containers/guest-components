// Copyright (c) 2024 Intel
// Copyright (c) 2025 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! # LUKS2
//!
//! This module uses the `cryptsetup` binary to encrypt/decrypt a block device with LUKS2.
//!
//! It requires the `cryptsetup` CLI to be installed (e.g. `cryptsetup-bin` on Debian/Ubuntu).
//! No libcryptsetup-rs is linked, so the hub binary can be built as fully static.

use std::path::Path;

use anyhow::{Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as b64, Engine};
use log::{debug, info, warn};
use nix::mount::{mount, MsFlags};
use serde::{Deserialize, Serialize};
use tokio::fs::symlink;
use zeroize::Zeroizing;

use crate::storage::drivers::filesystem::{FsFormatter, FsType};
use crate::storage::drivers::run_command;
use crate::storage::volume_type::blockdevice::SourceType;

/// Algorithm of the integrity hash (dm-integrity format name)
const HMAC_SHA256: &str = "hmac-sha256";

const SECTOR_SIZE: u32 = 4096;

const CRYPTSETUP_BIN: &str = "cryptsetup";

pub const LUKS_HEADERS_STORAGE_DIR: &str = "/run/confidential-containers/cdh/luks-headers";
pub const LUKS_HEADER_FILE_SUFFIX: &str = ".header";
pub const LUKS2_HEADER_MIN_SIZE_BYTES: u64 = 16 * 1024 * 1024;

/// Returns the path where the detached LUKS header for the given device is stored.
pub fn luks_header_path(device_path: &str) -> String {
    let name = b64.encode(device_path.as_bytes());
    format!("{LUKS_HEADERS_STORAGE_DIR}/{name}{LUKS_HEADER_FILE_SUFFIX}")
}

/// Creates and sizes the LUKS header file at `header_path`.
pub fn prepare_luks_header_file(header_path: &str) -> std::io::Result<()> {
    if let Some(parent) = Path::new(header_path).parent() {
        std::fs::create_dir_all(parent)?;
    }
    let file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(header_path)?;
    file.set_len(LUKS2_HEADER_MIN_SIZE_BYTES)?;
    Ok(())
}

/// The type of the target mount point.
#[derive(Serialize, Deserialize, PartialEq, Debug, Eq)]
#[serde(tag = "targetType")]
#[serde(rename_all = "camelCase")]
pub enum TargetType {
    /// The target is a device.
    Device,

    /// The target is a filesystem directory.
    FileSystem {
        /// The type of the target filesystem.
        /// In some cases, the filesystem type is determined by the higher
        /// level encryption_type ([`BlockDeviceEncryptType`]), so this
        /// field will be optional.
        #[serde(rename = "filesystemType")]
        #[serde(default)]
        filesystem_type: FsType,

        /// Extra options passed verbatim to mkfs.<fs> when it is needed.
        ///
        /// For LUKS2 + dm-integrity + ext4 on an empty device, CDH adds
        /// integrity-compatible ext4 defaults when the caller has not provided
        /// an explicit setting. In particular, CDH defaults lazy_itable_init to
        /// 0 to avoid lazy inode table writes against no-wipe dm-integrity
        /// devices.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        #[serde(rename = "mkfsOpts")]
        mkfs_opts: Option<String>,
    },
}

#[derive(Default)]
pub struct Luks2Formatter {
    pub integrity: bool,
}

impl Luks2Formatter {
    pub fn with_integrity(mut self, integrity: bool) -> Self {
        self.integrity = integrity;
        self
    }

    /// Encrypt (format) a block device as LUKS2 using the `cryptsetup` binary.
    pub fn encrypt_device(
        &self,
        device_path: &str,
        header_path: Option<&str>,
        passphrase: Zeroizing<Vec<u8>>,
    ) -> anyhow::Result<()> {
        let sector_size_str = SECTOR_SIZE.to_string();

        let mut args: Vec<&str> = vec![
            "--batch-mode",
            "luksFormat",
            "--type",
            "luks2",
            "--cipher",
            "aes-xts-plain64",
            "--sector-size",
            &sector_size_str,
        ];

        if let Some(h) = header_path {
            args.push("--header");
            args.push(h);
        }

        if self.integrity {
            args.push("--integrity");
            args.push(HMAC_SHA256);
            args.push("--integrity-no-wipe");
            args.push("--integrity-no-journal");
        }

        args.push(device_path);
        args.push("-"); // read passphrase from stdin

        run_cryptsetup_stdin(&args, &passphrase).context("cryptsetup luksFormat failed")?;
        Ok(())
    }

    /// Open a LUKS2 device using the `cryptsetup` binary.
    pub fn open_device(
        &self,
        device_path: &str,
        header_path: Option<&str>,
        name: &str,
        passphrase: Zeroizing<Vec<u8>>,
    ) -> anyhow::Result<()> {
        let mut args: Vec<&str> = vec!["luksOpen", "-d", "-", device_path, name];

        if let Some(h) = header_path {
            args.insert(1, h);
            args.insert(1, "--header");
        }

        run_cryptsetup_stdin(&args, &passphrase).context("cryptsetup luksOpen failed")?;
        debug!("device activated: {name}");
        Ok(())
    }

    /// Close a LUKS2 mapping using the `cryptsetup` binary.
    pub fn close_device(&self, name: &str) -> anyhow::Result<()> {
        let args = ["luksClose", name];
        run_cryptsetup(&args).context("cryptsetup luksClose failed")?;
        Ok(())
    }
}

/// Run cryptsetup with passphrase on stdin. Does not append newline.
fn run_cryptsetup_stdin(args: &[&str], passphrase: &[u8]) -> anyhow::Result<()> {
    let inputs = passphrase.to_vec();
    let _ = run_command(CRYPTSETUP_BIN, args, Some(inputs))
        .context("failed to run cryptsetup with stdin")?;
    Ok(())
}

/// Run cryptsetup without stdin (e.g. luksClose).
fn run_cryptsetup(args: &[&str]) -> anyhow::Result<()> {
    let _ = run_command(CRYPTSETUP_BIN, args, None).context("failed to run cryptsetup")?;
    Ok(())
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct Luks2MountParameters {
    /// Indicates whether to enable dm-integrity.
    ///
    /// When this is true and CDH formats an empty ext4 filesystem, CDH uses
    /// integrity-compatible formatting and applies ext4 safety defaults such as
    /// lazy_itable_init=0 unless the caller explicitly provides that option in
    /// mkfsOpts.
    #[serde(rename = "dataIntegrity")]
    #[serde(default)]
    pub data_integrity: Option<String>,

    /// Optional name for /dev/mapper/<name>
    #[serde(rename = "mapperName")]
    pub mapper_name: Option<String>,

    /// The type of the target mount point.
    /// Either `device` or `fileSystem`.
    #[serde(rename = "targetType")]
    #[serde(flatten)]
    pub target_type: TargetType,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Luks2Mount {
    pub header_path: Option<String>,
    pub mapper_name: String,
    pub target_is_device: bool,
}

impl Luks2MountParameters {
    /// Do the mount operation for the LUKS2 device.
    /// Returns the resources created by this operation so the caller can
    /// release them in the correct order.
    pub async fn do_mount(
        self,
        device_path: &str,
        mount_point: &str,
        key: Zeroizing<Vec<u8>>,
        source_type: SourceType,
    ) -> Result<Luks2Mount> {
        let data_integrity = self
            .data_integrity
            .as_deref()
            .unwrap_or("false")
            .parse::<bool>()
            .context("dataIntegrity must be `true` or `false`")?;
        let formatter = Luks2Formatter::default().with_integrity(data_integrity);
        // 3.1 if the source type is empty, encrypt the device and create detached header
        let mut header_path = if source_type == SourceType::Empty {
            warn!("encrypting the device. This will wipe original data on the disk.");
            let header_path = luks_header_path(device_path);
            prepare_luks_header_file(&header_path)?;
            if let Err(error) = formatter
                .encrypt_device(device_path, Some(&header_path), key.clone())
                .context("failed to encrypt LUKS2 device")
            {
                let _ = std::fs::remove_file(&header_path);
                return Err(error);
            }
            Some(header_path)
        } else {
            None
        };

        let devmapper_name = self.mapper_name.unwrap_or_else(|| {
            debug!("No mapper name provided, generating a random one");
            uuid::Uuid::new_v4().to_string()
        });

        debug!("luks2 opening device: {device_path}");
        if let Err(detached_error) = formatter.open_device(
            device_path,
            header_path.as_deref(),
            &devmapper_name,
            key.clone(),
        ) {
            // cryptsetup 2.3.x cannot reliably activate dm-integrity when the
            // LUKS2 header is detached. Since sourceType=empty explicitly
            // authorizes initialization, retry with an on-device header. The
            // random key still makes keyless ephemeral storage unrecoverable
            // after reboot.
            if data_integrity && source_type == SourceType::Empty && header_path.is_some() {
                warn!(
                    "detached LUKS2 header with dm-integrity is unsupported by this cryptsetup; retrying with an on-device header"
                );
                let _ = formatter.close_device(&devmapper_name);
                if let Some(path) = header_path.take() {
                    let _ = std::fs::remove_file(path);
                }

                let fallback_result = formatter
                    .encrypt_device(device_path, None, key.clone())
                    .context("failed to format the dm-integrity compatibility fallback")
                    .and_then(|_| {
                        formatter
                            .open_device(device_path, None, &devmapper_name, key)
                            .context("failed to open the dm-integrity compatibility fallback")
                    });
                if let Err(fallback_error) = fallback_result {
                    return Err(anyhow::anyhow!(
                        "failed to open LUKS2 with detached header: {detached_error:#}; on-device-header fallback also failed: {fallback_error:#}"
                    ));
                }
            } else {
                if let Some(path) = &header_path {
                    let _ = std::fs::remove_file(path);
                }
                return Err(detached_error).context("failed to open LUKS2 device");
            }
        }

        let dev_path = format!("/dev/mapper/{devmapper_name}");
        let target_is_device = self.target_type == TargetType::Device;
        let mount_result: Result<()> = async {
            match (self.target_type, source_type) {
                // 3.2 if the target type is device, do the symlink operation to map
                // the device path to the mount point.
                (TargetType::Device, _) => {
                    info!(
                        "symlinking device: {dev_path} to mount point: {mount_point}"
                    );
                    symlink(&dev_path, mount_point).await.with_context(|| {
                        format!(
                            "Failed to create symlink from {dev_path} to {mount_point}"
                        )
                    })?;
                    debug!("created device symlink at {mount_point}");
                }
                // 3.3 if the source type is encrypted, meaning that there is
                // already a filesystem on the device, so we just need to mount it to the mount point.
                (
                    TargetType::FileSystem {
                        filesystem_type, ..
                    },
                    SourceType::Encrypted,
                ) => {
                    info!(
                        "mounting device: {dev_path} to mount point: {mount_point}"
                    );
                    mount::<_, _, str, _>(
                        Some(&dev_path[..]),
                        mount_point,
                        Some(filesystem_type.as_ref()),
                        MsFlags::MS_NOATIME,
                        Some(""),
                    )
                    .with_context(|| {
                        format!(
                            "Failed to mount device {dev_path} to mount point {mount_point}"
                        )
                    })?;

                    debug!("mounted device at {mount_point}");
                }
                // 3.4 if the source type is empty, meaning that we should also make
                // a filesystem on the device.
                (
                    TargetType::FileSystem {
                        filesystem_type,
                        mkfs_opts,
                    },
                    SourceType::Empty,
                ) => {
                    info!(
                        "formatting device: {dev_path} and mounting it to mount point: {mount_point}"
                    );
                    let args = mkfs_opts
                        .map(|s| {
                            s.split_ascii_whitespace()
                                .map(|x| x.to_string())
                                .collect::<Vec<String>>()
                        })
                        .unwrap_or_default();
                    debug!(
                        "formatting device {dev_path} as {filesystem_type:?} with args {args:?}"
                    );
                    let fs_formatter = FsFormatter {
                        fs_type: filesystem_type,
                        force: true,
                        args,
                    };

                    let format_result = if data_integrity {
                        fs_formatter.format_integrity_compatible(&dev_path)
                    } else {
                        fs_formatter.format(&dev_path)
                    };
                    format_result.with_context(|| {
                        format!(
                            "Failed to make filesystem {filesystem_type:?} of device {dev_path}"
                        )
                    })?;

                    debug!("mounting device {dev_path}");
                    mount(
                        Some(&dev_path[..]),
                        mount_point,
                        Some(filesystem_type.as_ref()),
                        MsFlags::MS_NOATIME,
                        Some(""),
                    )
                    .with_context(|| {
                        format!(
                            "Failed to mount device {dev_path} to mount point {mount_point}"
                        )
                    })?;
                    debug!("mounted device at {mount_point}");
                }
            }
            Ok(())
        }
        .await;

        if let Err(error) = mount_result {
            let _ = formatter.close_device(&devmapper_name);
            if let Some(path) = &header_path {
                let _ = std::fs::remove_file(path);
            }
            return Err(error);
        }

        Ok(Luks2Mount {
            header_path,
            mapper_name: devmapper_name,
            target_is_device,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use serial_test::serial;
    use zeroize::Zeroizing;

    use super::{
        luks_header_path, prepare_luks_header_file, Luks2Formatter, LUKS2_HEADER_MIN_SIZE_BYTES,
    };
    use crate::storage::drivers::run_command;

    const TEST_PASSPHRASE: &[u8] = b"correct horse battery staple";

    struct CloseDeviceOnDrop(String);

    impl Drop for CloseDeviceOnDrop {
        fn drop(&mut self) {
            let _ = Luks2Formatter::default().close_device(&self.0);
        }
    }

    struct RemoveFileOnDrop(String);

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

    #[test]
    fn detached_header_path_is_stable_and_file_is_exclusive() {
        let device_path = format!("/dev/cdh-test-{:016x}", rand::random::<u64>());
        let header_path = luks_header_path(&device_path);
        let _guard = RemoveFileOnDrop(header_path.clone());

        prepare_luks_header_file(&header_path).unwrap();
        assert_eq!(
            std::fs::metadata(&header_path).unwrap().len(),
            LUKS2_HEADER_MIN_SIZE_BYTES
        );
        assert_eq!(
            prepare_luks_header_file(&header_path).unwrap_err().kind(),
            std::io::ErrorKind::AlreadyExists
        );
    }

    #[test]
    #[serial]
    fn encrypt_and_open_device_with_detached_header() {
        if !cryptsetup_available() {
            return;
        }

        let device = tempfile::NamedTempFile::new().unwrap();
        device.as_file().set_len(64 * 1024 * 1024).unwrap();
        let device_path = device.path().to_str().unwrap();
        let header_path = luks_header_path(device_path);
        let _header_guard = RemoveFileOnDrop(header_path.clone());
        prepare_luks_header_file(&header_path).unwrap();

        let formatter = Luks2Formatter::default();
        let key = Zeroizing::new(TEST_PASSPHRASE.to_vec());
        formatter
            .encrypt_device(device_path, Some(&header_path), key.clone())
            .unwrap();

        let mapper_name = unique_mapper_name("cdh-luks-header");
        formatter
            .open_device(device_path, Some(&header_path), &mapper_name, key)
            .unwrap();
        let _mapper_guard = CloseDeviceOnDrop(mapper_name.clone());
        assert!(Path::new(&format!("/dev/mapper/{mapper_name}")).exists());
    }

    #[test]
    #[serial]
    fn encrypt_and_open_preexisting_luks2_device() {
        if !cryptsetup_available() {
            return;
        }

        let device = tempfile::NamedTempFile::new().unwrap();
        device.as_file().set_len(64 * 1024 * 1024).unwrap();
        let device_path = device.path().to_str().unwrap();
        let formatter = Luks2Formatter::default();
        let key = Zeroizing::new(TEST_PASSPHRASE.to_vec());
        formatter
            .encrypt_device(device_path, None, key.clone())
            .unwrap();

        let mapper_name = unique_mapper_name("cdh-luks-existing");
        formatter
            .open_device(device_path, None, &mapper_name, key)
            .unwrap();
        let _mapper_guard = CloseDeviceOnDrop(mapper_name.clone());
        assert!(Path::new(&format!("/dev/mapper/{mapper_name}")).exists());
    }
}
