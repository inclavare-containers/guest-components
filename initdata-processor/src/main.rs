// Copyright (c) 2025 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0

mod initdata_spec;

use anyhow::{bail, Context, Result};
use attester::{detect_tee_type, BoxedAttester, InitDataResult};
use initdata_spec::InitData;
use log::{info, warn};
use sha2::{Digest, Sha256, Sha384, Sha512};
use std::fs::File;
use std::io::Read;
use std::os::unix::fs::FileTypeExt;
use std::path::{Path, PathBuf};

const INITDATA_MAGIC: &[u8] = b"initdata";
const INITDATA_OUT_DIR: &str = "/run/confidential-containers/initdata";

fn digest_raw_content(algorithm: &str, content: &[u8]) -> Result<Vec<u8>> {
    Ok(match algorithm {
        "sha256" => Sha256::digest(content).to_vec(),
        "sha384" => Sha384::digest(content).to_vec(),
        "sha512" => Sha512::digest(content).to_vec(),
        _ => bail!("unsupported hash algorithm {}", algorithm),
    })
}

/// Read gzip-compressed initdata payload after the standard `initdata` block header.
fn try_read_initdata_block(path: &Path) -> Result<Option<Vec<u8>>> {
    let md = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(_) => return Ok(None),
    };
    if !md.file_type().is_block_device() {
        return Ok(None);
    }

    let mut f = match File::open(path) {
        Ok(f) => f,
        Err(_) => return Ok(None),
    };

    let mut magic = [0u8; 8];
    if f.read_exact(&mut magic).is_err() {
        return Ok(None);
    }
    if magic != INITDATA_MAGIC {
        return Ok(None);
    }

    let mut len_buf = [0u8; 8];
    f.read_exact(&mut len_buf)
        .context("read initdata compressed length")?;
    let length = u64::from_le_bytes(len_buf) as usize;

    let mut buf = vec![0u8; length];
    f.read_exact(&mut buf)
        .context("read initdata gzip payload")?;

    let mut decoder = flate2::read::GzDecoder::new(&buf[..]);
    let mut out = Vec::new();
    decoder
        .read_to_end(&mut out)
        .context("gzip decompress initdata")?;

    Ok(Some(out))
}

fn find_initdata_device() -> Result<Option<(PathBuf, Vec<u8>)>> {
    let dev = Path::new("/dev");
    let rd = match std::fs::read_dir(dev) {
        Ok(r) => r,
        Err(e) => {
            warn!("cannot read /dev: {e}");
            return Ok(None);
        }
    };

    for ent in rd.flatten() {
        let path = ent.path();
        if let Some(raw) = try_read_initdata_block(&path)? {
            return Ok(Some((path, raw)));
        }
    }

    Ok(None)
}

fn ensure_plain_filename(key: &str) -> Result<&str> {
    if key.is_empty() {
        bail!("empty key in [data]");
    }
    if key.contains('/') || key.contains('\\') || key == "." || key == ".." {
        bail!("invalid [data] key (must be a single path segment): {key:?}");
    }
    Ok(key)
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let Some((device_path, raw)) = find_initdata_device()? else {
        info!("no initdata block device found, exiting");
        return Ok(());
    };

    info!("using initdata device {}", device_path.display());

    let raw_str = std::str::from_utf8(&raw).context("initdata is not valid UTF-8")?;
    let initdata: InitData = toml::from_str(raw_str).context("parse initdata toml")?;
    initdata.validate().context("initdata validation")?;

    let digest = digest_raw_content(initdata.algorithm(), &raw)?;

    let tee = detect_tee_type();
    let attester = BoxedAttester::try_from(tee).context("instantiate attester")?;
    match attester.bind_init_data(&digest).await {
        Ok(InitDataResult::Ok) => info!("bind_init_data succeeded for tee {:?}", tee),
        Ok(InitDataResult::Unsupported) => {
            warn!(
                "bind_init_data unsupported for tee {:?}; skipping hardware bind check",
                tee
            );
        }
        Err(e) => bail!("bind_init_data failed: {e:#}"),
    }

    tokio::fs::create_dir_all(INITDATA_OUT_DIR)
        .await
        .with_context(|| format!("create {}", INITDATA_OUT_DIR))?;

    for (key, value) in initdata.data() {
        let key = ensure_plain_filename(key)?;
        let out = Path::new(INITDATA_OUT_DIR).join(key);
        tokio::fs::write(&out, value.as_bytes())
            .await
            .with_context(|| format!("write {}", out.display()))?;
        info!("wrote {}", out.display());
    }

    Ok(())
}
