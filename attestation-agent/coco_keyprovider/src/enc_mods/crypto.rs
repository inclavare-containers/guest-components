// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
use anyhow::{anyhow, Result};

pub fn encrypt(data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
    let cipher =
        Aes256Gcm::new_from_slice(key).map_err(|_| anyhow!("A256GCM requires a 32-byte key"))?;
    cipher
        .encrypt(Nonce::from_slice(iv), data)
        .map_err(|e| anyhow!("A256GCM encryption failed: {e:?}"))
}
