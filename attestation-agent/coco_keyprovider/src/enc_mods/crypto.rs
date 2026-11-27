// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
use anyhow::{anyhow, ensure, Result};

pub fn encrypt(data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| anyhow!("KEK must be 32 bytes"))?;
    ensure!(iv.len() == 12, "AES-GCM nonce must be 12 bytes");
    cipher
        .encrypt(Nonce::from_slice(iv), data)
        .map_err(|e| anyhow!("Encrypt failed: {e:?}"))
}
