// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
use anyhow::{anyhow, ensure, Result};

/// Only for sample
pub const HARDCODED_KEY: &[u8] = &[
    217, 155, 119, 5, 176, 186, 122, 22, 130, 149, 179, 163, 54, 114, 112, 176, 221, 155, 55, 27,
    245, 20, 202, 139, 155, 167, 240, 163, 55, 17, 218, 234,
];

pub fn encrypt(data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| anyhow!("KEK must be 32 bytes"))?;
    ensure!(iv.len() == 12, "AES-GCM nonce must be 12 bytes");
    cipher
        .encrypt(Nonce::from_slice(iv), data)
        .map_err(|e| anyhow!("Encrypt failed: {e:?}"))
}
