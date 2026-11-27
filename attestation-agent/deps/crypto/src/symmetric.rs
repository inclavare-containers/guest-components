// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! APIs for symmetric keys

use anyhow::Result;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

#[cfg(feature = "openssl")]
use crate::native::*;

#[cfg(all(feature = "rust-crypto", not(feature = "openssl")))]
use crate::rust::*;

pub const AES_GCM_256_KEY_BITS: u32 = 256;

/// Supported WrapType, s.t. encryption algorithm using to encrypt the
/// [PLBCO](https://github.com/confidential-containers/guest-components/blob/main/attestation-agent/docs/IMPLEMENTATION.md#encryption-and-decryption-of-container-image).
#[derive(EnumString, AsRefStr, Serialize, Deserialize, PartialEq, Debug, Clone)]
pub enum WrapType {
    /// The serialized name follows 5.2.6 section
    /// <https://www.rfc-editor.org/rfc/inline-errata/rfc7518.html>
    #[strum(serialize = "A256GCM")]
    #[serde(rename = "A256GCM")]
    Aes256Gcm,
}

/// Decrypt the given `ciphertext` using AES-256-GCM and a 12-byte nonce.
pub fn decrypt(
    key: Zeroizing<Vec<u8>>,
    ciphertext: Vec<u8>,
    iv: Vec<u8>,
    wrap_type: WrapType,
) -> Result<Vec<u8>> {
    match wrap_type {
        WrapType::Aes256Gcm => aes256gcm::decrypt(&key, &ciphertext, &iv),
    }
}

/// Decrypt the given `ciphertext` with AES256-GCM algorithm.
pub fn decrypt_aead(
    key: Zeroizing<Vec<u8>>,
    ciphertext: Vec<u8>,
    iv: Vec<u8>,
    aad: Vec<u8>,
    tag: Vec<u8>,
    wrap_type: WrapType,
) -> Result<Vec<u8>> {
    match wrap_type {
        WrapType::Aes256Gcm => {
            aes256gcm::decrypt_with_aad_detached_tag(&key, &ciphertext, &iv, &aad, &tag)
        }
    }
}

/// Encrypt the given `plaintext` using AES-256-GCM and a 12-byte nonce.
pub fn encrypt(
    key: Zeroizing<Vec<u8>>,
    plaintext: Vec<u8>,
    iv: Vec<u8>,
    wrap_type: WrapType,
) -> Result<Vec<u8>> {
    match wrap_type {
        WrapType::Aes256Gcm => aes256gcm::encrypt(&key, &plaintext, &iv),
    }
}

pub struct AeadCipher {
    pub tag: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

/// Encrypt the given `plaintext` using AES-256-GCM with a detached tag.
pub fn encrypt_aead(
    key: Zeroizing<Vec<u8>>,
    plaintext: Vec<u8>,
    iv: Vec<u8>,
    aad: Vec<u8>,
    wrap_type: WrapType,
) -> Result<AeadCipher> {
    match wrap_type {
        WrapType::Aes256Gcm => {
            aes256gcm::encrypt_with_aad_detached_tag(&key, &plaintext, &iv, &aad)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;

    #[test]
    fn test_serialize_wrap_type() {
        let wrap_type = WrapType::Aes256Gcm;
        assert_eq!(wrap_type.as_ref(), "A256GCM");

        assert_eq!(WrapType::from_str("A256GCM").unwrap(), WrapType::Aes256Gcm);
        assert!(WrapType::from_str("A256CTR").is_err());
        assert!(serde_json::from_str::<WrapType>(r#""A256CTR""#).is_err());
    }
}
