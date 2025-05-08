// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! This mod implements aes-256-gcm encryption & decryption.

use anyhow::*;
use openssl::symm::Cipher;

const TAG_LENGTH: usize = 16;

pub fn decrypt(encrypted_data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
    let cipher = Cipher::aes_256_gcm();
    if encrypted_data.len() < TAG_LENGTH {
        bail!("Illegal length of ciphertext");
    }

    let (data, tag) = encrypted_data.split_at(encrypted_data.len() - TAG_LENGTH);
    openssl::symm::decrypt_aead(cipher, key, Some(iv), &[], data, tag)
        .map_err(|e| anyhow!(e.to_string()))
}

pub fn encrypt(data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
    let cipher = Cipher::aes_256_gcm();
    let mut tag = [0u8; TAG_LENGTH];
    let mut ciphertext = openssl::symm::encrypt_aead(cipher, key, Some(iv), &[], data, &mut tag)
        .map_err(|e| anyhow!(e.to_string()))?;
    ciphertext.extend_from_slice(&tag);
    Ok(ciphertext)
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::{decrypt, encrypt};

    #[rstest]
    #[case(b"plaintext1", b"0123456789abcdefghijklmnopqrstuv", b"unique nonce")]
    #[case(b"plaintext2", b"hijklmnopqrstuv0123456789abcdefg", b"unique2nonce")]
    fn en_decrypt(#[case] plaintext: &[u8], #[case] key: &[u8], #[case] iv: &[u8]) {
        let ciphertext = encrypt(plaintext, key, iv).expect("encryption failed");
        let plaintext_de = decrypt(&ciphertext, key, iv).expect("decryption failed");
        assert_eq!(plaintext, plaintext_de);
    }

    #[test]
    fn test_wrong_key() {
        let plaintext = b"plaintext";
        let key = b"0123456789abcdefghijklmnopqrstuv";
        let iv = b"16bytes ivlength";
        let ciphertext = encrypt(plaintext, key, iv).expect("encryption failed");

        let wrong_key = b"efghijklmnopqrstuv0123456789abcd";
        let plaintext_de = decrypt(&ciphertext, wrong_key, iv);
        assert!(plaintext_de.is_err());
    }
}
