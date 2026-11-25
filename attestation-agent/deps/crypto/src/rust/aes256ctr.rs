// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! This mod implements aes-256-ctr encryption & decryption.

use aes_gcm::aes::Aes256;
use anyhow::*;
use ctr::{
    cipher::{KeyIvInit, StreamCipher},
    Ctr128BE,
};

pub fn decrypt(key: &[u8], encrypted_data: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
    let mut decryptor = Ctr128BE::<Aes256>::new(key.into(), iv.into());
    let mut buf = Vec::new();
    buf.resize(encrypted_data.len(), b' ');
    decryptor
        .apply_keystream_b2b(encrypted_data, &mut buf)
        .map_err(|e| anyhow!("aes-256-ctr decrypt failed: {e:?}"))?;
    Ok(buf)
}

pub fn encrypt(key: &[u8], data: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
    let mut encryptor = Ctr128BE::<Aes256>::new(key.into(), iv.into());
    let mut ciphertext = data.to_vec();
    encryptor.apply_keystream(&mut ciphertext);
    Ok(ciphertext)
}

#[cfg(test)]
mod tests {
    use super::{decrypt, encrypt};
    use rstest::rstest;

    #[rstest]
    #[case(
        rand::random::<[u8; 32]>(),
        b"plaintext1",
        b"16bytes ivlength"
    )]
    #[case(
        rand::random::<[u8; 32]>(),
        b"plaintext2",
        b"16bytes ivlength"
    )]
    fn en_decrypt(#[case] key: [u8; 32], #[case] plaintext: &[u8], #[case] iv: &[u8]) {
        let ciphertext = encrypt(&key, plaintext, iv).expect("encryption failed");
        let plaintext_de = decrypt(&key, &ciphertext, iv).expect("decryption failed");
        assert_eq!(plaintext, plaintext_de);
    }

    #[test]
    fn test_wrong_key() {
        let plaintext = b"plaintext";
        let key = rand::random::<[u8; 32]>();
        let iv = b"16bytes ivlength";
        let ciphertext = encrypt(&key, plaintext, iv).expect("encryption failed");

        let mut wrong_key = key;
        wrong_key[0] ^= 1;
        let plaintext_de = decrypt(&wrong_key, &ciphertext, iv).unwrap();
        assert!(plaintext_de != plaintext);
    }
}
