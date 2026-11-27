// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::*;
use openssl::{
    encrypt::Decrypter,
    hash::MessageDigest,
    pkey::{PKey, Private},
    rsa::{Padding, Rsa},
};
use zeroize::Zeroizing;

use crate::rsa::{PaddingMode, RSA_PUBKEY_LENGTH};

#[derive(Debug, Clone)]
pub struct RSAKeyPair {
    private_key: Rsa<Private>,
}

impl RSAKeyPair {
    pub fn new() -> Result<RSAKeyPair> {
        let private_key = Rsa::generate(RSA_PUBKEY_LENGTH as u32)?;
        Ok(Self { private_key })
    }

    pub fn decrypt(&self, mode: PaddingMode, cipher_text: Vec<u8>) -> Result<Vec<u8>> {
        let key = PKey::from_rsa(self.private_key.clone())?;
        let mut decrypter = Decrypter::new(&key)?;
        match mode {
            PaddingMode::OAEP => {
                decrypter.set_rsa_padding(Padding::PKCS1_OAEP)?;
                decrypter.set_rsa_oaep_md(MessageDigest::sha256())?;
                decrypter.set_rsa_mgf1_md(MessageDigest::sha256())?;
            }
        }

        let mut plaintext = Zeroizing::new(vec![0; decrypter.decrypt_len(&cipher_text)?]);
        let decrypted_size = decrypter
            .decrypt(&cipher_text, &mut plaintext)
            .context("RSA key decrypt OAEP failed")?;
        Ok(plaintext[..decrypted_size].to_vec())
    }

    pub fn n(&self) -> Vec<u8> {
        self.private_key.n().to_vec()
    }

    pub fn e(&self) -> Vec<u8> {
        self.private_key.e().to_vec()
    }

    pub fn to_pkcs1_pem(&self) -> Result<Zeroizing<String>> {
        let res = self.private_key.private_key_to_pem()?;
        let pem = String::from_utf8(res)?;
        Ok(Zeroizing::new(pem))
    }

    pub fn from_pkcs1_pem(pem: &str) -> Result<Self> {
        let private_key = Rsa::<Private>::private_key_from_pem(pem.as_bytes())?;

        Ok(Self { private_key })
    }
}

#[cfg(test)]
mod tests {
    use openssl::encrypt::Encrypter;

    use super::*;

    #[test]
    fn rsa_oaep_256_requires_sha256_for_both_digests() {
        let rsa = Rsa::generate(RSA_PUBKEY_LENGTH as u32).unwrap();
        let pem = Zeroizing::new(rsa.private_key_to_pem().unwrap());
        let keypair = RSAKeyPair::from_pkcs1_pem(std::str::from_utf8(&pem).unwrap()).unwrap();
        let public_key =
            PKey::from_rsa(Rsa::public_key_from_pem(&rsa.public_key_to_pem().unwrap()).unwrap())
                .unwrap();
        let mut encrypter = Encrypter::new(&public_key).unwrap();
        encrypter.set_rsa_padding(Padding::PKCS1_OAEP).unwrap();
        encrypter.set_rsa_oaep_md(MessageDigest::sha256()).unwrap();
        let content_key = [0xA5; 32];
        let encrypt = |encrypter: &Encrypter<'_>| {
            let mut wrapped = vec![0; encrypter.encrypt_len(&content_key).unwrap()];
            let len = encrypter.encrypt(&content_key, &mut wrapped).unwrap();
            wrapped.truncate(len);
            wrapped
        };

        encrypter.set_rsa_mgf1_md(MessageDigest::sha256()).unwrap();
        assert_eq!(
            keypair
                .decrypt(PaddingMode::OAEP, encrypt(&encrypter))
                .unwrap(),
            content_key,
        );
        encrypter.set_rsa_mgf1_md(MessageDigest::sha1()).unwrap();
        assert!(keypair
            .decrypt(PaddingMode::OAEP, encrypt(&encrypter))
            .is_err());

        encrypter.set_rsa_oaep_md(MessageDigest::sha1()).unwrap();
        encrypter.set_rsa_mgf1_md(MessageDigest::sha256()).unwrap();
        assert!(keypair
            .decrypt(PaddingMode::OAEP, encrypt(&encrypter))
            .is_err());
    }
}
