// Copyright (c) 2024 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! Credentials to access aliyun KMS

use anyhow::*;
use base64::{engine::general_purpose::STANDARD, Engine};
use log::debug;
use p12::{CertBag, ContentInfo, MacData, SafeBagKind, PFX};
use ring::{rand::SystemRandom, rsa::KeyPair, signature::RSA_PKCS1_SHA256};
use serde::Deserialize;
use yasna::ASN1Result;

#[derive(Clone, Debug)]
pub(crate) struct CredentialClientKey {
    pub client_key_id: String,
    private_key: Vec<u8>,
}
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ClientKey {
    key_id: String,
    private_key_data: String,
}

// implement CredentialClientKey related function
impl CredentialClientKey {
    pub(crate) fn new(client_key: &str, pswd: &str) -> Result<Self> {
        let ck: ClientKey = serde_json::from_str(client_key)?;

        let private_key =
            Self::parse_private_key(ck.private_key_data, pswd.trim_end().to_string())?;

        let credential = CredentialClientKey {
            client_key_id: ck.key_id.clone(),
            private_key,
        };

        Ok(credential)
    }

    pub(crate) fn sign(&self, str_to_sign: &str) -> Result<String> {
        let mut signature = Vec::new();
        let private_key = KeyPair::from_pkcs8(&self.private_key)
            .map_err(|_| anyhow!("read RSA private key failed"))?;
        signature.resize(private_key.public().modulus_len(), 0);
        private_key
            .sign(
                &RSA_PKCS1_SHA256,
                &SystemRandom::new(),
                str_to_sign.as_bytes(),
                &mut signature,
            )
            .map_err(|_| anyhow!("signing failed"))?;

        Ok(STANDARD.encode(signature))
    }

    pub(crate) fn parse_private_key(private_key_data: String, password: String) -> Result<Vec<u8>> {
        let private_key_der = STANDARD.decode(private_key_data.as_bytes())?;
        let pfx = yasna::parse_der(&private_key_der, |r| -> ASN1Result<PFX> {
            r.read_sequence(|r| {
                let version = r.next().read_u8()?;
                let auth_safe = ContentInfo::parse(r.next())?;
                let mac_data = r.read_optional(MacData::parse).ok().flatten();
                std::result::Result::Ok(PFX {
                    version,
                    auth_safe,
                    mac_data,
                })
            })
        })?;

        let bags = pfx.bags(&password)?;
        for bag in &bags {
            match &bag.bag {
                SafeBagKind::Pkcs8ShroudedKeyBag(k) => {
                    let pass = Self::bmp_string(&password);
                    let private_key = k
                        .encryption_algorithm
                        .decrypt_pbe(&k.encrypted_data, &pass)
                        .ok_or(anyhow!("decrypt pbe failed"))?;
                    return Ok(private_key);
                }
                SafeBagKind::CertBag(e) => match e {
                    CertBag::X509(x) => {
                        debug!("parse aliyun pkcs12 credential X509: {}", hex::encode(x))
                    }
                    CertBag::SDSI(s) => debug!("parse aliyun pkcs12 credential SDSI: {s:?}"),
                },
                _ => continue,
            }
        }

        Err(anyhow!("no private key found!"))
    }

    fn bmp_string(s: &str) -> Vec<u8> {
        let utf16: Vec<u16> = s.encode_utf16().collect();

        let mut bytes = Vec::with_capacity(utf16.len() * 2 + 2);
        for c in utf16 {
            bytes.push((c / 256) as u8);
            bytes.push((c % 256) as u8);
        }
        bytes.push(0x00);
        bytes.push(0x00);
        bytes
    }
}

#[cfg(test)]
mod tests {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use rsa::{pkcs8::EncodePrivateKey, rand_core::OsRng, RsaPrivateKey};

    use super::CredentialClientKey;

    #[test]
    fn parse_and_sign_password() {
        let password = format!("{:032x}", rand::random::<u128>());
        let private_key = RsaPrivateKey::new(&mut OsRng, 2048).unwrap();
        let pkcs8 = private_key.to_pkcs8_der().unwrap();
        let pfx = p12::PFX::new(
            b"test certificate payload",
            pkcs8.as_bytes(),
            None,
            &password,
            "test",
        )
        .unwrap();
        let der = CredentialClientKey::parse_private_key(STANDARD.encode(pfx.to_der()), password)
            .unwrap();
        let key = CredentialClientKey {
            client_key_id: "test-id".into(),
            private_key: der,
        };

        key.sign("example content").unwrap();
    }
}
