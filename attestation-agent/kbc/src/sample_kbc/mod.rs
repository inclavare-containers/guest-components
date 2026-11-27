// Copyright (c) 2021 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use crate::{KbcCheckInfo, KbcInterface};
use base64::Engine;
use crypto::{decrypt, WrapType};
use resource_uri::{ResourcePluginPath, ResourceUri};

use anyhow::*;
use async_trait::async_trait;
use std::collections::HashMap;
use zeroize::Zeroizing;

use super::AnnotationPacket;

#[derive(AsRefStr, EnumString, Display, Debug, PartialEq, Eq)]
pub enum ResourceType {
    #[strum(serialize = "security-policy")]
    /// image security policy, used to define whether a specific
    /// image can be pulled, or signature verification is needed
    Policy,

    /// used to configure the storage path of public keys used
    /// by simple signing when doing iamge signature verification
    #[strum(serialize = "sigstore-config")]
    SigstoreConfig,

    /// gpg public key used to verify signature of images in
    /// simple signing scheme.
    #[strum(serialize = "gpg-public-config")]
    GPGPublicKey,

    /// public key file used to verify signature of images in
    /// cosign scheme.
    #[strum(serialize = "cosign-public-key")]
    CosignVerificationKey,

    /// container registry auth file, used to provide auth
    /// when accessing a private registry / repository
    #[strum(serialize = "credential")]
    Credential,
}

pub struct SampleKbc {
    kbs_info: HashMap<String, String>,
}

// As a KBS client for attestation-agent,
// it must implement KbcInterface trait.
#[async_trait]
impl KbcInterface for SampleKbc {
    fn check(&self) -> Result<KbcCheckInfo> {
        Ok(KbcCheckInfo {
            kbs_info: self.kbs_info.clone(),
        })
    }

    async fn decrypt_payload(&mut self, annotation_packet: AnnotationPacket) -> Result<Vec<u8>> {
        ensure!(
            annotation_packet.wrap_type == WrapType::Aes256Gcm.as_ref(),
            "unsupported sample KBC wrap type"
        );
        let key_file = std::env::var_os("COCO_SAMPLE_KEY_FILE")
            .context("COCO_SAMPLE_KEY_FILE must point to a raw 32-byte key")?;
        let key = Zeroizing::new(std::fs::read(key_file).context("read sample KBC key")?);
        ensure!(key.len() == 32, "sample KBC key must be exactly 32 bytes");
        let engine = base64::engine::general_purpose::STANDARD;
        let plain_text = decrypt(
            key,
            engine.decode(annotation_packet.wrapped_data)?,
            engine.decode(annotation_packet.iv)?,
            WrapType::Aes256Gcm,
        )?;

        Ok(plain_text)
    }

    async fn get_resource(&mut self, resource_uri: ResourceUri) -> Result<Vec<u8>> {
        let ResourcePluginPath { r#type, .. } = resource_uri
            .try_into()
            .context("sample KBC only supports the resource plugin")?;
        let typ = ResourceType::try_from(r#type.as_str())?;
        match typ {
            ResourceType::Policy => Ok(std::include_str!("policy.json").as_bytes().to_vec()),
            ResourceType::SigstoreConfig => Ok(std::include_str!("sigstore_config.yaml")
                .as_bytes()
                .to_vec()),
            ResourceType::GPGPublicKey => Ok(std::include_str!("pubkey.gpg").as_bytes().to_vec()),
            ResourceType::CosignVerificationKey => {
                Ok(std::include_str!("cosign.pub").as_bytes().to_vec())
            }
            ResourceType::Credential => match std::env::var_os("COCO_SAMPLE_REGISTRY_AUTH_FILE") {
                Some(path) => std::fs::read(path).context("read sample KBC registry auth"),
                None => Ok(br#"{"auths":{}}"#.to_vec()),
            },
        }
    }
}

impl SampleKbc {
    pub fn new(kbs_uri: String) -> SampleKbc {
        let mut kbs_info: HashMap<String, String> = HashMap::new();
        kbs_info.insert("kbs_uri".to_string(), kbs_uri);
        SampleKbc { kbs_info }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD;

    struct EnvRestore(&'static str, Option<std::ffi::OsString>);

    impl EnvRestore {
        fn capture(name: &'static str) -> Self {
            Self(name, std::env::var_os(name))
        }
    }

    impl Drop for EnvRestore {
        fn drop(&mut self) {
            match &self.1 {
                Some(value) => std::env::set_var(self.0, value),
                None => std::env::remove_var(self.0),
            }
        }
    }

    #[tokio::test]
    async fn externally_provisioned_sample_key_and_registry_auth() {
        const KEY_FILE: &str = "COCO_SAMPLE_KEY_FILE";
        const AUTH_FILE: &str = "COCO_SAMPLE_REGISTRY_AUTH_FILE";

        let _key_env = EnvRestore::capture(KEY_FILE);
        let _auth_env = EnvRestore::capture(AUTH_FILE);
        std::env::remove_var(KEY_FILE);
        std::env::remove_var(AUTH_FILE);

        let dir = tempfile::tempdir().unwrap();
        let key_file = dir.path().join("key");
        let auth_file = dir.path().join("auth.json");
        let key = crate::tests::generate_test_key();
        let nonce = crate::tests::generate_test_key()[..12].to_vec();
        let plaintext = b"image layer options";
        let ciphertext = crypto::encrypt(
            Zeroizing::new(key.to_vec()),
            plaintext.to_vec(),
            nonce.clone(),
            WrapType::Aes256Gcm,
        )
        .unwrap();
        let annotation = || AnnotationPacket {
            kid: "kbs:///default/test-key/1".try_into().unwrap(),
            wrapped_data: STANDARD.encode(&ciphertext),
            iv: STANDARD.encode(&nonce),
            wrap_type: WrapType::Aes256Gcm.as_ref().to_owned(),
        };
        let credential = || "kbs:///default/credential/test".try_into().unwrap();
        let mut kbc = SampleKbc::new(String::new());

        assert!(kbc.decrypt_payload(annotation()).await.is_err());
        assert_eq!(
            kbc.get_resource(credential()).await.unwrap(),
            br#"{"auths":{}}"#
        );

        std::fs::write(&key_file, b"wrong length").unwrap();
        std::env::set_var(KEY_FILE, &key_file);
        assert!(kbc.decrypt_payload(annotation()).await.is_err());
        std::fs::write(&key_file, key).unwrap();
        assert_eq!(kbc.decrypt_payload(annotation()).await.unwrap(), plaintext);

        let registry = serde_json::json!({
            "auths": {"registry.invalid": {"auth": STANDARD.encode(crate::tests::generate_test_key())}}
        });
        let registry = serde_json::to_vec(&registry).unwrap();
        std::env::set_var(AUTH_FILE, &auth_file);
        assert!(kbc.get_resource(credential()).await.is_err());
        std::fs::write(&auth_file, &registry).unwrap();
        assert_eq!(kbc.get_resource(credential()).await.unwrap(), registry);
    }
}
