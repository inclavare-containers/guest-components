// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

pub mod error;
pub mod layout;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD as b64, Engine};
use jose_jwa::Signing;
use jose_jwk::{EcCurves, Jwk};
use jose_jws::{Flattened, Protected, Unprotected};
use p256::ecdsa::{
    signature::{Signer, Verifier},
    Signature, SigningKey, VerifyingKey,
};
use serde::{Deserialize, Serialize};
use std::fs;

use self::layout::{envelope::EnvelopeSecret, vault::VaultSecret};
use crate::kms::{self, Annotations, ProviderSettings};
use resource_uri::ResourceUri;

pub use error::{Result, SecretError};

/// Path containing sealed-secret verification keys provisioned at CDH startup.
pub const SIGNING_CREDENTIALS_PATH: &str = "/run/confidential-containers/cdh/sealed-secret";

#[derive(Serialize, Deserialize, PartialEq, Debug)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum SecretContent {
    Envelope(EnvelopeSecret),
    Vault(VaultSecret),
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct Secret {
    pub version: String,

    #[serde(flatten)]
    pub r#type: SecretContent,
}

pub const VERSION: &str = "0.1.0";

pub async fn unseal_secret(secret: &[u8]) -> Result<Vec<u8>> {
    let secret_string = String::from_utf8(secret.to_vec())
        .map_err(|_| SecretError::ParseFailed("Secret string must be UTF-8"))?;

    let skip_verification = std::env::var("SKIP_SEALED_SECRET_VERIFICATION")
        .map(|value| value == "true")
        .unwrap_or(false);

    let secret = Secret::from_signed_base64_string(secret_string, skip_verification).await?;
    secret.unseal().await
}

impl Secret {
    pub async fn unseal(&self) -> Result<Vec<u8>> {
        if self.version != VERSION {
            return Err(SecretError::VersionError);
        }

        match &self.r#type {
            SecretContent::Envelope(env) => env.unseal().await.map_err(Into::into),
            SecretContent::Vault(v) => v.unseal().await.map_err(Into::into),
        }
    }

    pub async fn from_signed_base64_string(
        secret: String,
        skip_verification: bool,
    ) -> Result<Self> {
        let payload = if skip_verification {
            // Legacy fake JWS headers are intentionally accepted only through
            // this explicit compatibility mode.
            let sections: Vec<_> = secret.trim().split('.').collect();
            if sections.len() != 4 || sections[0] != "sealed" {
                return Err(SecretError::ParseFailed("malformed input sealed secret"));
            }

            b64.decode(sections[2]).map_err(|_| {
                SecretError::ParseFailed(
                    "failed to decode secret body as base64 (URL-safe without padding)",
                )
            })?
        } else {
            let compact_jws = secret
                .trim()
                .strip_prefix("sealed.")
                .ok_or(SecretError::ParseFailed(
                    "sealed secret must start with sealed.",
                ))?
                .to_string();

            let jws: Flattened = compact_jws
                .parse()
                .map_err(|_| SecretError::ParseFailed("Failed to parse JWS"))?;
            let protected = jws
                .signature
                .protected
                .as_ref()
                .ok_or(SecretError::ParseFailed("Could not find protected header"))?;
            let kid = protected
                .oth
                .kid
                .as_ref()
                .ok_or(SecretError::ParseFailed("Could not find kid"))?;
            let alg = protected
                .oth
                .alg
                .ok_or(SecretError::ParseFailed("Could not get algorithm"))?;

            if alg != Signing::Es256 {
                return Err(SecretError::BadSigningKey("JWS algorithm must be ES256"));
            }

            let verification_key = Self::get_kid(kid).await?;
            Self::validate_es256(
                &compact_jws,
                &verification_key,
                jws.signature.signature.as_ref(),
            )?;

            jws.payload
                .ok_or(SecretError::ParseFailed("Could not find JWS Payload"))?
                .to_vec()
        };

        let secret: Secret = serde_json::from_slice(&payload).map_err(|_| {
            SecretError::ParseFailed(
                "malformed input sealed secret format (json deserialization failed)",
            )
        })?;

        Ok(secret)
    }

    /// Resolve a verification key from Trustee when `kid` is a Resource URI,
    /// or from the credentials directory otherwise.
    async fn get_kid(kid: &str) -> Result<Vec<u8>> {
        if ResourceUri::try_from(kid).is_ok() {
            return Ok(kms::new_getter("kbs", ProviderSettings::default())
                .await?
                .get_secret(kid, &Annotations::default())
                .await?);
        }

        let base = fs::canonicalize(SIGNING_CREDENTIALS_PATH).map_err(|_| {
            SecretError::ParseFailed("KID is invalid. Must be a KBS URI or a credential path.")
        })?;
        let kid_path = fs::canonicalize(base.join(kid))?;
        if !kid_path.starts_with(&base) {
            return Err(SecretError::ParseFailed("Invalid KID Key Path"));
        }

        Ok(tokio::fs::read(kid_path).await?)
    }

    fn validate_es256(compact_jws: &str, verification_key: &[u8], signature: &[u8]) -> Result<()> {
        let jwk: Jwk = serde_json::from_slice(verification_key)?;
        let public_key: p256::PublicKey = match &jwk.key {
            jose_jwk::Key::Ec(ec) if ec.crv == EcCurves::P256 => ec
                .try_into()
                .map_err(|_| SecretError::BadSigningKey("Could not parse verification key."))?,
            _ => return Err(SecretError::BadSigningKey("Key must be P256")),
        };

        let mut sections = compact_jws.split('.');
        let protected = sections
            .next()
            .ok_or(SecretError::ParseFailed("Could not find JWS header"))?;
        let payload = sections
            .next()
            .ok_or(SecretError::ParseFailed("Could not find JWS payload"))?;
        let signing_input = format!("{protected}.{payload}");

        let signature = Signature::from_slice(signature)?;
        VerifyingKey::from(&public_key).verify(signing_input.as_bytes(), &signature)?;
        Ok(())
    }

    pub fn to_signed_base64_string(&self, signing_key: Jwk, signing_kid: String) -> Result<String> {
        let secret_json = serde_json::to_string(&self)
            .map_err(|_| SecretError::ParseFailed("JSON serialization failed"))?;

        let signing_key: p256::SecretKey = match &signing_key.key {
            jose_jwk::Key::Ec(ec) if ec.crv == EcCurves::P256 => ec
                .try_into()
                .map_err(|_| SecretError::BadSigningKey("Could not parse signing key."))?,
            _ => {
                return Err(SecretError::BadSigningKey(
                    "Key must be EC P256 private key",
                ))
            }
        };
        let signing_key = SigningKey::from(&signing_key);

        let header = Protected {
            oth: Unprotected {
                alg: Some(Signing::Es256),
                kid: Some(signing_kid),
                ..Default::default()
            },
            ..Default::default()
        };
        let header_b64 = b64.encode(serde_json::to_vec(&header)?);
        let payload_b64 = b64.encode(secret_json.as_bytes());
        let signing_input = format!("{header_b64}.{payload_b64}");
        let signature: Signature = signing_key.sign(signing_input.as_bytes());
        let signature_b64 = b64.encode(signature.to_bytes());

        Ok(format!("sealed.{header_b64}.{payload_b64}.{signature_b64}"))
    }
}

#[cfg(test)]
mod tests {
    use std::{env, ffi::OsString};

    use assert_json_diff::assert_json_eq;
    use base64::{engine::general_purpose::STANDARD, Engine};
    use crypto::WrapType;
    use jose_jwk::Jwk;
    use rstest::rstest;
    use serial_test::serial;

    use crate::secret::layout::{
        envelope::EnvelopeSecret,
        vault::{Annotations, ProviderSettings, VaultSecret},
    };

    use super::{b64, Secret, SecretContent, SecretError};

    const PRIVATE_JWK: &str = include_str!("./tests/test-key.json");
    const OTHER_PRIVATE_JWK: &str = include_str!("./tests/test-key-2.json");

    struct EnvRestore {
        aa_kbc_params: Option<OsString>,
        extra_resources: Option<OsString>,
    }

    impl EnvRestore {
        fn capture() -> Self {
            Self {
                aa_kbc_params: env::var_os("AA_KBC_PARAMS"),
                extra_resources: env::var_os("OFFLINE_FS_KBC_EXTRA_FILE_PATH"),
            }
        }
    }

    impl Drop for EnvRestore {
        fn drop(&mut self) {
            match self.aa_kbc_params.take() {
                Some(value) => env::set_var("AA_KBC_PARAMS", value),
                None => env::remove_var("AA_KBC_PARAMS"),
            }
            match self.extra_resources.take() {
                Some(value) => env::set_var("OFFLINE_FS_KBC_EXTRA_FILE_PATH", value),
                None => env::remove_var("OFFLINE_FS_KBC_EXTRA_FILE_PATH"),
            }
        }
    }

    fn signing_key(jwk: &str) -> Jwk {
        serde_json::from_str(jwk).expect("parse test signing JWK")
    }

    fn public_jwk(jwk: &str) -> Vec<u8> {
        let mut value: serde_json::Value = serde_json::from_str(jwk).unwrap();
        value.as_object_mut().unwrap().remove("d");
        serde_json::to_vec(&value).unwrap()
    }

    async fn provision_offline_verification_key(jwk: &str) -> tempfile::NamedTempFile {
        let resources = tempfile::NamedTempFile::new().unwrap();
        let content = serde_json::json!({
            "default/sealed-secret/test-key": STANDARD.encode(public_jwk(jwk)),
        });
        tokio::fs::write(resources.path(), content.to_string())
            .await
            .unwrap();
        env::set_var("AA_KBC_PARAMS", "offline_fs_kbc::");
        env::set_var("OFFLINE_FS_KBC_EXTRA_FILE_PATH", resources.path());
        resources
    }

    fn signed(secret: &Secret, jwk: &str) -> String {
        secret
            .to_signed_base64_string(
                signing_key(jwk),
                "kbs:///default/sealed-secret/test-key".to_string(),
            )
            .expect("sign secret")
    }

    fn vault_secret(name: &str) -> Secret {
        Secret {
            version: "0.1.0".into(),
            r#type: SecretContent::Vault(VaultSecret {
                provider: "kbs".into(),
                provider_settings: ProviderSettings::default(),
                annotations: Annotations::default(),
                name: name.into(),
            }),
        }
    }

    #[rstest]
    #[case(include_str!("./tests/envelope-1.json"), Secret {
        version: "0.1.0".into(),
        r#type: SecretContent::Envelope(EnvelopeSecret {
            provider: "aliyun".into(),
            provider_settings: ProviderSettings::default(),
            key_id: "xxx".into(),
            encrypted_key: "yyy".into(),
            encrypted_data: "zzz".into(),
            wrap_type: WrapType::Aes256Gcm,
            iv: "www".into(),
            annotations: Annotations::default(),
        }),
    })]
    #[case(include_str!("./tests/vault-1.json"), Secret {
        version: "0.1.0".into(),
        r#type: SecretContent::Vault(VaultSecret {
            provider: "aliyun".into(),
            provider_settings: ProviderSettings::default(),
            annotations: Annotations::default(),
            name: "xxx".into(),
        }),
    })]
    #[case(include_str!("./tests/vault-2.json"), Secret {
        version: "0.1.0".into(),
        r#type: SecretContent::Vault(VaultSecret {
            provider: "kbs".into(),
            provider_settings: ProviderSettings::default(),
            annotations: Annotations::default(),
            name: "kbs:///one/2/trois".into(),
        }),
    })]
    #[tokio::test]
    async fn serialize_deserialize(#[case] secret_json: &str, #[case] secret_object: Secret) {
        let serialized = serde_json::to_string_pretty(&secret_object).expect("serialize failed");
        assert_json_eq!(secret_json, serialized);

        let parsed: Secret = serde_json::from_str(secret_json).expect("deserialize failed");
        assert_eq!(parsed, secret_object);

        let secret_string = signed(&secret_object, PRIVATE_JWK);
        let secret_from_string = Secret::from_signed_base64_string(secret_string, true)
            .await
            .expect("deserialization failed in explicit compatibility mode");

        assert_eq!(secret_from_string, secret_object);
    }

    #[tokio::test]
    #[serial]
    async fn verifies_es256_key_retrieved_through_openanolis_kbs_uri() {
        let _restore = EnvRestore::capture();
        let _resources = provision_offline_verification_key(PRIVATE_JWK).await;
        let secret = vault_secret("kbs:///default/secret/value");

        let parsed = Secret::from_signed_base64_string(signed(&secret, PRIVATE_JWK), false)
            .await
            .expect("verification with OfflineFS/OpenAnolis resource URI must pass");
        assert_eq!(parsed, secret);
    }

    #[tokio::test]
    #[serial]
    async fn rejects_tampered_payload() {
        let _restore = EnvRestore::capture();
        let _resources = provision_offline_verification_key(PRIVATE_JWK).await;
        let mut sections: Vec<String> =
            signed(&vault_secret("kbs:///default/secret/value"), PRIVATE_JWK)
                .split('.')
                .map(ToString::to_string)
                .collect();
        let replacement = if sections[2].starts_with('A') {
            "B"
        } else {
            "A"
        };
        sections[2].replace_range(..1, replacement);

        assert!(Secret::from_signed_base64_string(sections.join("."), false)
            .await
            .is_err());
    }

    #[tokio::test]
    #[serial]
    async fn rejects_signature_from_wrong_key() {
        let _restore = EnvRestore::capture();
        let _resources = provision_offline_verification_key(PRIVATE_JWK).await;
        let secret = vault_secret("kbs:///default/secret/value");

        assert!(
            Secret::from_signed_base64_string(signed(&secret, OTHER_PRIVATE_JWK), false)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn rejects_non_es256_algorithm_before_key_lookup() {
        let mut sections: Vec<String> = signed(&vault_secret("ignored"), PRIVATE_JWK)
            .split('.')
            .map(ToString::to_string)
            .collect();
        let mut header: serde_json::Value =
            serde_json::from_slice(&b64.decode(&sections[1]).unwrap()).unwrap();
        header["alg"] = serde_json::json!("RS256");
        sections[1] = b64.encode(serde_json::to_vec(&header).unwrap());

        let error = Secret::from_signed_base64_string(sections.join("."), false)
            .await
            .unwrap_err();
        assert!(matches!(error, SecretError::BadSigningKey(_)));
    }

    #[tokio::test]
    async fn legacy_fake_signature_requires_explicit_skip() {
        let secret = vault_secret("kbs:///default/secret/value");
        let payload = b64.encode(serde_json::to_vec(&secret).unwrap());
        let legacy = format!("sealed.fakejwsheader.{payload}.fakesignature");

        assert!(Secret::from_signed_base64_string(legacy.clone(), false)
            .await
            .is_err());
        assert_eq!(
            Secret::from_signed_base64_string(legacy, true)
                .await
                .unwrap(),
            secret
        );
    }

    #[test]
    fn signing_requires_private_p256_key() {
        let public_key = signing_key(&String::from_utf8(public_jwk(PRIVATE_JWK)).unwrap());
        let error = vault_secret("ignored")
            .to_signed_base64_string(public_key, "kid".into())
            .unwrap_err();
        assert!(matches!(error, SecretError::BadSigningKey(_)));
    }

    #[rstest]
    fn test_no_padding(#[values(0, 1, 2, 3)] name_size: usize) {
        let name = "0".repeat(name_size);

        let secret = Secret {
            version: "0.1.0".into(),
            r#type: SecretContent::Vault(VaultSecret {
                provider: "kbs".into(),
                provider_settings: ProviderSettings::default(),
                annotations: Annotations::default(),
                name,
            }),
        };

        let serialized = serde_json::to_string_pretty(&secret).unwrap();

        assert!(!serialized.contains('='));
    }
}
