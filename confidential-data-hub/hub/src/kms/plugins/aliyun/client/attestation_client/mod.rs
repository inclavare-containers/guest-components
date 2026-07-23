// Copyright (c) 2026 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! Aliyun KMS client that fetches confidential resources by remote attestation.
//!
//! Different from [`super::client_key_client::ClientKeyClient`] (which authenticates
//! with a pre-provisioned client key), this client proves the running TEE to a KMS
//! instance that has the Trustee Attestation Service integrated. The KMS encrypts the
//! secret with an ephemeral public key that is bound into the TEE evidence, so the
//! plaintext is only recoverable inside the attested TEE.
//!
//! Protocol (all requests are RPC-style `POST /` form bodies signed with the Aliyun
//! POP HMAC-SHA1 scheme, sent to the dedicated instance endpoint over its private CA):
//!
//! 1. `GetChallenge` -> `{ Nonce, ChallengeToken }`
//! 2. generate an ephemeral RSA-2048 key pair, build the `structured` runtime data
//!    `{ challenge_token, nonce, tee-pubkey }`, hash it canonically with SHA-384 and
//!    let the attestation-agent embed the hash into the TEE evidence report data
//! 3. `GetSecretValue` with a `Recipient` carrying the evidence; the KMS verifies the
//!    evidence and returns `CiphertextForRecipient` = RSA-OAEP(SHA-256)(secret)
//! 4. decrypt `CiphertextForRecipient` with the ephemeral private key

use std::{collections::BTreeMap, env, fmt, fmt::Write as _};

use anyhow::{anyhow, bail, Context};
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE, URL_SAFE_NO_PAD},
    Engine,
};
use canon_json::CanonicalFormatter;
use chrono::Utc;
use log::{debug, info};
use protos::ttrpc::aa::{
    attestation_agent::GetEvidenceRequest, attestation_agent_ttrpc::AttestationAgentServiceClient,
};
use rand::{distr::Alphanumeric, Rng};
use reqwest::{Certificate, ClientBuilder};
use rsa::{rand_core::OsRng, traits::PublicKeyParts, Oaep, RsaPrivateKey};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256, Sha384};
use tokio::fs;
use ttrpc::context;

use super::super::annotations::AliSecretAnnotations;
use super::sts_token_client::credential::{self, StsCredential};
use super::ALIYUN_IN_GUEST_DEFAULT_KEY_PATH;
use crate::kms::{Annotations, Error, ProviderSettings, Result};

/// Default ttrpc socket the attestation-agent listens on inside a CoCo guest.
const DEFAULT_AA_SOCKET: &str =
    "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock";

const AA_TTRPC_TIMEOUT_NANOS: i64 = 50 * 1000 * 1000 * 1000;

/// `Recipient.KeyEncryptionAlgorithm` understood by the KMS Trustee integration.
/// The secret is wrapped with RSAES-OAEP using SHA-256 for both the hash and MGF1.
const KEY_ENCRYPTION_ALGORITHM: &str = "RSAES_OAEP_SHA_256";

/// Bit length of the ephemeral RSA key pair bound into the evidence.
const RSA_KEY_BITS: usize = 2048;

/// Serialized [`crate::ProviderSettings`] for the attestation client.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AliAttestationProviderSettings {
    /// KMS instance id, e.g. `kst-xxxxxx`.
    pub kms_instance_id: String,

    /// ECS RAM role bound to the instance. When configured, its temporary STS
    /// credential is fetched from IMDS to sign the KMS requests.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ecs_ram_role_name: Option<String>,

    /// STS credential in `AK:SK:STS` format. This is an alternative to
    /// `ecs_ram_role_name`; exactly one credential source must be configured.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sts_token: Option<String>,

    /// PEM-encoded private CA certificate of the KMS instance. When omitted, the
    /// certificate is read from the in-guest credential directory.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kms_ca_cert: Option<String>,

    /// TEE type reported in the attestation document, e.g. `tdx`. Defaults to `tdx`.
    #[serde(default = "default_tee")]
    pub tee: String,
}

fn default_tee() -> String {
    "tdx".to_string()
}

#[derive(Clone)]
pub struct AttestationClient {
    kms_instance_id: String,
    endpoint: String,
    credential_source: CredentialSource,
    kms_ca_cert: Option<String>,
    tee: String,
    aa_socket: String,
    http_client: reqwest::Client,
}

#[derive(Clone)]
enum CredentialSource {
    EcsRamRole(String),
    StsToken(StsCredential),
}

impl fmt::Debug for AttestationClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let credential_source = match &self.credential_source {
            CredentialSource::EcsRamRole(_) => "ecs_ram_role",
            CredentialSource::StsToken(_) => "sts_token",
        };
        f.debug_struct("AttestationClient")
            .field("kms_instance_id", &self.kms_instance_id)
            .field("endpoint", &self.endpoint)
            .field("credential_source", &credential_source)
            .field(
                "kms_ca_cert",
                &self.kms_ca_cert.as_ref().map(|_| "<redacted>"),
            )
            .field("tee", &self.tee)
            .field("aa_socket", &self.aa_socket)
            .field("http_client", &self.http_client)
            .finish()
    }
}

impl AttestationClient {
    pub fn new(settings: AliAttestationProviderSettings, cert_pem: &str) -> Result<Self> {
        let credential_source = credential_source(&settings)?;
        let endpoint = format!(
            "{}.cryptoservice.kms.aliyuncs.com",
            settings.kms_instance_id
        );
        let cert = Certificate::from_pem(cert_pem.as_bytes()).map_err(|e| {
            Error::AliyunKmsError(format!("read kms instance ca cert failed: {e:?}"))
        })?;
        let http_client = ClientBuilder::new()
            .use_rustls_tls()
            .add_root_certificate(cert)
            .build()
            .map_err(|e| Error::AliyunKmsError(format!("build http client failed: {e:?}")))?;

        let aa_socket =
            env::var("ATTESTATION_AGENT_SOCKET").unwrap_or_else(|_| DEFAULT_AA_SOCKET.to_string());

        Ok(Self {
            kms_instance_id: settings.kms_instance_id,
            endpoint,
            credential_source,
            kms_ca_cert: settings.kms_ca_cert,
            tee: settings.tee,
            aa_socket,
            http_client,
        })
    }

    /// This new function is used by an in-pod client. It reads the KMS instance's
    /// private CA certificate from the by-default in-guest key path, mirroring the
    /// layout used by [`super::client_key_client::ClientKeyClient`].
    pub async fn from_provider_settings(provider_settings: &ProviderSettings) -> Result<Self> {
        let settings: AliAttestationProviderSettings =
            serde_json::from_value(Value::Object(provider_settings.clone())).map_err(|e| {
                Error::AliyunKmsError(format!("parse attestation provider setting failed: {e:?}"))
            })?;

        let cert_pem = load_kms_ca_cert(&settings).await?;

        Self::new(settings, &cert_pem)
    }

    /// Export the [`ProviderSettings`] of the current client.
    pub fn export_provider_settings(&self) -> Result<ProviderSettings> {
        let settings = AliAttestationProviderSettings {
            kms_instance_id: self.kms_instance_id.clone(),
            ecs_ram_role_name: match &self.credential_source {
                CredentialSource::EcsRamRole(name) => Some(name.clone()),
                CredentialSource::StsToken(_) => None,
            },
            sts_token: match &self.credential_source {
                CredentialSource::EcsRamRole(_) => None,
                CredentialSource::StsToken(credential) => Some(format!(
                    "{}:{}:{}",
                    credential.ak, credential.sk, credential.sts
                )),
            },
            kms_ca_cert: self.kms_ca_cert.clone(),
            tee: self.tee.clone(),
        };
        let provider_settings = serde_json::to_value(settings)
            .map_err(|e| {
                Error::AliyunKmsError(format!("serialize ProviderSettings failed: {e:?}"))
            })?
            .as_object()
            .expect("must be an object")
            .to_owned();
        Ok(provider_settings)
    }

    pub async fn get_secret(&self, name: &str, annotations: &Annotations) -> Result<Vec<u8>> {
        let secret_settings: AliSecretAnnotations =
            serde_json::from_value(Value::Object(annotations.clone())).map_err(|e| {
                Error::AliyunKmsError(format!(
                    "deserialize Secret annotations for get_secret failed: {e:?}"
                ))
            })?;

        self.get_secret_inner(name, &secret_settings)
            .await
            .map_err(|e| Error::AliyunKmsError(format!("attestation get_secret failed: {e:#}")))
    }

    async fn get_secret_inner(
        &self,
        name: &str,
        secret_settings: &AliSecretAnnotations,
    ) -> anyhow::Result<Vec<u8>> {
        let credential = self.get_session_credential().await?;

        let challenge = self
            .get_challenge(&credential)
            .await
            .context("GetChallenge")?;

        let keypair = RsaPrivateKey::new(&mut OsRng, RSA_KEY_BITS)
            .context("generate ephemeral RSA key pair")?;
        let recipient = self
            .build_recipient(&challenge, &keypair)
            .await
            .context("build attestation Recipient")?;

        let params = BTreeMap::from([
            ("SecretName".to_string(), name.to_string()),
            (
                "VersionStage".to_string(),
                secret_settings.version_stage.clone(),
            ),
            ("VersionId".to_string(), secret_settings.version_id.clone()),
            ("FetchExtendedConfig".to_string(), "true".to_string()),
            ("Recipient".to_string(), recipient),
        ]);

        let response = self
            .call_api(&credential, "GetSecretValue", params)
            .await
            .context("GetSecretValue")?;

        let ciphertext_for_recipient = response
            .get("CiphertextForRecipient")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("response has no CiphertextForRecipient field"))?;

        let ciphertext = STANDARD
            .decode(ciphertext_for_recipient)
            .context("base64-decode CiphertextForRecipient")?;

        let plaintext = keypair
            .decrypt(Oaep::new::<Sha256>(), &ciphertext)
            .map_err(|e| anyhow!("RSA-OAEP decrypt CiphertextForRecipient failed: {e:?}"))?;

        Ok(plaintext)
    }

    /// A `Challenge` is a fresh nonce plus a short-lived token signed by the AS, both
    /// bound into the evidence to defeat replay.
    async fn get_challenge(&self, credential: &StsCredential) -> anyhow::Result<Challenge> {
        let response = self
            .call_api(credential, "GetChallenge", BTreeMap::new())
            .await?;
        let nonce = response
            .get("Nonce")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("GetChallenge response has no Nonce"))?
            .to_string();
        let challenge_token = response
            .get("ChallengeToken")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("GetChallenge response has no ChallengeToken"))?
            .to_string();
        Ok(Challenge {
            nonce,
            challenge_token,
        })
    }

    /// Build the base64url(with padding) `attestationDocument` wrapped inside a
    /// `Recipient` JSON string, binding `keypair`'s public key into TEE evidence.
    async fn build_recipient(
        &self,
        challenge: &Challenge,
        keypair: &RsaPrivateKey,
    ) -> anyhow::Result<String> {
        let tee_pubkey = json!({
            "alg": "RSA",
            "k-exp": URL_SAFE_NO_PAD.encode(keypair.e().to_bytes_be()),
            "k-mod": URL_SAFE_NO_PAD.encode(keypair.n().to_bytes_be()),
        });
        let structured = json!({
            "challenge_token": challenge.challenge_token,
            "nonce": challenge.nonce,
            "tee-pubkey": tee_pubkey,
        });

        // report_data = SHA-384(canonical(structured)); the AS recomputes and compares
        // it against the report data embedded in the quote.
        let report_data = sha384_canonical(&structured)?;
        let evidence = self.get_evidence(report_data).await?;

        let attestation_document = json!({
            "tee": self.tee,
            "evidence": URL_SAFE_NO_PAD.encode(evidence),
            "runtime_data": { "structured": structured },
            "runtime_data_hash_algorithm": "sha384",
        });
        let attestation_document =
            serde_json::to_vec(&attestation_document).context("serialize attestationDocument")?;

        let recipient = json!({
            "type": "Trustee",
            "KeyEncryptionAlgorithm": KEY_ENCRYPTION_ALGORITHM,
            // NOTE: base64url WITH padding, matching the KMS Trustee parser.
            "attestationDocument": URL_SAFE.encode(attestation_document),
        });
        serde_json::to_string(&recipient).context("serialize Recipient")
    }

    /// Ask the attestation-agent to produce TEE evidence whose report data is
    /// `report_data` (the canonical SHA-384 of the structured runtime data).
    async fn get_evidence(&self, report_data: Vec<u8>) -> anyhow::Result<Vec<u8>> {
        let client = ttrpc::r#async::Client::connect(&self.aa_socket).map_err(|e| {
            anyhow!(
                "connect attestation-agent at {} failed: {e}",
                self.aa_socket
            )
        })?;
        let aa = AttestationAgentServiceClient::new(client);
        let req = GetEvidenceRequest {
            RuntimeData: report_data,
            ..Default::default()
        };
        let res = aa
            .get_evidence(context::with_timeout(AA_TTRPC_TIMEOUT_NANOS), &req)
            .await
            .map_err(|e| anyhow!("get evidence from attestation-agent failed: {e}"))?;
        Ok(res.Evidence)
    }

    async fn get_session_credential(&self) -> anyhow::Result<StsCredential> {
        match &self.credential_source {
            CredentialSource::StsToken(credential) => Ok(credential.clone()),
            CredentialSource::EcsRamRole(role_name) => {
                let request_url = format!(
                    "http://100.100.100.200/latest/meta-data/ram/security-credentials/{role_name}"
                );
                let response = reqwest::get(&request_url)
                    .await
                    .context("request STS session credential from IMDS")?;
                if !response.status().is_success() {
                    bail!(
                        "request session credential from IMDS failed with status: {}",
                        response.status()
                    );
                }
                let body = response.text().await?;
                serde_json::from_str(&body).context("parse IMDS STS credential")
            }
        }
    }

    const API_VERSION: &'static str = "2016-01-20";
    const SIGNATURE_METHOD: &'static str = "HMAC-SHA1";
    const SIGNATURE_VERSION: &'static str = "1.0";
    const FORMAT: &'static str = "JSON";

    /// Perform one signed POP RPC call against the dedicated instance endpoint. All
    /// parameters (including the STS `SecurityToken`) go into the url-encoded form body.
    async fn call_api(
        &self,
        credential: &StsCredential,
        action: &str,
        biz_params: BTreeMap<String, String>,
    ) -> anyhow::Result<Value> {
        let mut params = biz_params;
        params.insert("Action".to_string(), action.to_string());
        params.insert("Version".to_string(), Self::API_VERSION.to_string());
        params.insert("Format".to_string(), Self::FORMAT.to_string());
        params.insert("AccessKeyId".to_string(), credential.ak.clone());
        params.insert("SecurityToken".to_string(), credential.sts.clone());
        params.insert(
            "SignatureMethod".to_string(),
            Self::SIGNATURE_METHOD.to_string(),
        );
        params.insert(
            "SignatureVersion".to_string(),
            Self::SIGNATURE_VERSION.to_string(),
        );
        params.insert(
            "Timestamp".to_string(),
            Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        );
        let nonce: Vec<u8> = rand::rng().sample_iter(&Alphanumeric).take(16).collect();
        let nonce = nonce.iter().fold(String::new(), |mut out, b| {
            let _ = write!(out, "{b:02X}");
            out
        });
        params.insert("SignatureNonce".to_string(), nonce);

        // canonicalized query = sorted "k=v" joined by '&', each url-encoded (POP style)
        let canonicalized = params
            .iter()
            .map(|(k, v)| {
                format!(
                    "{}={}",
                    credential::urlencode_openapi(k),
                    credential::urlencode_openapi(v)
                )
            })
            .collect::<Vec<_>>()
            .join("&");
        let string_to_sign = format!("POST&%2F&{}", credential::urlencode_openapi(&canonicalized));
        let signature = credential::sign(&string_to_sign, &(credential.sk.clone() + "&"))?;
        params.insert("Signature".to_string(), signature);

        let body = params
            .iter()
            .map(|(k, v)| {
                format!(
                    "{}={}",
                    credential::urlencode_openapi(k),
                    credential::urlencode_openapi(v)
                )
            })
            .collect::<Vec<_>>()
            .join("&");

        debug!("aliyun kms attestation: calling {action}");
        let response = self
            .http_client
            .post(format!("https://{}/", self.endpoint))
            .header("Host", &self.endpoint)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(body)
            .send()
            .await?;

        let status = response.status();
        let text = response.text().await?;
        let value: Value = serde_json::from_str(&text)
            .with_context(|| format!("parse {action} response as JSON: {text}"))?;

        if !status.is_success() {
            bail!(
                "{action} failed, http status: {}, code: {}, message: {}, request id: {}",
                status,
                value.get("Code").and_then(Value::as_str).unwrap_or("-"),
                value.get("Message").and_then(Value::as_str).unwrap_or("-"),
                value
                    .get("RequestId")
                    .and_then(Value::as_str)
                    .unwrap_or("-"),
            );
        }
        Ok(value)
    }
}

struct Challenge {
    nonce: String,
    challenge_token: String,
}

fn credential_source(settings: &AliAttestationProviderSettings) -> Result<CredentialSource> {
    match (
        settings
            .ecs_ram_role_name
            .as_deref()
            .filter(|name| !name.trim().is_empty()),
        settings
            .sts_token
            .as_deref()
            .filter(|token| !token.trim().is_empty()),
    ) {
        (Some(role_name), None) => Ok(CredentialSource::EcsRamRole(role_name.to_owned())),
        (None, Some(token)) => parse_sts_token(token).map(CredentialSource::StsToken),
        (Some(_), Some(_)) => Err(Error::AliyunKmsError(
            "only one of ecs_ram_role_name and sts_token can be configured".to_string(),
        )),
        (None, None) => Err(Error::AliyunKmsError(
            "one of ecs_ram_role_name and sts_token must be configured".to_string(),
        )),
    }
}

fn parse_sts_token(token: &str) -> Result<StsCredential> {
    let mut sections = token.splitn(3, ':');
    let ak = sections.next().unwrap_or_default();
    let sk = sections.next().unwrap_or_default();
    let sts = sections.next().unwrap_or_default();
    if ak.is_empty() || sk.is_empty() || sts.is_empty() {
        return Err(Error::AliyunKmsError(
            "invalid sts_token format, expected AK:SK:STS".to_string(),
        ));
    }
    Ok(StsCredential {
        ak: ak.to_owned(),
        sk: sk.to_owned(),
        sts: sts.to_owned(),
    })
}

async fn load_kms_ca_cert(settings: &AliAttestationProviderSettings) -> Result<String> {
    if let Some(cert) = settings
        .kms_ca_cert
        .as_deref()
        .filter(|cert| !cert.trim().is_empty())
    {
        return Ok(cert.to_owned());
    }

    let key_path = env::var("ALIYUN_IN_GUEST_KEY_PATH")
        .unwrap_or_else(|_| ALIYUN_IN_GUEST_DEFAULT_KEY_PATH.to_owned());
    info!("ALIYUN_IN_GUEST_KEY_PATH = {}", key_path);

    let cert_path = format!("{}/PrivateKmsCA_{}.pem", key_path, settings.kms_instance_id);
    fs::read_to_string(&cert_path).await.map_err(|e| {
        Error::AliyunKmsError(format!(
            "read kms instance pem cert from {cert_path} failed: {e:?}"
        ))
    })
}

/// Serialize `value` with the same canonical JSON rules the AS uses (recursively
/// key-sorted, compact) and return its SHA-384 digest.
fn sha384_canonical(value: &Value) -> anyhow::Result<Vec<u8>> {
    let mut buf = Vec::new();
    let mut serializer =
        serde_json::Serializer::with_formatter(&mut buf, CanonicalFormatter::new());
    value.serialize(&mut serializer)?;
    Ok(Sha384::digest(&buf).to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_hash_is_order_independent() {
        let a = json!({
            "nonce": "n",
            "tee-pubkey": { "k-mod": "m", "alg": "RSA", "k-exp": "AQAB" },
            "challenge_token": "t",
        });
        let b = json!({
            "challenge_token": "t",
            "tee-pubkey": { "alg": "RSA", "k-exp": "AQAB", "k-mod": "m" },
            "nonce": "n",
        });
        let da = sha384_canonical(&a).unwrap();
        let db = sha384_canonical(&b).unwrap();
        assert_eq!(da, db);
        assert_eq!(da.len(), 48);
    }

    #[test]
    fn oaep_roundtrip_with_ephemeral_key() {
        // The KMS encrypts the secret with the exported public modulus/exponent and
        // RSAES-OAEP-SHA256; the ephemeral private key must recover it. This guards
        // against an OAEP hash mismatch (e.g. SHA-1) breaking decryption.
        use rsa::RsaPublicKey;

        let keypair = RsaPrivateKey::new(&mut OsRng, RSA_KEY_BITS).unwrap();
        let n = rsa::BigUint::from_bytes_be(&keypair.n().to_bytes_be());
        let e = rsa::BigUint::from_bytes_be(&keypair.e().to_bytes_be());
        let public = RsaPublicKey::new(n, e).unwrap();
        assert_eq!(public.size(), RSA_KEY_BITS / 8);

        let secret = b"1234567890";
        let ciphertext = public
            .encrypt(&mut OsRng, Oaep::new::<Sha256>(), secret)
            .unwrap();
        let recovered = keypair.decrypt(Oaep::new::<Sha256>(), &ciphertext).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn tee_pubkey_exponent_is_aqab() {
        let keypair = RsaPrivateKey::new(&mut OsRng, RSA_KEY_BITS).unwrap();
        assert_eq!(URL_SAFE_NO_PAD.encode(keypair.e().to_bytes_be()), "AQAB");
    }

    #[test]
    fn parse_direct_sts_token() {
        let credential = parse_sts_token("ak:sk:sts:with:colons").unwrap();
        assert_eq!(credential.ak, "ak");
        assert_eq!(credential.sk, "sk");
        assert_eq!(credential.sts, "sts:with:colons");
    }

    #[test]
    fn credential_source_must_be_unambiguous() {
        let settings = AliAttestationProviderSettings {
            kms_instance_id: "kst-test".to_string(),
            ecs_ram_role_name: Some("test-role".to_string()),
            sts_token: Some("ak:sk:sts".to_string()),
            kms_ca_cert: None,
            tee: default_tee(),
        };
        assert!(credential_source(&settings).is_err());
    }

    #[tokio::test]
    async fn embedded_ca_cert_takes_precedence_over_file() {
        let settings = AliAttestationProviderSettings {
            kms_instance_id: "kst-test".to_string(),
            ecs_ram_role_name: Some("test-role".to_string()),
            sts_token: None,
            kms_ca_cert: Some("-----BEGIN CERTIFICATE-----\ninline\n".to_string()),
            tee: default_tee(),
        };
        assert_eq!(
            load_kms_ca_cert(&settings).await.unwrap(),
            "-----BEGIN CERTIFICATE-----\ninline\n"
        );
    }

    #[test]
    fn legacy_region_id_is_ignored() {
        let settings: AliAttestationProviderSettings = serde_json::from_value(json!({
            "kms_instance_id": "kst-test",
            "region_id": "cn-hangzhou",
            "ecs_ram_role_name": "test-role"
        }))
        .unwrap();
        assert_eq!(settings.kms_instance_id, "kst-test");
        assert_eq!(settings.ecs_ram_role_name.as_deref(), Some("test-role"));
    }
}
