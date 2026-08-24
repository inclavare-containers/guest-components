// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! # KBS Clients
//!
//! There are two different kinds of KBS clients:
//! - `RCAR Client`: s.t. `KbsClient<Box<dyn EvidenceProvider>>`. It can
//!   perform RCAR handshaking, get token and get resource using the
//!   authenticated http session.
//! - `Token Client`: s.t. `KbsClient<Box<dyn TokenProvider>>`. It is a
//!   simpler client. It can only get resource with a valid token as its
//!   authentication materials.

#[cfg(feature = "background_check")]
pub mod rcar_client;

#[cfg(feature = "passport")]
pub mod token_client;

use kbs_types::{Response, Tee};
use reqwest::header::CONTENT_TYPE;
use resource_uri::ResourceUri;

use crate::{keypair::TeeKeyPair, token_provider::Token, Error, Result};

pub(crate) enum ClientTee {
    Uninitialized,
    _Initialized(Tee),
}

/// This Client is used to connect to the remote KBS.
pub struct KbsClient<T> {
    /// TEE Type
    pub(crate) _tee: ClientTee,

    /// The asymmetric key pair inside the TEE
    pub(crate) tee_key: TeeKeyPair,

    pub(crate) provider: T,

    /// Http client
    pub(crate) http_client: reqwest::Client,

    /// KBS Host URL
    pub(crate) kbs_host_url: String,

    /// token
    pub(crate) token: Option<Token>,

    /// initdata toml plaintext (if any)
    pub(crate) _initdata: Option<String>,
}

pub const KBS_PROTOCOL_VERSION: &str = "0.4.0";

pub const KBS_GET_RESOURCE_MAX_ATTEMPT: u64 = 3;

pub const KBS_PREFIX: &str = "kbs/v0";

impl<T> KbsClient<T> {
    /// Decode a successful plugin response according to Trustee's response
    /// contract. Encrypted plugin responses use the KBS JWE JSON envelope;
    /// plaintext plugins use a non-JSON content type and return their bytes
    /// directly.
    async fn decode_resource_response(&self, response: reqwest::Response) -> Result<Vec<u8>> {
        let content_type = response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok());

        if !is_encrypted_resource_response(content_type) {
            return response
                .bytes()
                .await
                .map(|body| body.to_vec())
                .map_err(|error| Error::KbsResponseDeserializationFailed(error.to_string()));
        }

        let response = response
            .json::<Response>()
            .await
            .map_err(|error| Error::KbsResponseDeserializationFailed(error.to_string()))?;
        self.tee_key
            .decrypt_response(response)
            .map_err(|error| Error::DecryptResponseFailed(error.to_string()))
    }
}

fn is_encrypted_resource_response(content_type: Option<&str>) -> bool {
    // KBS resource responses historically omitted Content-Type in some
    // deployments, so keep the encrypted JWE behavior as the safe default.
    content_type
        .map(|value| {
            value
                .split(';')
                .next()
                .unwrap_or_default()
                .trim()
                .eq_ignore_ascii_case("application/json")
        })
        .unwrap_or(true)
}

pub(crate) fn resource_url(kbs_host_url: &str, resource_uri: &ResourceUri) -> String {
    let mut url = format!(
        "{}/{KBS_PREFIX}/{}/{}",
        kbs_host_url.trim_end_matches('/'),
        resource_uri.plugin(),
        resource_uri.resource_path(),
    );

    if let Some(query) = &resource_uri.query {
        url.push('?');
        url.push_str(query);
    }

    url
}

#[cfg(test)]
mod tests {
    use super::{is_encrypted_resource_response, resource_url};
    use resource_uri::ResourceUri;
    use rstest::rstest;

    #[cfg(feature = "background_check")]
    use {
        crate::{
            evidence_provider::{mock::MockedEvidenceProvider, EvidenceProvider},
            KbsClientBuilder, KbsClientCapabilities,
        },
        tokio::io::{AsyncReadExt, AsyncWriteExt},
        tokio::net::TcpListener,
    };

    #[rstest]
    #[case(
        "https://kbs.example.com/",
        "kbs:///repo/type/tag",
        "https://kbs.example.com/kbs/v0/resource/repo/type/tag"
    )]
    #[case(
        "https://kbs.example.com",
        "kbs+pkcs11:///slot/key/label/version?pin-source=file",
        "https://kbs.example.com/kbs/v0/pkcs11/slot/key/label/version?pin-source=file"
    )]
    fn builds_openanolis_trustee_plugin_route(
        #[case] base: &str,
        #[case] uri: &str,
        #[case] expected: &str,
    ) {
        let resource_uri = ResourceUri::try_from(uri).unwrap();
        assert_eq!(resource_url(base, &resource_uri), expected);
    }

    #[rstest]
    #[case(None, true)]
    #[case(Some("application/json"), true)]
    #[case(Some("application/json; charset=utf-8"), true)]
    #[case(Some("text/xml"), false)]
    #[case(Some("application/octet-stream"), false)]
    fn classifies_encrypted_and_plaintext_plugin_responses(
        #[case] content_type: Option<&str>,
        #[case] expected: bool,
    ) {
        assert_eq!(is_encrypted_resource_response(content_type), expected);
    }

    #[cfg(feature = "background_check")]
    #[tokio::test]
    async fn returns_plaintext_plugin_response_with_arbitrary_path_and_query() {
        const BODY: &[u8] = b"sample plugin response";

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = vec![0; 4096];
            let bytes_read = stream.read(&mut request).await.unwrap();
            let request = String::from_utf8_lossy(&request[..bytes_read]);
            assert!(request
                .starts_with("GET /kbs/v0/sample/path/with/arbitrary/depth?mode=test HTTP/1.1"));

            let headers = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: text/xml\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                BODY.len()
            );
            stream.write_all(headers.as_bytes()).await.unwrap();
            stream.write_all(BODY).await.unwrap();
        });

        let provider: Box<dyn EvidenceProvider> = Box::new(MockedEvidenceProvider::default());
        let mut client =
            KbsClientBuilder::with_evidence_provider(provider, &format!("http://{address}"))
                .build()
                .unwrap();
        let resource_uri =
            ResourceUri::try_from("kbs+sample:///path/with/arbitrary/depth?mode=test").unwrap();

        let response = client.get_resource(resource_uri).await.unwrap();
        server.await.unwrap();
        assert_eq!(response, BODY);
    }
}
