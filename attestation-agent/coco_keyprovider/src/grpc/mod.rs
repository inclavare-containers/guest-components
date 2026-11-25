// Copyright (c) 2021 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use crate::enc_mods;
use anyhow::*;
use base64::Engine;
use jwt_simple::prelude::Ed25519KeyPair;
use log::*;
use protos::grpc::cdh::keyprovider::{
    key_provider_service_server::{KeyProviderService, KeyProviderServiceServer},
    KeyProviderKeyWrapProtocolInput, KeyProviderKeyWrapProtocolOutput,
};
use reqwest::Url;
use std::net::SocketAddr;
use std::path::PathBuf;
use tokio::fs;
use tonic::{transport::Server, Request, Response, Status};

use protocol::keyprovider_structs::*;

pub mod protocol;

pub struct KeyProvider {
    auth_private_key: Option<Ed25519KeyPair>,
    kbs: Option<Url>,
}

impl KeyProvider {
    pub fn new(auth_private_key: Option<Ed25519KeyPair>, kbs: Option<String>) -> Result<Self> {
        let kbs = match kbs {
            Some(addr) => addr.parse().ok(),
            None => None,
        };

        Ok(Self {
            auth_private_key,
            kbs,
        })
    }
}

#[tonic::async_trait]
impl KeyProviderService for KeyProvider {
    async fn wrap_key(
        &self,
        request: Request<KeyProviderKeyWrapProtocolInput>,
    ) -> Result<Response<KeyProviderKeyWrapProtocolOutput>, Status> {
        let input_string = String::from_utf8(
            request.into_inner().key_provider_key_wrap_protocol_input,
        )
        .map_err(|e| {
            Status::invalid_argument(format!(
                "key_provider_key_wrap_protocol_input is not legal utf8 string: {e:?}"
            ))
        })?;

        let input: KeyProviderInput = serde_json::from_str::<KeyProviderInput>(&input_string)
            .map_err(|e| {
                Status::invalid_argument(format!("parse key provider input failed: {e:?}"))
            })?;
        let optsdata = input
            .keywrapparams
            .optsdata
            .ok_or_else(|| Status::invalid_argument("illegal keywrapparams without optsdata"))?;

        let engine = base64::engine::general_purpose::STANDARD;
        let params = input
            .keywrapparams
            .ec
            .ok_or_else(|| Status::invalid_argument("illegal keywrapparams without ec"))?
            .parameters
            .get("attestation-agent")
            .ok_or_else(|| {
                Status::invalid_argument("illegal encryption provider without attestation-agent")
            })?
            .iter()
            // According to
            // https://github.com/containers/ocicrypt/blob/e4a936881fb7cf4b2b8fe49e81b8232fd4c48e97/config/constructors.go#L112,
            // the vector normally has one element. Use the first usable parameters string.
            .find_map(|p| {
                engine
                    .decode(p)
                    .ok()
                    .and_then(|st| String::from_utf8(st).ok())
            })
            .ok_or_else(|| Status::invalid_argument("missing encryption parameters"))?;

        let annotation: String = enc_mods::enc_optsdata_gen_anno(
            (&self.kbs, &self.auth_private_key),
            &engine
                .decode(optsdata)
                .map_err(|_| Status::aborted("base64 decode"))?,
            &params,
        )
        .await
        .map_err(|e| Status::internal(format!("encrypt failed: {e:?}")))?;

        let output_struct = KeyWrapOutput {
            keywrapresults: KeyWrapResults {
                annotation: annotation.as_bytes().to_vec(),
            },
        };
        let output = serde_json::to_string(&output_struct)
            .map_err(|e| Status::internal(format!("serde json failed: {e:?}")))?
            .as_bytes()
            .to_vec();
        debug!(
            "WrapKey API output: {}",
            serde_json::to_string(&output_struct)
                .map_err(|e| Status::internal(format!("serde json failed: {e:?}")))?
        );
        let reply = KeyProviderKeyWrapProtocolOutput {
            key_provider_key_wrap_protocol_output: output,
        };
        debug!("Reply successfully!");

        Result::Ok(Response::new(reply))
    }

    async fn un_wrap_key(
        &self,
        _request: Request<KeyProviderKeyWrapProtocolInput>,
    ) -> Result<Response<KeyProviderKeyWrapProtocolOutput>, Status> {
        debug!("The UnWrapKey API is called...");
        debug!("UnWrapKey API is unimplemented!");
        Err(Status::unimplemented(
            "UnWrapKey API of sample-kbs is unimplemented!",
        ))
    }
}

pub async fn start_service(
    socket: SocketAddr,
    auth_private_key: Option<PathBuf>,
    kbs: Option<String>,
) -> Result<()> {
    let auth_private_key = match auth_private_key {
        Some(key_path) => {
            let pem = fs::read_to_string(key_path)
                .await
                .context("open auth private key")?;

            Some(Ed25519KeyPair::from_pem(&pem)?)
        }
        None => None,
    };

    Server::builder()
        .add_service(KeyProviderServiceServer::new(KeyProvider::new(
            auth_private_key,
            kbs,
        )?))
        .serve(socket)
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
    use rand::TryRngCore;
    use rstest::rstest;
    use std::io::Write;

    #[rstest]
    #[case("")]
    #[case("::algorithm=A256GCM")]
    #[case("::algorithm=A256CTR")]
    #[tokio::test]
    async fn wrap_key_emits_a256gcm(#[case] algorithm_param: &str) {
        let provider = KeyProvider::new(None, None).unwrap();
        let engine = base64::engine::general_purpose::STANDARD;
        let mut key = [0; 32];
        rand::rngs::OsRng.try_fill_bytes(&mut key).unwrap();
        let mut key_file = tempfile::NamedTempFile::new().unwrap();
        key_file.write_all(&key).unwrap();
        let kid = "kbs:///default/key/test-wrap-key";
        let params = format!(
            "keypath={}::keyid={kid}{algorithm_param}",
            key_file.path().display()
        );
        let optsdata = b"layer options";
        let input = serde_json::json!({
            "op": "keywrap",
            "keywrapparams": {
                "ec": {
                    "Parameters": {"attestation-agent": [engine.encode(params)]},
                    "DecryptConfig": {"Parameters": {}},
                },
                "optsdata": engine.encode(optsdata),
            },
            "keyunwrapparams": {},
        });
        let request = Request::new(KeyProviderKeyWrapProtocolInput {
            key_provider_key_wrap_protocol_input: serde_json::to_vec(&input).unwrap(),
        });

        let body = provider.wrap_key(request).await.unwrap().into_inner();
        let output: KeyWrapOutput =
            serde_json::from_slice(&body.key_provider_key_wrap_protocol_output).unwrap();
        let annotation: enc_mods::AnnotationPacket =
            serde_json::from_slice(&output.keywrapresults.annotation).unwrap();
        assert_eq!(annotation.kid, kid);
        assert_eq!(annotation.wrap_type, "A256GCM");
        let iv = engine.decode(annotation.iv).unwrap();
        assert_eq!(iv.len(), 12);
        let wrapped_data = engine.decode(annotation.wrapped_data).unwrap();
        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
        assert_eq!(
            cipher
                .decrypt(Nonce::from_slice(&iv), wrapped_data.as_slice())
                .unwrap(),
            &optsdata[..],
        );
    }
}
