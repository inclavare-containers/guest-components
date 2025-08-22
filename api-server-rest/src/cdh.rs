// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use crate::router::ApiHandler;
use anyhow::*;
use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD, Engine};
use hyper::{body, Body, Method, Request, Response, StatusCode};
use protos::ttrpc::cdh::{
    api::{CommitResourceInjectionRequest, GetResourceRequest, PrepareResourceInjectionRequest},
    api_ttrpc::GetResourceServiceClient,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::net::SocketAddr;

use crate::utils::split_nth_slash;
use crate::TTRPC_TIMEOUT;

/// ROOT path for Confidential Data Hub API
pub const CDH_ROOT: &str = "/cdh";

/// URL for querying CDH get resource API
pub const CDH_RESOURCE_URL: &str = "/resource";
pub const CDH_RESOURCE_INJECTION_URL: &str = "/resource-injection";

const KBS_PREFIX: &str = "kbs://";

#[derive(Debug, Deserialize)]
struct PrepareInjectionBody {
    nonce: String,
}

#[derive(Debug, Deserialize)]
struct CommitInjectionBody {
    session_id: String,
    encrypted_resource: Value,
}

#[derive(Debug, Serialize)]
struct PrepareInjectionResponse {
    session_id: String,
    nonce: String,
    tee_pubkey: Value,
    evidence: String,
}

pub struct CDHClient {
    client: GetResourceServiceClient,
    accepted_method: Vec<Method>,
    allow_remote_resource_injection: bool,
}

#[async_trait]
impl ApiHandler for CDHClient {
    async fn handle_request(
        &self,
        remote_addr: SocketAddr,
        url_path: &str,
        req: Request<Body>,
    ) -> Result<Response<Body>> {
        if !self.accepted_method.iter().any(|i| i.eq(&req.method())) {
            // Return 405 Method Not Allowed response.
            return self.not_allowed();
        }

        if let Some((api, resource_path)) = split_nth_slash(url_path, 2) {
            match api {
                CDH_RESOURCE_URL => {
                    if !is_cdh_request_allowed(
                        remote_addr,
                        api,
                        self.allow_remote_resource_injection,
                    ) {
                        return self.forbidden();
                    }
                    match self.get_resource(resource_path).await {
                        std::result::Result::Ok(results) => {
                            return self.octet_stream_response(results)
                        }
                        Err(e) => return self.internal_error(e.to_string()),
                    }
                }
                CDH_RESOURCE_INJECTION_URL => {
                    if !is_cdh_request_allowed(
                        remote_addr,
                        api,
                        self.allow_remote_resource_injection,
                    ) {
                        return self.forbidden();
                    }
                    if let Some((operation, target)) = split_nth_slash(resource_path, 2) {
                        // Keep the leading slash for `/cdh/resource/...` to form `kbs:///...`,
                        // but strip it here because CDH injection expects a relative path.
                        let target = normalize_injection_resource_path(target);
                        match operation {
                            "/prepare" => {
                                if req.method() != Method::POST {
                                    return self.not_allowed();
                                }
                                let body_bytes = body::to_bytes(req.into_body())
                                    .await
                                    .context("read prepare injection body")?;
                                let payload: PrepareInjectionBody =
                                    serde_json::from_slice(&body_bytes)
                                        .context("parse prepare injection body")?;
                                match self.prepare_resource_injection(target, payload.nonce).await {
                                    std::result::Result::Ok(result) => {
                                        let body = serde_json::to_vec(&result)?;
                                        return Ok(Response::builder()
                                            .status(StatusCode::OK)
                                            .header("content-type", "application/json")
                                            .body(Body::from(body))?);
                                    }
                                    Err(e) => return self.internal_error(e.to_string()),
                                }
                            }
                            "/commit" => {
                                if req.method() != Method::POST {
                                    return self.not_allowed();
                                }
                                let body_bytes = body::to_bytes(req.into_body())
                                    .await
                                    .context("read commit injection body")?;
                                let payload: CommitInjectionBody =
                                    serde_json::from_slice(&body_bytes)
                                        .context("parse commit injection body")?;
                                let encrypted_resource =
                                    serde_json::to_vec(&payload.encrypted_resource)?;
                                match self
                                    .commit_resource_injection(
                                        target,
                                        payload.session_id,
                                        encrypted_resource,
                                    )
                                    .await
                                {
                                    std::result::Result::Ok(()) => {
                                        return Ok(Response::builder()
                                            .status(StatusCode::OK)
                                            .body(Body::empty())?)
                                    }
                                    Err(e) => return self.internal_error(e.to_string()),
                                }
                            }
                            _ => return self.not_found(),
                        }
                    }
                    return self.not_found();
                }
                _ => {
                    return self.not_found();
                }
            }
        }

        Ok(Response::builder().status(404).body(Body::empty())?)
    }
}

impl CDHClient {
    pub fn new(
        cdh_addr: &str,
        accepted_method: Vec<Method>,
        allow_remote_resource_injection: bool,
    ) -> Result<Self> {
        let inner = ttrpc::asynchronous::Client::connect(cdh_addr)
            .context(format!("ttrpc connect to CDH addr: {} failed!", cdh_addr))?;
        let client = GetResourceServiceClient::new(inner);

        Ok(Self {
            client,
            accepted_method,
            allow_remote_resource_injection,
        })
    }

    pub async fn get_resource(&self, resource_path: &str) -> Result<Vec<u8>> {
        let req = GetResourceRequest {
            ResourcePath: build_kbs_resource_uri(resource_path),
            ..Default::default()
        };
        let res = self
            .client
            .get_resource(ttrpc::context::with_timeout(TTRPC_TIMEOUT), &req)
            .await?;
        Ok(res.Resource)
    }

    async fn prepare_resource_injection(
        &self,
        resource_path: &str,
        nonce: String,
    ) -> Result<PrepareInjectionResponse> {
        let req = PrepareResourceInjectionRequest {
            ResourcePath: resource_path.to_string(),
            Nonce: nonce,
            ..Default::default()
        };
        let res = self
            .client
            .prepare_resource_injection(ttrpc::context::with_timeout(TTRPC_TIMEOUT), &req)
            .await?;
        let tee_pubkey: Value = serde_json::from_str(&res.TeePubKey)
            .context("parse CDH tee pubkey from prepare response")?;
        Ok(PrepareInjectionResponse {
            session_id: res.SessionId,
            nonce: res.Nonce,
            tee_pubkey,
            evidence: STANDARD.encode(res.Evidence),
        })
    }

    async fn commit_resource_injection(
        &self,
        resource_path: &str,
        session_id: String,
        encrypted_resource: Vec<u8>,
    ) -> Result<()> {
        let req = CommitResourceInjectionRequest {
            SessionId: session_id,
            ResourcePath: resource_path.to_string(),
            EncryptedResource: encrypted_resource,
            ..Default::default()
        };
        self.client
            .commit_resource_injection(ttrpc::context::with_timeout(TTRPC_TIMEOUT), &req)
            .await?;
        Ok(())
    }
}

fn is_cdh_request_allowed(
    remote_addr: SocketAddr,
    api: &str,
    allow_remote_resource_injection: bool,
) -> bool {
    if remote_addr.ip().is_loopback() {
        return true;
    }

    matches!(api, CDH_RESOURCE_INJECTION_URL) && allow_remote_resource_injection
}

fn normalize_injection_resource_path(resource_path: &str) -> &str {
    resource_path.trim_start_matches('/')
}

fn build_kbs_resource_uri(resource_path: &str) -> String {
    format!("{KBS_PREFIX}{resource_path}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn local_addr() -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], 8006))
    }

    fn remote_addr() -> SocketAddr {
        SocketAddr::from(([10, 0, 0, 8], 8006))
    }

    #[test]
    fn local_cdh_requests_are_always_allowed() {
        assert!(is_cdh_request_allowed(
            local_addr(),
            CDH_RESOURCE_URL,
            false
        ));
        assert!(is_cdh_request_allowed(
            local_addr(),
            CDH_RESOURCE_INJECTION_URL,
            false
        ));
    }

    #[test]
    fn remote_resource_injection_access_is_configurable() {
        assert!(!is_cdh_request_allowed(
            remote_addr(),
            CDH_RESOURCE_INJECTION_URL,
            false
        ));
        assert!(is_cdh_request_allowed(
            remote_addr(),
            CDH_RESOURCE_INJECTION_URL,
            true
        ));
    }

    #[test]
    fn remote_get_resource_remains_forbidden() {
        assert!(!is_cdh_request_allowed(
            remote_addr(),
            CDH_RESOURCE_URL,
            false
        ));
        assert!(!is_cdh_request_allowed(
            remote_addr(),
            CDH_RESOURCE_URL,
            true
        ));
    }

    #[test]
    fn normalize_injection_resource_path_strips_leading_slash() {
        assert_eq!(
            normalize_injection_resource_path("/default/key/1"),
            "default/key/1"
        );
        assert_eq!(
            normalize_injection_resource_path("default/key/1"),
            "default/key/1"
        );
    }

    #[test]
    fn build_kbs_resource_uri_preserves_leading_slash_for_get_resource() {
        assert_eq!(
            build_kbs_resource_uri("/default/key/1"),
            "kbs:///default/key/1"
        );
    }
}
