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
                    let options = match resource_query(req.uri().query()) {
                        std::result::Result::Ok(options) => options,
                        Err(_) => return self.bad_request(),
                    };
                    match self.get_resource(resource_path, options).await {
                        std::result::Result::Ok(results) => {
                            return self.octet_stream_response(results)
                        }
                        Err(e) => return self.rpc_error_response(e),
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
            .context(format!("ttrpc connect to CDH addr: {cdh_addr} failed!"))?;
        let client = GetResourceServiceClient::new(inner);

        Ok(Self {
            client,
            accepted_method,
            allow_remote_resource_injection,
        })
    }

    pub async fn get_resource(
        &self,
        resource_path: &str,
        mut req: GetResourceRequest,
    ) -> Result<Vec<u8>> {
        req.ResourcePath = build_kbs_resource_uri(resource_path);
        let ctx = ttrpc::context::with_timeout(TTRPC_TIMEOUT);
        let res = if req.Type.is_some() || !req.Options.is_empty() {
            self.client.get_resource_with_options(ctx, &req).await?
        } else {
            self.client.get_resource(ctx, &req).await?
        };
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

// This proxy only decodes the transport envelope. CDH interprets provider options.
// Reject duplicates before collecting a map; otherwise authorization options can
// silently overwrite each other. Never include query values in an error.
fn resource_query(query: Option<&str>) -> Result<GetResourceRequest> {
    let mut req = GetResourceRequest::default();
    let query = query.unwrap_or_default();
    ensure!(query.len() <= 20 * 1024, "resource query is too large");
    for (key, value) in form_urlencoded::parse(query.as_bytes()) {
        if key == "type" {
            ensure!(req.Type.is_none(), "duplicate resource query parameter");
            req.Type = Some(value.into_owned());
        } else {
            ensure!(
                req.Options
                    .insert(key.into_owned(), value.into_owned())
                    .is_none(),
                "duplicate resource query parameter"
            );
        }
    }
    Ok(req)
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

    #[test]
    fn resource_options_are_optional_independent_and_url_decoded() {
        let empty = resource_query(None).unwrap();
        assert!(empty.Type.is_none() && empty.Options.is_empty());
        for (query, key, value) in [
            ("sts=YWJj", "sts", "YWJj"),
            ("kms_id=kst-test", "kms_id", "kst-test"),
            ("region_id=cn-beijing", "region_id", "cn-beijing"),
        ] {
            let req = resource_query(Some(query)).unwrap();
            assert!(req.Type.is_none());
            assert_eq!(req.Options.len(), 1);
            assert_eq!(req.Options[key], value);
        }
        let req = resource_query(Some(
            "type=aliyun_kms&sts=YWJj%2B%2F%3D&kms_id=kst-test&region_id=cn-beijing",
        ))
        .unwrap();
        assert_eq!(req.Type.as_deref(), Some("aliyun_kms"));
        assert_eq!(req.Options["sts"], "YWJj+/=");
        assert_eq!(req.Options["kms_id"], "kst-test");
        assert_eq!(req.Options["region_id"], "cn-beijing");
        assert_eq!(req.Options.len(), 3);
    }

    #[test]
    fn proxy_rejects_duplicates_and_bounds_but_does_not_validate_provider_values() {
        for query in [
            "sts=a&sts=b",
            "kms_id=kst-a&kms_id=kst-b",
            "region_id=cn-beijing&region_id=cn-hangzhou",
            "type=kbs&type=aliyun_kms",
            "private-marker=a&private-marker=b",
        ] {
            let error = resource_query(Some(query)).err().unwrap();
            assert!(!error.to_string().contains("private-marker"));
        }
        assert!(resource_query(Some(&"a".repeat(20 * 1024 + 1))).is_err());
        for query in [
            "sts=",
            "kms_id=https%3A%2F%2Fexample.test",
            "region_id=cn%2Fbeijing",
            "future_option=private-marker",
        ] {
            assert!(resource_query(Some(query)).is_ok());
        }
    }

    struct ResourceMock;

    #[async_trait]
    impl protos::ttrpc::cdh::api_ttrpc::GetResourceService for ResourceMock {
        async fn get_resource(
            &self,
            _ctx: &ttrpc::asynchronous::TtrpcContext,
            req: GetResourceRequest,
        ) -> ttrpc::Result<protos::ttrpc::cdh::api::GetResourceResponse> {
            assert_eq!(req.ResourcePath, "kbs:///my-secret");
            assert!(req.Type.is_none() && req.Options.is_empty());
            std::result::Result::Ok(protos::ttrpc::cdh::api::GetResourceResponse {
                Resource: b"legacy".to_vec(),
                ..Default::default()
            })
        }

        async fn get_resource_with_options(
            &self,
            _ctx: &ttrpc::asynchronous::TtrpcContext,
            req: GetResourceRequest,
        ) -> ttrpc::Result<protos::ttrpc::cdh::api::GetResourceResponse> {
            assert_eq!(req.ResourcePath, "kbs:///my-secret");
            if req.Options.get("kms_id").map(String::as_str) == Some("kst-invalid")
                || req.Options.values().any(String::is_empty)
            {
                let mut status = ttrpc::Status::new();
                status.set_code(ttrpc::Code::INVALID_ARGUMENT);
                status.set_message("private-marker must not be exposed by REST".into());
                return Err(ttrpc::Error::RpcStatus(status));
            }
            if let Some(resource_type) = req.Type.as_deref() {
                assert_eq!(resource_type, "aliyun_kms");
            }
            assert_eq!(req.Options["region_id"], "cn-beijing");
            if !req.Options.contains_key("sts") && !req.Options.contains_key("kms_id") {
                return std::result::Result::Ok(protos::ttrpc::cdh::api::GetResourceResponse {
                    Resource: b"region-only".to_vec(),
                    ..Default::default()
                });
            }
            assert_eq!(req.Options["sts"], "YWJj+/=");
            assert_eq!(req.Options["kms_id"], "kst-test");
            std::result::Result::Ok(protos::ttrpc::cdh::api::GetResourceResponse {
                Resource: vec![0, 255, 1],
                ..Default::default()
            })
        }
    }

    #[tokio::test]
    async fn rest_forwards_options_through_ttrpc_and_preserves_legacy_requests() {
        use std::sync::Arc;
        let dir = tempfile::tempdir().unwrap();
        let socket = format!("unix://{}/cdh.sock", dir.path().display());
        let services =
            protos::ttrpc::cdh::api_ttrpc::create_get_resource_service(Arc::new(ResourceMock));
        let mut server = ttrpc::asynchronous::Server::new()
            .bind(&socket)
            .unwrap()
            .register_service(services);
        server.start().await.unwrap();
        let client = CDHClient::new(&socket, vec![Method::GET], false).unwrap();
        for (query, status, expected) in [
            ("", StatusCode::OK, b"legacy".as_slice()),
            (
                "?sts=YWJj%2B%2F%3D&kms_id=kst-test&region_id=cn-beijing",
                StatusCode::OK,
                &[0, 255, 1],
            ),
            (
                "?region_id=cn-beijing",
                StatusCode::OK,
                b"region-only".as_slice(),
            ),
            (
                "?type=aliyun_kms&sts=YWJj%2B%2F%3D&kms_id=kst-test&region_id=cn-beijing",
                StatusCode::OK,
                &[0, 255, 1],
            ),
            (
                "?region_id=",
                StatusCode::BAD_REQUEST,
                b"BAD REQUEST".as_slice(),
            ),
            (
                "?kms_id=kst-invalid",
                StatusCode::BAD_REQUEST,
                b"BAD REQUEST".as_slice(),
            ),
            ("?sts=", StatusCode::BAD_REQUEST, b"BAD REQUEST".as_slice()),
        ] {
            let request = Request::builder()
                .uri(format!("/cdh/resource/my-secret{query}"))
                .body(Body::empty())
                .unwrap();
            let response = client
                .handle_request(local_addr(), "/resource/my-secret", request)
                .await
                .unwrap();
            assert_eq!(response.status(), status);
            if status == StatusCode::OK {
                assert_eq!(
                    response.headers()["content-type"],
                    "application/octet-stream"
                );
            }
            assert_eq!(
                body::to_bytes(response.into_body()).await.unwrap().as_ref(),
                expected
            );
        }
        server.shutdown().await.unwrap();
    }

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
