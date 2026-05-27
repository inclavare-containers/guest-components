// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use crate::router::ApiHandler;
use crate::TTRPC_TIMEOUT;
use anyhow::*;
use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use hyper::{body, Body, Method, Request, Response};
use protos::ttrpc::aa::attestation_agent::{
    ExtendRuntimeMeasurementRequest, GetAdditionalTeesRequest, GetEvidenceRequest,
    GetTeeTypeRequest, GetTokenRequest,
};
use protos::ttrpc::aa::attestation_agent_ttrpc::AttestationAgentServiceClient;
use serde::Deserialize;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

/// ROOT path for Confidential Data Hub API
pub const AA_ROOT: &str = "/aa";

/// URL for querying CDH get resource API
const AA_TOKEN_URL: &str = "/token";
const AA_EVIDENCE_URL: &str = "/evidence";
const AA_AAEL_URL: &str = "/aael";

#[derive(Debug, Deserialize)]
struct AaelRequest {
    domain: String,
    operation: String,
    content: String,
    #[serde(default)]
    register_index: Option<u64>,
}

pub struct AAClient {
    client: AttestationAgentServiceClient,
    accepted_method: Vec<Method>,
    allow_remote_get_evidence: bool,
}

#[async_trait]
impl ApiHandler for Arc<AAClient> {
    async fn handle_request(
        &self,
        remote_addr: SocketAddr,
        url_path: &str,
        req: Request<Body>,
    ) -> Result<Response<Body>> {
        self.as_ref()
            .handle_request(remote_addr, url_path, req)
            .await
    }
}

#[async_trait]
impl ApiHandler for AAClient {
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

        let params: HashMap<String, String> = req
            .uri()
            .query()
            .map(|v| form_urlencoded::parse(v.as_bytes()).into_owned().collect())
            .unwrap_or_default();

        match url_path {
            AA_TOKEN_URL => {
                if !is_aa_request_allowed(remote_addr, url_path, self.allow_remote_get_evidence) {
                    return self.forbidden();
                }
                if req.method() != Method::GET {
                    return self.not_allowed();
                }
                if params.len() != 1 {
                    return self.not_allowed();
                }
                match params.get("token_type") {
                    Some(token_type) => match self.get_token(token_type).await {
                        std::result::Result::Ok(results) => {
                            return self.octet_stream_response(results)
                        }
                        Err(e) => return self.internal_error(e.to_string()),
                    },
                    None => return self.bad_request(),
                }
            }
            AA_EVIDENCE_URL => {
                if !is_aa_request_allowed(remote_addr, url_path, self.allow_remote_get_evidence) {
                    return self.forbidden();
                }
                if req.method() != Method::GET {
                    return self.not_allowed();
                }
                if params.get("runtime_data").is_none() {
                    return self.bad_request();
                }
                if params
                    .keys()
                    .any(|key| key != "runtime_data" && key != "encoding")
                {
                    return self.bad_request();
                }

                match params.get("runtime_data") {
                    Some(runtime_data) => {
                        let encoding = params.get("encoding").map(String::as_str);
                        let runtime_data =
                            match parse_evidence_runtime_data(runtime_data, encoding) {
                                std::result::Result::Ok(runtime_data) => runtime_data,
                                std::result::Result::Err(_) => return self.bad_request(),
                            };
                        match self.get_evidence(&runtime_data).await {
                            std::result::Result::Ok(results) => {
                                return self.octet_stream_response(results)
                            }
                            Err(e) => return self.internal_error(e.to_string()),
                        }
                    }
                    None => return self.bad_request(),
                }
            }
            AA_AAEL_URL => {
                if !is_aa_request_allowed(remote_addr, url_path, self.allow_remote_get_evidence) {
                    return self.forbidden();
                }
                if req.method() != Method::POST {
                    return self.not_allowed();
                }
                let body_bytes = body::to_bytes(req.into_body())
                    .await
                    .map_err(|e| anyhow!("Failed to read request body: {}", e))?;
                let payload: AaelRequest = serde_json::from_slice(&body_bytes)
                    .map_err(|e| anyhow!("Failed to parse request body as JSON: {}", e))?;
                match self
                    .extend_runtime_measurement(
                        payload.register_index,
                        &payload.domain,
                        &payload.operation,
                        &payload.content,
                    )
                    .await
                {
                    std::result::Result::Ok(_) => {
                        return Ok(Response::builder()
                            .status(hyper::StatusCode::OK)
                            .body(Body::empty())?)
                    }
                    Err(e) => return self.internal_error(e.to_string()),
                }
            }
            _ => {
                return self.not_found();
            }
        }
    }
}

impl AAClient {
    pub fn new(
        aa_addr: &str,
        accepted_method: Vec<Method>,
        allow_remote_get_evidence: bool,
    ) -> Result<Self> {
        let inner = ttrpc::asynchronous::Client::connect(aa_addr)
            .context(format!("ttrpc connect to AA addr: {} failed!", aa_addr))?;
        let client = AttestationAgentServiceClient::new(inner);

        Ok(Self {
            client,
            accepted_method,
            allow_remote_get_evidence,
        })
    }

    pub async fn get_token(&self, token_type: &str) -> Result<Vec<u8>> {
        let req = GetTokenRequest {
            TokenType: token_type.to_string(),
            ..Default::default()
        };
        let res = self
            .client
            .get_token(ttrpc::context::with_timeout(TTRPC_TIMEOUT), &req)
            .await?;
        Ok(res.Token)
    }

    pub async fn get_tee_type(&self) -> Result<String> {
        let req = GetTeeTypeRequest {
            ..Default::default()
        };
        let res = self
            .client
            .get_tee_type(ttrpc::context::with_timeout(TTRPC_TIMEOUT), &req)
            .await?;
        Ok(res.tee)
    }

    pub async fn get_additional_tees(&self) -> Result<Vec<String>> {
        let req = GetAdditionalTeesRequest {
            ..Default::default()
        };
        let res = self
            .client
            .get_additional_tees(ttrpc::context::with_timeout(TTRPC_TIMEOUT), &req)
            .await?;
        Ok(res.additional_tees)
    }

    pub async fn get_evidence(&self, runtime_data: &[u8]) -> Result<Vec<u8>> {
        let req = GetEvidenceRequest {
            RuntimeData: runtime_data.to_vec(),
            ..Default::default()
        };
        let res = self
            .client
            .get_evidence(ttrpc::context::with_timeout(TTRPC_TIMEOUT), &req)
            .await?;
        Ok(res.Evidence)
    }

    pub async fn extend_runtime_measurement(
        &self,
        register_index: Option<u64>,
        domain: &str,
        operation: &str,
        content: &str,
    ) -> Result<()> {
        let req = ExtendRuntimeMeasurementRequest {
            Domain: domain.to_string(),
            Operation: operation.to_string(),
            Content: content.to_string(),
            RegisterIndex: register_index,
            ..Default::default()
        };

        self.client
            .extend_runtime_measurement(ttrpc::context::with_timeout(TTRPC_TIMEOUT), &req)
            .await
            .context("ttrpc extend_runtime_measurement failed")?;
        Ok(())
    }
}

fn is_aa_request_allowed(
    remote_addr: SocketAddr,
    url_path: &str,
    allow_remote_get_evidence: bool,
) -> bool {
    if remote_addr.ip().is_loopback() {
        return true;
    }

    matches!(url_path, AA_EVIDENCE_URL) && allow_remote_get_evidence
}

fn parse_evidence_runtime_data(runtime_data: &str, encoding: Option<&str>) -> Result<Vec<u8>> {
    match encoding {
        None => Ok(runtime_data.as_bytes().to_vec()),
        Some("base64") => URL_SAFE_NO_PAD
            .decode(runtime_data)
            .context("Failed to decode runtime_data as base64 URL-safe no padding"),
        Some(other) => bail!("Unsupported encoding: {other}"),
    }
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
    fn local_requests_are_always_allowed() {
        assert!(is_aa_request_allowed(local_addr(), AA_TOKEN_URL, false));
        assert!(is_aa_request_allowed(local_addr(), AA_EVIDENCE_URL, false));
        assert!(is_aa_request_allowed(local_addr(), AA_AAEL_URL, false));
    }

    #[test]
    fn remote_evidence_access_is_configurable() {
        assert!(!is_aa_request_allowed(
            remote_addr(),
            AA_EVIDENCE_URL,
            false
        ));
        assert!(is_aa_request_allowed(remote_addr(), AA_EVIDENCE_URL, true));
    }

    #[test]
    fn remote_non_evidence_aa_apis_remain_forbidden() {
        assert!(!is_aa_request_allowed(remote_addr(), AA_TOKEN_URL, true));
        assert!(!is_aa_request_allowed(remote_addr(), AA_AAEL_URL, true));
    }

    #[test]
    fn evidence_runtime_data_defaults_to_raw_bytes() {
        let runtime_data = parse_evidence_runtime_data("xxxx", None).unwrap();
        assert_eq!(runtime_data, b"xxxx");
    }

    #[test]
    fn evidence_runtime_data_supports_base64_url_safe_no_pad() {
        let runtime_data =
            parse_evidence_runtime_data("eHh4eA", Some("base64")).unwrap();
        assert_eq!(runtime_data, b"xxxx");
    }

    #[test]
    fn evidence_runtime_data_rejects_unknown_encoding() {
        assert!(parse_evidence_runtime_data("xxxx", Some("hex")).is_err());
    }

    #[test]
    fn evidence_runtime_data_rejects_invalid_base64() {
        assert!(parse_evidence_runtime_data("not-base64!", Some("base64")).is_err());
    }
}
