// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use crate::router::ApiHandler;
use crate::ttrpc_proto::attestation_agent::{
    ExtendRuntimeMeasurementRequest, GetEvidenceRequest, GetTokenRequest,
};
use crate::ttrpc_proto::attestation_agent_ttrpc::AttestationAgentServiceClient;
use crate::TTRPC_TIMEOUT;
use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use hyper::{body, Body, Method, Request, Response};
use serde::Deserialize;
use std::collections::HashMap;
use std::net::SocketAddr;

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
}

#[async_trait]
impl ApiHandler for AAClient {
    async fn handle_request(
        &self,
        remote_addr: SocketAddr,
        url_path: &str,
        req: Request<Body>,
    ) -> Result<Response<Body>> {
        if !remote_addr.ip().is_loopback() {
            // Return 403 Forbidden response.
            return self.forbidden();
        }

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
                if req.method() != Method::GET {
                    return self.not_allowed();
                }
                if params.len() != 1 {
                    return self.not_allowed();
                }
                match params.get("token_type") {
                    Some(token_type) => match self.get_token(token_type).await {
                        Ok(results) => return self.octet_stream_response(results),
                        Err(e) => return self.internal_error(e.to_string()),
                    },
                    None => return self.bad_request(),
                }
            }
            AA_EVIDENCE_URL => {
                if req.method() != Method::GET {
                    return self.not_allowed();
                }
                if params.len() != 1 {
                    return self.not_allowed();
                }
                match params.get("runtime_data") {
                    Some(runtime_data) => {
                        match self.get_evidence(&runtime_data.clone().into_bytes()).await {
                            Ok(results) => return self.octet_stream_response(results),
                            Err(e) => return self.internal_error(e.to_string()),
                        }
                    }
                    None => return self.bad_request(),
                }
            }
            AA_AAEL_URL => {
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
                    Ok(_) => {
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
    pub fn new(aa_addr: &str, accepted_method: Vec<Method>) -> Result<Self> {
        let inner = ttrpc::asynchronous::Client::connect(aa_addr)
            .context(format!("ttrpc connect to AA addr: {} failed!", aa_addr))?;
        let client = AttestationAgentServiceClient::new(inner);

        Ok(Self {
            client,
            accepted_method,
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
