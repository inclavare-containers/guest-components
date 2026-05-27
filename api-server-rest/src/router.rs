// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::*;
use async_trait::async_trait;
use hyper::{header, Body, Method, Request, Response, StatusCode};
use serde::Serialize;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use crate::aa::AAClient;
use crate::utils::split_nth_slash;

#[async_trait]
pub trait ApiHandler: Send {
    async fn handle_request(
        &self,
        _remote_addr: SocketAddr,
        _resource_path: &str,
        _req: Request<Body>,
    ) -> Result<Response<Body>> {
        Ok(Response::new(Body::empty()))
    }

    // Build octet-stream response for bytes data.
    fn octet_stream_response(&self, data: Vec<u8>) -> Result<Response<Body>> {
        Ok(Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/octet-stream")
            .body(Body::from(data))?)
    }

    // Build json response.
    #[allow(dead_code)]
    fn json_response(&self, json: String) -> Result<Response<Body>> {
        Ok(Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(json))?)
    }

    // Build 400 Bad Request response.
    fn bad_request(&self) -> Result<Response<Body>> {
        Ok(Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(Body::from("BAD REQUEST"))?)
    }

    // Build 403 Forbidden response.
    fn forbidden(&self) -> Result<Response<Body>> {
        Ok(Response::builder()
            .status(StatusCode::FORBIDDEN)
            .body(Body::from("Forbidden"))?)
    }

    // Build 404 Not Found response.
    fn not_found(&self) -> Result<Response<Body>> {
        Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Body::from("URL NOT FOUND"))?)
    }

    // Build 405 Method Not Allowed response.
    fn not_allowed(&self) -> Result<Response<Body>> {
        Ok(Response::builder()
            .status(StatusCode::METHOD_NOT_ALLOWED)
            .body(Body::from("Method Not Allowed"))?)
    }

    // Build 500 Internal Server Error response.
    fn internal_error(&self, body: String) -> Result<Response<Body>> {
        Ok(Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .body(Body::from(body))?)
    }
}

pub struct Router {
    routes: HashMap<String, Box<dyn ApiHandler + Sync + Send>>,
    version: String,
    aa_client: Option<Arc<AAClient>>,
}

impl Router {
    pub fn new(version: &str) -> Self {
        Router {
            routes: HashMap::new(),
            version: version.to_string(),
            aa_client: None,
        }
    }

    pub fn set_aa_client(&mut self, aa_client: Arc<AAClient>) {
        self.aa_client = Some(aa_client);
    }

    pub fn register_route(&mut self, route: &str, handler: Box<dyn ApiHandler + Sync + Send>) {
        self.routes.insert(route.to_string(), handler);
    }

    fn json_response(&self, json: String) -> Result<Response<Body>> {
        Ok(Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(json))?)
    }

    fn not_allowed(&self) -> Result<Response<Body>> {
        Ok(Response::builder()
            .status(StatusCode::METHOD_NOT_ALLOWED)
            .body(Body::from("Method Not Allowed"))?)
    }

    pub async fn route(
        &mut self,
        remote_addr: SocketAddr,
        req: Request<Body>,
    ) -> Result<Response<Body>> {
        if req.uri().path() == "/info" {
            if req.method() != Method::GET {
                return self.not_allowed();
            }

            #[derive(Serialize)]
            struct VersionInfo {
                version: String,
                #[serde(skip_serializing_if = "Option::is_none")]
                tee: Option<String>,
                additional_tees: Vec<String>,
            }

            let (tee, additional_tees) = match &self.aa_client {
                Some(client) => {
                    let tee = client.get_tee_type().await?;
                    let additional_tees = client.get_additional_tees().await?;
                    (Some(tee), additional_tees)
                }
                None => (None, vec![]),
            };

            let version_info = VersionInfo {
                version: self.version.clone(),
                tee,
                additional_tees,
            };
            return self.json_response(serde_json::to_string(&version_info)?);
        }

        if let Some((root_path, url_path)) = split_nth_slash(req.uri().path(), 2) {
            println!("root_path {}, url_path {}", root_path, url_path);
            let local_url = url_path.to_string();
            match self.routes.get(root_path) {
                Some(handler) => return handler.handle_request(remote_addr, &local_url, req).await,
                None => return Ok(Response::builder().status(404).body(Body::empty())?),
            }
        }

        Ok(Response::builder().status(404).body(Body::empty())?)
    }
}
