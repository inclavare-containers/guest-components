// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use std::fs::File;
use std::io::Write;
use ttrpc_codegen::{Codegen, Customize, ProtobufCustomize};
use utoipa::OpenApi;

#[utoipa::path(
    get,
    path = "/aa/token",
    params(
        ("token_type" = String, Query, description = "Token Type")
    ),
    responses(
        (status = 200, description = "success response",
                content_type = "application/octet-stream",
                body = String,
                example = json!({"token": "eyJhbGciOiJFUzI1NiI...", "tee_keypair": "-----BEGIN RSA... "})),
        (status = 400, description = "bad request for invalid token type"),
        (status = 403, description = "forbid external access"),
        (status = 404, description = "resource not found"),
        (status = 405, description = "only Get method allowed")
    )
)]
fn _token() {}

#[utoipa::path(
    get,
    path = "/aa/evidence",
    params(
        ("runtime_data" = String, Query, description = "Runtime Data")
    ),
    responses(
        (status = 200, description = "success response",
                content_type = "application/octet-stream",
                body = String,
                example = json!({"svn":"1","report_data":"eHh4eA=="})),
        (status = 400, description = "bad request for invalid query param"),
        (status = 403, description = "forbid external access"),
        (status = 404, description = "resource not found"),
        (status = 405, description = "only Get method allowed")
    )
)]
fn _evidence() {}

#[utoipa::path(
    get,
    path = "/cdh/resource/{repository}/{type}/{tag}",
    responses(
        (status = 200, description = "success response",
                content_type = "application/octet-stream",
                body = String,
                example = json!({"123456":"value"})),
        (status = 403, description = "forbid external access"),
        (status = 404, description = "resource not found"),
        (status = 405, description = "only Get method allowed")
    )
)]
fn _resource() {}

#[utoipa::path(
    post,
    path = "/cdh/resource-injection/prepare/{repository}/{type}/{tag}",
    request_body = serde_json::Value,
    responses(
        (status = 200, description = "prepare injection response",
                content_type = "application/json",
                body = serde_json::Value,
                example = json!({
                    "session_id": "inject-session-id",
                    "nonce": "nonce-from-verifier",
                    "tee_pubkey": {"kty": "EC", "crv": "P-256", "alg": "ECDH-ES+A256KW", "x": "....", "y": "...."},
                    "evidence": "base64-encoded-evidence"
                })),
        (status = 403, description = "forbid external access"),
        (status = 404, description = "resource not found"),
        (status = 405, description = "only POST method allowed")
    )
)]
fn _resource_injection_prepare() {}

#[utoipa::path(
    post,
    path = "/cdh/resource-injection/commit/{repository}/{type}/{tag}",
    request_body = serde_json::Value,
    responses(
        (status = 200, description = "commit injection response"),
        (status = 403, description = "forbid external access"),
        (status = 404, description = "resource not found"),
        (status = 405, description = "only POST method allowed")
    )
)]
fn _resource_injection_commit() {}

fn generate_openapi_document() -> std::io::Result<()> {
    #[derive(OpenApi)]
    #[openapi(
    info(
        title = "CoCo Restful API",
        description = "HTTP based API for CoCo containers to get resource/evidence/token from confidential-data-hub and attestation-agent."),

    servers(
        (url = "http://127.0.0.1:8006", description = "CoCo Restful API")
     ),

    paths(
        _token,
        _evidence,
        _resource,
        _resource_injection_prepare,
        _resource_injection_commit
    )
 )]
    struct ApiDoc;
    let mut file = File::create("openapi/api.json")?;
    let json = ApiDoc::openapi().to_pretty_json()?;
    println!("{}", &json);
    file.write_all(json.as_bytes())
}

fn main() -> std::io::Result<()> {
    let protos = vec![
        "./protos/confidential_data_hub.proto",
        "./protos/attestation_agent.proto",
    ];
    let protobuf_customized = ProtobufCustomize::default().gen_mod_rs(false);

    Codegen::new()
        .out_dir("src/ttrpc_proto")
        .inputs(&protos)
        .include("./protos")
        .rust_protobuf()
        .customize(Customize {
            async_all: true,
            ..Default::default()
        })
        .rust_protobuf_customize(protobuf_customized)
        .run()
        .expect("Generate ttrpc protocol code failed.");

    generate_openapi_document().expect("Generate restful OpenAPI yaml failed.");

    Ok(())
}
