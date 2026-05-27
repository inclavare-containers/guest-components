// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use std::fs::File;
use std::io::Write;
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
        ("runtime_data" = String, Query, description = "Runtime Data"),
        ("encoding" = Option<String>, Query, description = "Optional runtime_data encoding, e.g. \"base64\" for URL-safe no padding base64")
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

#[derive(utoipa::ToSchema)]
pub struct VersionInfo {
    /// Guest Components version string from `git describe --tags --dirty --always`
    pub version: String,
    /// TEE type (optional)
    pub tee: Option<String>,
    /// Additional TEE types
    pub additional_tees: Vec<String>,
}

#[utoipa::path(
    get,
    path = "/info",
    responses(
        (status = 200, description = "success response",
                content_type = "application/json",
                body = VersionInfo,
                example = json!({"version": "v1.0.0", "tee": "tdx", "additional_tees": []})),
        (status = 405, description = "only Get method allowed")
    )
)]
fn _version() {}

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
        _resource_injection_commit,
        _version
    )
 )]
    struct ApiDoc;
    let mut file = File::create("openapi/api.json")?;
    let json = ApiDoc::openapi().to_pretty_json()?;
    println!("{}", &json);
    file.write_all(json.as_bytes())
}

fn generate_version_file() -> std::io::Result<()> {
    use std::env;
    use std::path::Path;
    use std::process::Command;

    let out_dir = env::var("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("guest_components_version");
    let mut f = File::create(dest_path)?;

    let git_version = Command::new("git")
        .args(["describe", "--tags", "--dirty", "--always"])
        .output()
        .unwrap()
        .stdout;

    let git_version = String::from_utf8(git_version).unwrap();
    let git_version = git_version.trim_end();

    writeln!(f, "{git_version}")?;
    Ok(())
}

fn main() -> std::io::Result<()> {
    generate_openapi_document().expect("Generate restful OpenAPI yaml failed.");
    generate_version_file().expect("Generate version file failed.");

    Ok(())
}
