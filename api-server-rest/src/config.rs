// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

use anyhow::{Context, Result};
use serde::Deserialize;

pub const DEFAULT_CONFIG_PATH: &str = "/etc/trustiflux/trustiflux-api-server.toml";
pub const DEFAULT_BIND: &str = "127.0.0.1:8006";
pub const DEFAULT_CDH_SOCKET: &str = "unix:///run/confidential-containers/cdh.sock";
pub const DEFAULT_AA_SOCKET: &str =
    "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock";

#[derive(Debug, Deserialize)]
pub struct ApiServerConfig {
    #[serde(default = "default_bind")]
    pub bind: String,

    #[serde(default = "default_true")]
    pub enable_cdh: bool,

    #[serde(default = "default_true")]
    pub enable_aa: bool,

    #[serde(default = "default_cdh_socket")]
    pub cdh_socket: String,

    #[serde(default = "default_aa_socket")]
    pub aa_socket: String,
}

fn default_bind() -> String {
    DEFAULT_BIND.to_string()
}

fn default_true() -> bool {
    true
}

fn default_cdh_socket() -> String {
    DEFAULT_CDH_SOCKET.to_string()
}

fn default_aa_socket() -> String {
    DEFAULT_AA_SOCKET.to_string()
}

pub fn load_config(path: &str) -> Result<ApiServerConfig> {
    let settings = ::config::Config::builder()
        .add_source(::config::File::with_name(path).required(false))
        .build()
        .context(format!("failed to load api server config: {}", path))?;

    let cfg: ApiServerConfig = settings
        .try_deserialize()
        .context("failed to deserialize api server config")?;

    Ok(cfg)
}
