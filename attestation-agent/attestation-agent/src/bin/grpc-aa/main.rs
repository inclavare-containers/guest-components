// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

mod server;

use anyhow::*;
use attestation_agent::{initdata::Initdata, AttestationAPIs, AttestationAgent};
use base64::Engine;
use clap::Parser;
use log::{debug, info};
use tokio::signal::unix::{signal, SignalKind};

use std::net::SocketAddr;

const DEFAULT_ATTESTATION_AGENT_ADDR: &str = "127.0.0.1:50002";

const VERSION: &str = include_str!(concat!(env!("OUT_DIR"), "/version"));

#[derive(Debug, Parser)]
#[command(author, version = Some(VERSION))]
struct Cli {
    /// Attestation gRPC Unix socket addr.
    ///
    /// This Unix socket address which the Attestation gRPC service
    /// will listen to, for example:
    ///
    /// `--attestation_sock 127.0.0.1:11223`
    #[arg(default_value_t = DEFAULT_ATTESTATION_AGENT_ADDR.to_string(), short, long = "attestation_sock")]
    attestation_sock: String,

    /// Configuration file for Attestation Agent
    ///
    /// Example:
    /// `--config /etc/attestation-agent.conf`
    #[arg(short, long)]
    config_file: Option<String>,

    /// Initdata digest to be verified by AA. If initdata check failed, AA will failed to launch.
    /// The initdata should be base64 standard encoding.
    ///
    /// Note that this is an alternative to `--initdata_toml`.
    ///
    /// If both parameters `--initdata_toml` and `initdata_digest` are provided, parameter
    /// `--initdata_toml` takes precedence.
    ///
    /// Example:
    /// `--initdata_digest AAAAAAAAAAAA`
    #[arg(short, long)]
    initdata_digest: Option<String>,

    /// Path to the Initdata TOML file to be verified by AA. If initdata check failed, AA will failed to launch.
    /// The initdata should be base64 standard encoding.
    ///
    /// Note that this is an alternative to `--initdata_digest`.
    ///
    /// /// If both parameters `--initdata_toml` and `initdata_digest` are provided, parameter
    /// `--initdata_toml` takes precedence.
    ///
    /// Example:
    /// `--initdata_toml /path/to/initdata.toml`
    #[arg(short = 't', long)]
    initdata_toml: Option<String>,
}

#[tokio::main]
pub async fn main() -> Result<()> {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));
    let cli = Cli::parse();

    let attestation_socket = cli.attestation_sock.parse::<SocketAddr>()?;

    let mut aa = AttestationAgent::new(cli.config_file.as_deref()).context("start AA")?;

    let mut initdata_digest = None;
    if let Some(initdata_toml_path) = cli.initdata_toml {
        info!("Initdata TOML file is given by parameter");
        let initdata_toml =
            std::fs::read_to_string(initdata_toml_path).context("read initdata toml file")?;
        let (_, digest) = Initdata::parse_and_get_digest(&initdata_toml)?;
        aa.set_initdata_toml(initdata_toml);
        initdata_digest = Some(digest);
    } else if let Some(initdata) = cli.initdata_digest {
        info!("Initdata digest is given by parameter");
        let initdata = base64::engine::general_purpose::STANDARD
            .decode(initdata)
            .context("base64 decode initdata")?;
        initdata_digest = Some(initdata);
    }

    if let Some(initdata_digest) = initdata_digest {
        let res = aa.bind_init_data(&initdata_digest).await.context(
        "The initdata supplied by the parameter is inconsistent with that of the current platform.",
    )?;

        match res {
            attester::InitDataResult::Ok => info!("Check initdata passed."),
            attester::InitDataResult::Unsupported => {
                info!("Platform does not support initdata checking. Jumping.")
            }
        }
    }

    aa.init().await.context("init AA")?;
    debug!(
        "Attestation gRPC service listening on: {:?}",
        cli.attestation_sock
    );

    // Check if heartbeat is enabled and get interval
    let config = aa.config.read().await;
    let _heartbeat_enabled = config.aa_instance.heartbeat.enabled;
    let _heartbeat_interval = config.aa_instance.heartbeat.interval_minutes.unwrap_or(5); // Default 5 minutes
    drop(config);

    // Start heartbeat task if enabled
    #[cfg(feature = "instance_info")]
    let heartbeat_task = if _heartbeat_enabled {
        use log::warn;
        let config_file = cli.config_file.clone();
        Some(tokio::spawn(async move {
            use attestation_agent::instance_info::InstanceHeartbeat;
            use tokio::time::{interval, Duration};
            let heartbeat = match InstanceHeartbeat::new_from_config_path(config_file.as_deref()) {
                Result::Ok(h) => h,
                Result::Err(e) => {
                    warn!("Failed to create heartbeat instance: {}", e);
                    return;
                }
            };

            let mut timer = interval(Duration::from_secs(_heartbeat_interval * 60)); // Convert minutes to seconds
            loop {
                timer.tick().await;
                if let Err(e) = heartbeat.send_heartbeat().await {
                    warn!("Heartbeat failed: {}", e);
                } else {
                    debug!("Heartbeat sent successfully");
                }
            }
        }))
    } else {
        None
    };

    let mut interrupt = signal(SignalKind::interrupt())?;
    let mut hangup = signal(SignalKind::hangup())?;
    tokio::select! {
        _ = hangup.recv() => info!("Client terminal disconnected."),
        _ = interrupt.recv() => info!("SIGINT received, gracefully shutdown."),
        _ = server::start_grpc_service(attestation_socket, aa) => info!("AA exits."),
    }

    // Cancel heartbeat task if it was started
    #[cfg(feature = "instance_info")]
    if let Some(task) = heartbeat_task {
        task.abort();
    }

    Ok(())
}
