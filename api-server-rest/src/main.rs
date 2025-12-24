// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use clap::Parser;
use hyper::server::conn::AddrStream;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Method, Server};
use std::net::SocketAddr;
use std::sync::Arc;

mod aa;
mod cdh;
mod config;
mod router;
mod ttrpc_proto;
mod utils;

use aa::{AAClient, AA_ROOT};
use cdh::{CDHClient, CDH_ROOT};
use config::{load_config, DEFAULT_CONFIG_PATH};
use router::Router;

type GenericError = Box<dyn std::error::Error + Send + Sync>;
type Result<T> = std::result::Result<T, GenericError>;

pub const TTRPC_TIMEOUT: i64 = 50 * 1000 * 1000 * 1000;

/// API Server arguments info.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Config file path for API Server
    #[arg(default_value_t = DEFAULT_CONFIG_PATH.to_string(), short, long = "config")]
    config: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let config = load_config(&args.config)?;

    println!(
        "Starting API server with config {} (bind {})",
        args.config, config.bind
    );

    if !config.enable_aa && !config.enable_cdh {
        eprintln!("No API is enabled, please enable aa and/or cdh in the config file.");
        std::process::exit(1);
    }

    let address: SocketAddr = config.bind.parse().expect("Failed to parse the address");

    let mut router = Router::new();

    if config.enable_cdh {
        router.register_route(
            CDH_ROOT,
            Box::new(CDHClient::new(&config.cdh_socket, vec![Method::GET])?),
        );
    }

    if config.enable_aa {
        router.register_route(
            AA_ROOT,
            Box::new(AAClient::new(&config.aa_socket, vec![Method::GET])?),
        );
    }

    let router = Arc::new(tokio::sync::Mutex::new(router));

    let api_service = make_service_fn(|conn: &AddrStream| {
        let remote_addr = conn.remote_addr();
        let local_router = router.clone();

        async move {
            Ok::<_, GenericError>(service_fn(move |req| {
                let local_router = local_router.clone();
                async move { local_router.lock().await.route(remote_addr, req).await }
            }))
        }
    });

    let server = Server::bind(&address).serve(api_service);

    println!("API Server listening on http://{}", config.bind);

    if let Err(e) = server.await {
        eprintln!("API server error: {}", e);
    }

    Ok(())
}
