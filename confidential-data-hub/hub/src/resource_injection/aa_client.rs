// Copyright (c) 2026 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use protos::ttrpc::aa::{
    attestation_agent::GetEvidenceRequest, attestation_agent_ttrpc::AttestationAgentServiceClient,
};
use ttrpc::context;

use crate::{Error, Result};

const AA_TTRPC_TIMEOUT_NANOS: i64 = 50 * 1000 * 1000 * 1000;

pub(super) struct AaClient {
    client: AttestationAgentServiceClient,
}

impl AaClient {
    pub(super) fn new(aa_socket: &str) -> Result<Self> {
        let client = ttrpc::r#async::Client::connect(aa_socket).map_err(|e| {
            Error::ResourceInjection(format!(
                "connect to attestation-agent via ttrpc at {aa_socket} failed: {e}"
            ))
        })?;

        Ok(Self {
            client: AttestationAgentServiceClient::new(client),
        })
    }

    pub(super) async fn get_evidence(&self, runtime_data: Vec<u8>) -> Result<Vec<u8>> {
        let req = GetEvidenceRequest {
            RuntimeData: runtime_data,
            ..Default::default()
        };
        let res = self
            .client
            .get_evidence(context::with_timeout(AA_TTRPC_TIMEOUT_NANOS), &req)
            .await
            .map_err(|e| {
                Error::ResourceInjection(format!(
                    "get evidence from attestation-agent via ttrpc failed: {e}"
                ))
            })?;

        Ok(res.Evidence)
    }
}
