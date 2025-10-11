// Copyright (c) 2025 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// TPM Evidence
#[derive(Serialize, Deserialize)]
pub struct TpmEvidence {
    // PEM format of EK certificate
    pub ek_cert: Option<String>,
    // PEM format of AK public key
    pub ak_pubkey: String,
    // TPM Quote (Contained PCRs)
    pub quote: HashMap<String, TpmQuote>,
    // Base64 encoded Eventlog ACPI table
    pub eventlog: Option<String>,
    // Base64 encoded AA Eventlog
    pub aa_eventlog: Option<String>,
}

/// TPM Quote
#[derive(Debug, Serialize, Clone, Deserialize)]
pub struct TpmQuote {
    // Base64 encoded
    pub attest_body: String,
    // Base64 encoded
    pub attest_sig: String,
    // PCRs
    pub pcrs: Vec<String>,
}
