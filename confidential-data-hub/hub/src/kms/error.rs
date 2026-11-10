// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use attestation_agent::config::aa_kbc_params;
use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Invalid resource options: {0}")]
    InvalidResourceOptions(&'static str),
    #[cfg(feature = "aliyun")]
    #[error("Aliyun KMS error: {0}")]
    AliyunKmsError(String),

    #[error("Kbs client error: {0}")]
    KbsClientError(String),

    #[cfg(feature = "ehsm")]
    #[error("eHSM-KMS client error: {0}")]
    EhsmKmsError(String),

    #[error("Unsupported provider: {0}")]
    UnsupportedProvider(String),

    #[error("aa_kbc_params error")]
    AaKbcParamsError(#[from] aa_kbc_params::ParamError),
}
