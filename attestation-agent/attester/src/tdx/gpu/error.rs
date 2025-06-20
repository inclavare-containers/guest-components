use thiserror::Error;

/// Attestation error types
#[derive(Error, Debug)]
pub enum GpuAttestationError {
    #[error("NVML error: {0}")]
    NvmlError(#[from] nvml_wrapper::error::NvmlError),

    #[error("No GPU device found")]
    NoGpuDevice,

    #[error("Other error: {0}")]
    Other(String),

    #[error("Confidential compute unavailable")]
    ConfidentialComputeUnavailable,

    #[error("Get GPU certificate failed")]
    GetGpuCertificateFailed,
}
