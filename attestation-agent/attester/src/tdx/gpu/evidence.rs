use super::error::GpuAttestationError;
use base64::{engine::general_purpose, Engine};
use nvml_wrapper::{Device as NvmlDevice, Nvml};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// GPU attestation evidence
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpuEvidence {
    /// Device index
    pub index: u32,
    /// Device UUID
    pub uuid: String,
    /// Device name
    pub name: String,
    /// Driver version
    pub driver_version: String,
    /// VBIOS version
    pub vbios_version: String,
    /// Attestation report (Base64 encoded)
    pub attestation_report: Option<String>,
    /// Certificate (Base64 encoded)
    pub certificate: Option<String>,
    /// Confidential computing status
    pub cc_enabled: bool,
}

impl GpuEvidence {
    /// Create new GPU evidence
    pub fn new(
        index: u32,
        uuid: String,
        name: String,
        driver_version: String,
        vbios_version: String,
    ) -> Self {
        Self {
            index,
            uuid,
            name,
            driver_version,
            vbios_version,
            attestation_report: None,
            certificate: None,
            cc_enabled: false,
        }
    }

    /// Set attestation report
    pub fn with_attestation_report(mut self, report: Vec<u8>) -> Self {
        self.attestation_report = Some(general_purpose::STANDARD.encode(report));
        self
    }

    /// Set certificate
    pub fn with_certificate(mut self, cert: Vec<u8>) -> Self {
        self.certificate = Some(general_purpose::STANDARD.encode(cert));
        self
    }

    /// Set confidential computing status
    pub fn with_cc_enabled(mut self, enabled: bool) -> Self {
        self.cc_enabled = enabled;
        self
    }
}

/// Evidence list
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpuEvidenceList {
    /// List of GPU evidence
    pub evidence_list: Vec<GpuEvidence>,
    /// Collection time
    pub collection_time: chrono::DateTime<chrono::Utc>,
}

impl GpuEvidenceList {
    /// Create an empty evidence list
    pub fn new() -> Self {
        Self {
            evidence_list: Vec::new(),
            collection_time: chrono::Utc::now(),
        }
    }

    /// Add GPU evidence
    pub fn add_gpu_evidence(&mut self, evidence: GpuEvidence) {
        self.evidence_list.push(evidence);
    }

    /// Get GPU evidence count
    pub fn gpu_count(&self) -> usize {
        self.evidence_list.len()
    }

    /// Whether the list is empty
    pub fn is_empty(&self) -> bool {
        self.evidence_list.is_empty()
    }
}

/// Evidence collector
pub struct GpuEvidenceCollector {
    nvml: Nvml,
}

impl GpuEvidenceCollector {
    /// Create a new evidence collector
    pub fn new() -> Result<Self, GpuAttestationError> {
        let nvml = Nvml::init()?;
        Ok(Self { nvml })
    }

    /// Collect GPU evidence (public method, accepts report_data parameter)
    pub fn collect_gpu_evidence(
        &self,
        report_data: &[u8],
    ) -> Result<GpuEvidenceList, GpuAttestationError> {
        let mut evidence = GpuEvidenceList::new();

        let device_count = self.nvml.device_count()?;

        for i in 0..device_count {
            match self.collect_single_gpu_evidence(i, report_data) {
                Ok(gpu_evidence) => evidence.add_gpu_evidence(gpu_evidence),
                Err(e) => {
                    log::warn!("Failed to collect evidence for GPU {}: {}", i, e);
                    // Continue with other GPUs, do not terminate due to a single failure
                }
            }
        }

        if evidence.is_empty() {
            return Err(GpuAttestationError::NoGpuDevice);
        }

        Ok(evidence)
    }

    /// Collect evidence for a single GPU (accepts report_data parameter)
    fn collect_single_gpu_evidence(
        &self,
        device_index: u32,
        report_data: &[u8],
    ) -> Result<GpuEvidence, GpuAttestationError> {
        let device = self.nvml.device_by_index(device_index)?;

        // Get basic device information
        let device_uuid = device.uuid()?;
        let device_name = device.name()?;
        let driver_version = self.nvml.sys_driver_version().map_err(|e| {
            GpuAttestationError::Other(format!("Failed to get driver version: {}", e))
        })?;
        let vbios_version = device.vbios_version()?;

        let mut gpu_evidence = GpuEvidence::new(
            device_index,
            device_uuid,
            device_name,
            driver_version,
            vbios_version,
        );

        // Get attestation report
        if let Ok(report) = self.get_attestation_report(&device, report_data) {
            gpu_evidence = gpu_evidence.with_attestation_report(report);
        } else {
            log::warn!("Failed to get attestation report for GPU {}", device_index);
        }

        // Check confidential computing support
        match device.is_cc_enabled() {
            Ok(cc_enabled) => {
                gpu_evidence = gpu_evidence.with_cc_enabled(cc_enabled);
                if cc_enabled {
                    // Get certificate
                    if let Ok(cert) = self.get_gpu_certificate(&device) {
                        gpu_evidence = gpu_evidence.with_certificate(cert);
                    }
                }
            }
            Err(e) => {
                log::warn!(
                    "Failed to check confidential computing status for GPU {}: {}",
                    device_index,
                    e
                );
            }
        }

        Ok(gpu_evidence)
    }

    /// Get GPU attestation report
    fn get_attestation_report(
        &self,
        device: &NvmlDevice,
        report_data: &[u8],
    ) -> Result<Vec<u8>, GpuAttestationError> {
        // Prepare nonce array from report_data
        let mut nonce_array = [0u8; 32];

        if report_data.is_empty() {
            // If report_data is empty, use random UUID as fallback
            let uuid = Uuid::new_v4();
            let uuid_bytes = uuid.as_bytes();
            nonce_array[..16].copy_from_slice(uuid_bytes);
            nonce_array[16..32].copy_from_slice(uuid_bytes);
        } else if report_data.len() <= 32 {
            // If length is less than 32 bytes, copy data and pad the rest with 0
            nonce_array[..report_data.len()].copy_from_slice(report_data);
        } else {
            // If more than 32 bytes, truncate to 32 bytes
            nonce_array.copy_from_slice(&report_data[..32]);
        }

        match device.confidential_compute_gpu_attestation_report(nonce_array) {
            Ok(report) => Ok(report.attestation_report),
            Err(e) => {
                log::error!("Failed to get gpu attestation report: {}", e);
                Err(GpuAttestationError::ConfidentialComputeUnavailable)
            }
        }
    }

    /// Get GPU certificate
    fn get_gpu_certificate(&self, device: &NvmlDevice) -> Result<Vec<u8>, GpuAttestationError> {
        match device.confidential_compute_gpu_certificate() {
            Ok(cert) => Ok(cert.cert_chain),
            Err(e) => {
                log::error!("Failed to get GPU certificate: {}", e);
                Err(GpuAttestationError::GetGpuCertificateFailed)
            }
        }
    }

    /// Get device count
    pub fn device_count(&self) -> Result<u32, GpuAttestationError> {
        Ok(self.nvml.device_count()?)
    }

    /// Check if there are available GPU devices
    pub fn has_gpu_devices(&self) -> bool {
        self.device_count().unwrap_or(0) > 0
    }
}
