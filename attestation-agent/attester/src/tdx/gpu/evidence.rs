use super::error::GpuAttestationError;
use base64::{engine::general_purpose, Engine};
use nvml_wrapper::{Device as NvmlDevice, Nvml};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};

/// GPU attestation evidence
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpuEvidence {
    /// NVIDIA architecture, used by the remote verifier.
    pub arch: String,
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
            arch: String::new(),
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
    /// Version of the CPU/GPU evidence binding protocol.
    pub binding_version: u32,
    /// List of GPU evidence
    pub evidence_list: Vec<GpuEvidence>,
    /// Collection time
    pub collection_time: chrono::DateTime<chrono::Utc>,
}

impl GpuEvidenceList {
    /// Create an empty evidence list
    pub fn new() -> Self {
        Self {
            binding_version: 1,
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

    /// Commit the complete, ordered set of device reports and certificates to
    /// the primary TDX quote. Length prefixes make the encoding unambiguous
    /// and independent of JSON formatting and timestamp serialization.
    pub fn bound_report_data(&self, report_data: &[u8]) -> anyhow::Result<Vec<u8>> {
        anyhow::ensure!(report_data.len() <= 64, "TDX report data exceeds 64 bytes");
        anyhow::ensure!(self.binding_version == 1, "Unsupported GPU binding version");
        anyhow::ensure!(
            !self.is_empty() && self.gpu_count() <= 32,
            "Invalid GPU count"
        );
        let mut padded = [0u8; 64];
        padded[..report_data.len()].copy_from_slice(report_data);
        let mut hash = Sha512::new();
        hash.update(b"tdx-nvidia-evidence-v1\0");
        hash.update(padded);
        hash.update((self.gpu_count() as u32).to_le_bytes());
        let mut indices = std::collections::HashSet::new();
        for gpu in &self.evidence_list {
            anyhow::ensure!(indices.insert(gpu.index), "Duplicate GPU index");
            anyhow::ensure!(
                matches!(gpu.arch.as_str(), "HOPPER" | "BLACKWELL"),
                "Unsupported GPU architecture"
            );
            hash.update(gpu.index.to_le_bytes());
            let report = general_purpose::STANDARD.decode(
                gpu.attestation_report
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("Missing GPU report"))?,
            )?;
            let cert = general_purpose::STANDARD.decode(
                gpu.certificate
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("Missing GPU certificate"))?,
            )?;
            anyhow::ensure!(
                !report.is_empty()
                    && !cert.is_empty()
                    && report.len() <= 128 * 1024
                    && cert.len() <= 128 * 1024,
                "Invalid GPU evidence size"
            );
            for field in [gpu.arch.as_bytes(), report.as_slice(), cert.as_slice()] {
                hash.update(u32::try_from(field.len())?.to_le_bytes());
                hash.update(field);
            }
        }
        Ok(hash.finalize().to_vec())
    }
}

/// Bind all 64 bytes of the primary challenge, including any public-key hash,
/// into the 32-byte SPDM requester nonce.
pub fn gpu_nonce(report_data: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"tdx-nvidia-nonce-v1\0");
    hash.update(report_data);
    hash.finalize().into()
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
        if device_count > 32 {
            return Err(GpuAttestationError::Other("GPU count exceeds 32".into()));
        }

        for i in 0..device_count {
            evidence.add_gpu_evidence(self.collect_single_gpu_evidence(i, report_data)?);
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
            GpuAttestationError::Other(format!("Failed to get driver version: {e}"))
        })?;
        let vbios_version = device.vbios_version()?;

        let mut gpu_evidence = GpuEvidence::new(
            device_index,
            device_uuid,
            device_name,
            driver_version,
            vbios_version,
        );

        gpu_evidence.arch = match device.architecture()? {
            nvml_wrapper::enums::device::DeviceArchitecture::Hopper => "HOPPER",
            nvml_wrapper::enums::device::DeviceArchitecture::Blackwell => "BLACKWELL",
            _ => {
                return Err(GpuAttestationError::Other(
                    "Unsupported GPU architecture".into(),
                ))
            }
        }
        .into();
        if !device.is_cc_enabled()? {
            return Err(GpuAttestationError::ConfidentialComputeUnavailable);
        }
        gpu_evidence = gpu_evidence
            .with_cc_enabled(true)
            .with_attestation_report(self.get_attestation_report(&device, report_data)?)
            .with_certificate(self.get_gpu_certificate(&device)?);

        Ok(gpu_evidence)
    }

    /// Get GPU attestation report
    fn get_attestation_report(
        &self,
        device: &NvmlDevice,
        report_data: &[u8],
    ) -> Result<Vec<u8>, GpuAttestationError> {
        let nonce_array = gpu_nonce(report_data);

        match device.confidential_compute_gpu_attestation_report(nonce_array) {
            Ok(report) => Ok(report.attestation_report),
            Err(e) => {
                log::error!("Failed to get gpu attestation report: {e}");
                Err(GpuAttestationError::ConfidentialComputeUnavailable)
            }
        }
    }

    /// Get GPU certificate
    fn get_gpu_certificate(&self, device: &NvmlDevice) -> Result<Vec<u8>, GpuAttestationError> {
        match device.confidential_compute_gpu_certificate() {
            Ok(cert) => Ok(cert.cert_chain),
            Err(e) => {
                log::error!("Failed to get GPU certificate: {e}");
                Err(GpuAttestationError::GetGpuCertificateFailed)
            }
        }
    }

    /// Get device count
    pub fn device_count(&self) -> Result<u32, GpuAttestationError> {
        Ok(self.nvml.device_count()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn shared_binding_vector_and_full_nonce() {
        let vector: serde_json::Value =
            serde_json::from_str(include_str!("../../../test_data/tdx_gpu_binding_v1.json"))
                .unwrap();
        let report_data = hex::decode(vector["report_data"].as_str().unwrap()).unwrap();
        let gpus: GpuEvidenceList = serde_json::from_value(vector["gpu_evidence"].clone()).unwrap();
        assert_eq!(
            hex::encode(gpus.bound_report_data(&report_data).unwrap()),
            vector["bound_report_data"]
        );
        assert_eq!(hex::encode(gpu_nonce(&report_data)), vector["nonce"]);
        let mut other = report_data.clone();
        other[63] ^= 1;
        assert_ne!(gpu_nonce(&report_data), gpu_nonce(&other));
        let mut partial = gpus.clone();
        partial.evidence_list.pop();
        assert_ne!(
            gpus.bound_report_data(&report_data).unwrap(),
            partial.bound_report_data(&report_data).unwrap()
        );
        let mut missing = gpus;
        missing.evidence_list[0].certificate = None;
        assert!(missing.bound_report_data(&report_data).is_err());
    }
}
