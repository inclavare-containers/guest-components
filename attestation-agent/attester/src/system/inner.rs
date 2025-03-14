use super::sysinfo::get_machine_info;
use anyhow::*;
use log::{info, warn};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha384};

#[derive(Clone, Serialize, Deserialize, Default, Debug, PartialEq)]
pub struct MeasurementEntry {
    pub name: String,
    pub algorithm: String,
    pub digest: String,
}

#[derive(Default)]
pub struct SystemAttesterdInner {
    mr_register: String,
    measurements: Vec<MeasurementEntry>,
}

impl SystemAttesterdInner {
    pub fn measure(&mut self, name: String, data: Vec<u8>) -> Result<()> {
        // Measure data
        let mut hasher = Sha384::new();
        hasher.update(data);
        let digest = hasher.finalize().to_vec();
        let digest_hex = hex::encode(&digest);

        // Add New Measurements Entry
        let entry = MeasurementEntry {
            name,
            algorithm: "sha384".to_string(),
            digest: digest_hex,
        };
        info!("{}", format!("Measurement Entry: {:?}", &entry));
        self.measurements.push(entry);

        // Extend MR Register Hash
        let mr_register_value_bytes = hex::decode(self.mr_register.clone())?;
        let mut hasher = Sha384::new();
        if !mr_register_value_bytes.is_empty() {
            hasher.update(&mr_register_value_bytes);
        }
        hasher.update(&digest);
        self.mr_register = hex::encode(hasher.finalize());
        info!("{}", format!("Updated MR Register: {}", self.mr_register));

        Ok(())
    }

    pub fn get_measurements(&self) -> Vec<MeasurementEntry> {
        self.measurements.clone()
    }

    pub fn read_mr_register(&self) -> String {
        self.mr_register.clone()
    }

    pub fn read_sys_report(&self) -> Result<String> {
        let machine_info = get_machine_info()?;
        let sys_report = serde_json::to_string(&machine_info)?;
        info!(
            "System Report: {}",
            serde_json::to_string_pretty(&machine_info)?
        );
        Ok(sys_report)
    }
}

impl SystemAttesterdInner {
    pub fn init(&mut self) -> Result<()> {
        info!("Initialize: measure Kernel and Initrams of this system...");
        let uname_output = std::process::Command::new("uname").arg("-r").output()?;
        let kernel_version = match uname_output.status.success() {
            true => String::from_utf8_lossy(&uname_output.stdout)
                .trim()
                .to_string(),
            false => bail!("Failed to get kernel version"),
        };
        let kernel_blob_path = format!("/boot/vmlinuz-{kernel_version}");
        let initramfs_img_path = format!("/boot/initramfs-{kernel_version}.img");
        match std::fs::read(kernel_blob_path) {
            std::result::Result::Ok(kernel_blob) => {
                self.measure("kernel".to_string(), kernel_blob)?
            }
            Err(e) => warn!("Failed to read kernel blob: {e}"),
        }

        match std::fs::read(initramfs_img_path) {
            std::result::Result::Ok(initramfs_blob) => {
                self.measure("initramfs".to_string(), initramfs_blob)?
            }
            Err(e) => warn!("Failed to read initramfs blob: {e}"),
        }

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use sha2::{Digest, Sha384};

    #[test]
    fn test_measure() {
        let mut attesterd = SystemAttesterdInner::default();
        let data = b"1234567890".to_vec();
        let result = attesterd.measure("test".to_string(), data.clone());
        assert!(result.is_ok());
        let mut hasher = Sha384::new();
        hasher.update(data);
        let digest = hasher.finalize().to_vec();
        let digest_hex = hex::encode(&digest);
        let mut hasher = Sha384::new();
        hasher.update(&digest);
        let new_mr_register = hex::encode(hasher.finalize().to_vec());
        let mr_register_read = attesterd.read_mr_register();
        assert_eq!(new_mr_register, mr_register_read);
        let entry = MeasurementEntry {
            name: "test".to_string(),
            algorithm: "sha384".to_string(),
            digest: digest_hex,
        };
        let measurement_entry = attesterd.get_measurements()[0].clone();
        assert_eq!(measurement_entry, entry);
    }

    #[test]
    fn test_init() {
        let mut attesterd = SystemAttesterdInner::default();
        let result = attesterd.init();
        let measurements = attesterd.get_measurements();
        let _measurements_str = serde_json::to_string(&measurements).unwrap();
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_read_sysreport() {
        let attesterd = SystemAttesterdInner::default();
        let result = attesterd.read_sys_report();
        assert!(result.is_ok());
    }
}
