use anyhow::{bail, Context, Result};
use pnet::datalink;
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Read};
use std::path::Path;
use std::process::Command;
use udev;

const BIOS_INFO_PATH: &str = "/sys/firmware/dmi/entries/0-0/raw";
const SYSTEM_INFO_PATH: &str = "/sys/firmware/dmi/entries/1-0/raw";
const ENCLOSURE_INFO_PATH: &str = "/sys/firmware/dmi/entries/3-0/raw";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareInfo {
    pub cpu_is_virtual: bool,
    pub disk_serial_number: String,
    pub mac_addresses: String,
    pub bios_info: BiosInfo,
    pub system_info: SystemInfo,
    pub enclosure_info: EnclosureInfo,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extra: Option<serde_json::Value>,
}

impl HardwareInfo {
    pub fn new() -> Result<Self> {
        Ok(HardwareInfo {
            cpu_is_virtual: determine_virtual_machine_status(),
            disk_serial_number: get_root_device()
                .and_then(|disk_part_name| get_serial_number(&disk_part_name))
                .unwrap_or_default(),
            mac_addresses: get_mac_addresses()?,
            bios_info: read_bios_info(BIOS_INFO_PATH).unwrap_or_default(),
            system_info: read_system_info(SYSTEM_INFO_PATH).unwrap_or_default(),
            enclosure_info: read_enclosure_info(ENCLOSURE_INFO_PATH).unwrap_or_default(),
            extra: None,
        })
    }

    pub fn with_extra(mut self, extra: serde_json::Value) -> Self {
        self.extra = Some(extra);
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BiosInfo {
    pub vendor: String,
    pub bios_version: String,
    pub bios_release_date: String,
    pub is_virtual_machine: bool,
    pub system_bios_major_release: String,
    pub system_bios_minor_release: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SystemInfo {
    pub manufacturer: String,
    pub product_name: String,
    pub serial_number: String,
    pub uuid: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EnclosureInfo {
    pub manufacturer: String,
    pub enclosure_type: String,
    pub version: String,
    pub serial_number: String,
    pub asset_tag_number: String,
}

#[cfg(target_arch = "x86_64")]
fn is_hypervisor_present() -> bool {
    use std::arch::x86_64::__cpuid;

    // Check CPUID hypervisor bit
    let basic_cpuid = unsafe { __cpuid(1) };
    let is_vm = (basic_cpuid.ecx & (1 << 31)) != 0;

    // Early return if hypervisor bit is set
    if is_vm {
        return true;
    }

    // Check hypervisor name
    if get_hypervisor_name().is_some() {
        return true;
    }

    // Check system indicators
    check_sys_hypervisor() || check_dmesg_hypervisor()
}

#[cfg(target_arch = "x86_64")]
fn get_hypervisor_name() -> Option<&'static str> {
    use std::arch::x86_64::__cpuid;

    // CPUID leaf 0x40000000 returns hypervisor signature
    let hypervisor_cpuid = unsafe { __cpuid(0x40000000) };
    let signature = [
        hypervisor_cpuid.ebx,
        hypervisor_cpuid.ecx,
        hypervisor_cpuid.edx,
    ];

    const VMWARE: [u32; 3] = [0x56_4D_77_61, 0x72_65_56_4D, 0x77_61_72_65];
    const HYPERV: [u32; 3] = [0x4D_69_63_72, 0x6F_73_6F_66, 0x74_20_48_76];
    const KVM: [u32; 3] = [0x4B_56_4D_4B, 0x56_4D_4B_56, 0x4D_4B_56_4D];
    const XEN: [u32; 3] = [0x58_65_6E_56, 0x4D_4D_58_65, 0x6E_56_4D_4D];

    match signature {
        VMWARE => Some("VMware"),
        HYPERV => Some("Microsoft Hyper-V"),
        KVM => Some("KVM"),
        XEN => Some("Xen"),
        _ => None,
    }
}

fn check_sys_hypervisor() -> bool {
    match fs::read_to_string("/sys/hypervisor/type") {
        Ok(content) => content.contains("xen") || content.contains("kvm"),
        Err(_) => false,
    }
}

fn check_dmesg_hypervisor() -> bool {
    Command::new("dmesg")
        .output()
        .map(|output| String::from_utf8_lossy(&output.stdout).contains("hypervisor"))
        .unwrap_or(false)
}

#[cfg(target_arch = "aarch64")]
fn is_hypervisor_present() -> bool {
    // Use lazy evaluation with || to short-circuit checks
    check_cpuinfo_hypervisor()
        || check_sys_hypervisor()
        || check_rdmsr_hypervisor()
        || check_dmesg_hypervisor()
        || check_device_tree_hypervisor()
}

#[cfg(target_arch = "aarch64")]
fn check_cpuinfo_hypervisor() -> bool {
    fs::read_to_string("/proc/cpuinfo")
        .map(|content| content.contains("hypervisor"))
        .unwrap_or(false)
}

#[cfg(target_arch = "aarch64")]
fn check_rdmsr_hypervisor() -> bool {
    // TODO: rdmsr command needs to be installed in Dockerfile for ARM architecture
    // Note: Currently ARM platform is not supported in production
    // An issue should be created to track adding rdmsr dependency to Dockerfile
    Command::new("rdmsr")
        .arg("0xC0C")
        .output()
        .map(|output| String::from_utf8_lossy(&output.stdout).contains("hypervisor"))
        .unwrap_or(false)
}

#[cfg(target_arch = "aarch64")]
fn check_device_tree_hypervisor() -> bool {
    Command::new("cat")
        .arg("/proc/device-tree/hypervisor")
        .output()
        .map(|output| !String::from_utf8_lossy(&output.stdout).is_empty())
        .unwrap_or(false)
}

// TODO: add other arch support, such as riscv
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
fn is_hypervisor_present() -> bool {
    // Use const array for paths to check
    const VIRT_PATHS: [&str; 4] = ["/.dockerenv", "/proc/xen", "/proc/vz", "/proc/bc"];

    // Check cpuinfo first as it's most reliable
    if let Ok(content) = fs::read_to_string("/proc/cpuinfo") {
        if content.contains("hypervisor")
            || content.contains("virtualization")
            || content.contains("paravirtualized")
        {
            return true;
        }
    }

    if check_sys_hypervisor() {
        return true;
    }

    if check_dmesg_hypervisor() {
        return true;
    }

    if fs::metadata("/proc/device-tree/hypervisor").is_ok() {
        return true;
    }

    VIRT_PATHS.iter().any(|path| fs::metadata(path).is_ok())
}

/// Detects if the system is running in a virtual machine environment.
/// Uses various detection techniques inspired by Al-khaser and Pafish projects.
/// - Al-khaser: https://github.com/LordNoteworthy/al-khaser
/// - Pafish: https://github.com/a0rtega/pafish
///   TODO: more virtual machine detection methods are adding.
fn determine_virtual_machine_status() -> bool {
    const CONTAINER_PATHS: [&str; 2] = ["/.dockerenv", "/.dockerinit"];

    if is_hypervisor_present() {
        return true;
    }

    if CONTAINER_PATHS
        .iter()
        .any(|path| fs::metadata(path).is_ok())
    {
        return true;
    }

    Command::new("systemctl")
        .arg("is-system-running")
        .output()
        .map(|output| String::from_utf8_lossy(&output.stdout).contains("running in container"))
        .unwrap_or(false)
}

fn get_root_device() -> Result<String> {
    let file = File::open("/proc/mounts").context("Failed to open /proc/mounts")?;
    let reader = BufReader::with_capacity(4096, file);

    for line in reader.lines() {
        let line = line?;
        let mut parts = line.split_whitespace().take(2);
        if let (Some(device), Some("/")) = (parts.next(), parts.next()) {
            if let Some(stripped) = device.strip_prefix("/dev/") {
                return Ok(stripped.to_string());
            }
            return Ok(device.to_string());
        }
    }
    bail!("Root device not found in /proc/mounts")
}

fn get_serial_number(disk_part_name: &str) -> Result<String> {
    let udev = udev::Udev::new()?;
    let mut enumerator = udev::Enumerator::with_udev(udev)?;

    enumerator.match_subsystem("block")?;
    enumerator.match_sysname(disk_part_name)?;

    let device = enumerator
        .scan_devices()?
        .next()
        .ok_or_else(|| anyhow::anyhow!("Device not found"))?;

    let parent = device
        .parent()
        .ok_or_else(|| anyhow::anyhow!("Failed to get parent device"))?;

    let serial = parent
        .property_value("ID_SERIAL")
        .ok_or_else(|| anyhow::anyhow!("Serial number not found"))?
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("Invalid serial number encoding"))?
        .to_string();

    Ok(serial)
}

fn get_mac_addresses() -> Result<String> {
    let interfaces = datalink::interfaces();
    let mut mac_addresses = Vec::new();

    for iface in interfaces {
        if let Some(mac) = iface.mac {
            mac_addresses.push(format!("{}", mac));
        }
    }

    Ok(mac_addresses.join(", "))
}

fn read_bios_info<P: AsRef<Path>>(path: P) -> Result<BiosInfo> {
    let mut buffer = Vec::new();
    File::open(&path)?.read_to_end(&mut buffer)?;

    if buffer.len() < 2 {
        bail!("Buffer too small");
    }

    let length = buffer[1] as usize;
    if buffer.len() <= length {
        bail!("Invalid buffer length");
    }

    let unformatted_section = &buffer[length..];

    if buffer.len() <= 0x15 {
        bail!("Buffer too small for BIOS info");
    }

    Ok(BiosInfo {
        vendor: extract_string(unformatted_section, buffer[0x04])?,
        bios_version: extract_string(unformatted_section, buffer[0x05])?,
        bios_release_date: extract_string(unformatted_section, buffer[0x08])?,
        is_virtual_machine: (buffer[0x13] & 0x08) >> 3 == 1 || determine_virtual_machine_status(),
        system_bios_major_release: buffer[0x14].to_string(),
        system_bios_minor_release: buffer[0x15].to_string(),
    })
}

fn read_system_info<P: AsRef<Path>>(path: P) -> Result<SystemInfo> {
    let mut buffer = Vec::new();
    File::open(&path)?.read_to_end(&mut buffer)?;

    if buffer.len() < 2 {
        bail!("Buffer too small");
    }

    let length = buffer[1] as usize;
    if buffer.len() <= length {
        bail!("Invalid buffer length");
    }

    let unformed_section = &buffer[length..];

    if buffer.len() <= 0x17 {
        bail!("Buffer too small for system info");
    }

    Ok(SystemInfo {
        manufacturer: extract_string(unformed_section, buffer[0x04])?,
        product_name: extract_string(unformed_section, buffer[0x05])?,
        serial_number: extract_string(unformed_section, buffer[0x07])?,
        uuid: format!(
            "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            buffer[0x08], buffer[0x09], buffer[0x0a], buffer[0x0b],
            buffer[0x0c], buffer[0x0d], buffer[0x0e], buffer[0x0f],
            buffer[0x10], buffer[0x11], buffer[0x12], buffer[0x13],
            buffer[0x14], buffer[0x15], buffer[0x16], buffer[0x17]
        ),
    })
}

fn read_enclosure_info<P: AsRef<Path>>(path: P) -> Result<EnclosureInfo> {
    let mut buffer = Vec::new();
    File::open(&path)?.read_to_end(&mut buffer)?;

    if buffer.len() < 2 {
        bail!("Buffer too small");
    }

    let length = buffer[1] as usize;
    if buffer.len() <= length {
        bail!("Invalid buffer length");
    }

    let unformed_section = &buffer[length..];

    if buffer.len() <= 0x08 {
        bail!("Buffer too small for enclosure info");
    }

    Ok(EnclosureInfo {
        manufacturer: extract_string(unformed_section, buffer[0x04])?,
        enclosure_type: extract_string(unformed_section, buffer[0x05])?,
        version: extract_string(unformed_section, buffer[0x06])?,
        serial_number: extract_string(unformed_section, buffer[0x07])?,
        asset_tag_number: extract_string(unformed_section, buffer[0x08])?,
    })
}

fn extract_string(unformed_section: &[u8], index: u8) -> Result<String> {
    if index == 0 {
        return Ok(String::new());
    }

    let s = unformed_section
        .split(|&b| b == 0)
        .nth(index as usize - 1)
        .ok_or_else(|| anyhow::anyhow!("String not found"))?;

    Ok(String::from_utf8_lossy(s).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_root_device() {
        let root_device = get_root_device().unwrap();
        assert!(!root_device.is_empty());
    }

    #[test]
    fn test_get_serial_number() {
        let Ok(disk_part_name) = get_root_device() else {
            return;
        };

        let Ok(serial_number) = get_serial_number(&disk_part_name) else {
            return;
        };

        assert!(!serial_number.is_empty());
    }

    #[test]
    fn test_get_mac_addresses() {
        let mac_addresses = get_mac_addresses().unwrap();
        assert!(!mac_addresses.is_empty());
    }

    #[test]
    fn test_get_bios_info() {
        let Ok(bios_info) = read_bios_info(BIOS_INFO_PATH) else {
            return;
        };

        assert!(!bios_info.vendor.is_empty());
    }

    #[test]
    fn test_get_system_info() {
        let Ok(system_info) = read_system_info(SYSTEM_INFO_PATH) else {
            return;
        };

        assert!(!system_info.manufacturer.is_empty());
    }

    #[test]
    fn test_get_enclosure_info() {
        let Ok(enclosure_info) = read_enclosure_info(ENCLOSURE_INFO_PATH) else {
            return;
        };

        assert!(!enclosure_info.manufacturer.is_empty());
    }

    #[test]
    fn test_hardware_info_with_extra() {
        let hardware_info = HardwareInfo::new()
            .unwrap()
            .with_extra(serde_json::json!({"custom_field": "value"}));

        assert!(hardware_info.extra.is_some());
        assert_eq!(hardware_info.extra.unwrap()["custom_field"], "value");
    }

    #[test]
    fn test_hardware_info_serialization() {
        let hardware_info = HardwareInfo::new().unwrap();
        let serialized = serde_json::to_string(&hardware_info).unwrap();
        let deserialized: HardwareInfo = serde_json::from_str(&serialized).unwrap();
        assert_eq!(hardware_info.cpu_is_virtual, deserialized.cpu_is_virtual);
        assert_eq!(
            hardware_info.disk_serial_number,
            deserialized.disk_serial_number
        );
    }
}
