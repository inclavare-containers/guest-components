//! A library for retrieving system information.
//!
//! This module provides functionality to gather hardware and software information
//! about the machine it's running on. It includes details such as CPU, disk,
//! network interfaces, operating system, and more.
//!
//! # Platform Support
//! - **Linux**: Full support for retrieving system information, including detailed hardware and software details (e.g., using `libudev` for disk serial number retrieval).
//!
//! # Dependencies
//! - **Linux**: Requires `libudev` for certain hardware information retrieval (e.g., disk serial numbers). Ensure `libudev` is installed on the system.
//!     - On Debian/Ubuntu: `sudo apt-get install libudev-dev`
//!     - On Fedora/Red Hat: `sudo dnf install systemd-devel`
//!
//! # Environment Setup
//! - Ensure the appropriate development packages are installed for the target platform.
//! - On **non-Linux** platforms, functionality relying on `libudev` will be disabled to ensure compatibility.
//! - For custom configurations, such as setting `PKG_CONFIG_PATH`, ensure the environment is correctly configured when building on Linux systems.
//!
//! # Example
//! ```
//! use attester::system::sysinfo::get_machine_info;
//!
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let machine_info = get_machine_info()?;
//!     println!("Machine Info: {:?}", machine_info);
//!     Ok(())
//! }
//! ```

pub mod system_info;

pub use system_info::get_machine_info;
