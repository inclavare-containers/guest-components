# TDX and NVIDIA GPU evidence

Rust TDX attestation and Go TDX attestation built with `-tags gpu` collect
Hopper/Blackwell evidence through NVML. Every discovered device must supply a
report and certificate chain; query failures, unsupported architectures and
disabled CC mode fail collection rather than silently omitting a device.
CPU-only systems retain the existing TDX evidence format.

GPU-enabled collectors also check NVIDIA display/3D devices in the visible
PCI inventory. If NVML returns fewer devices, collection fails. This catches
driver initialization failures that otherwise appear as zero GPUs, including
an H20 initialization failure observed during hardware testing. PCI bridges
and NVSwitch devices are not counted as GPUs.

The collector creates the GPU requester nonce from all 64 padded report-data
bytes, then commits the complete ordered device set in the primary TDX quote:

```text
R = original report_data, right-padded to 64 bytes
GPU nonce = SHA256("tdx-nvidia-nonce-v1\0" || R)
TDX REPORT_DATA = SHA512("tdx-nvidia-evidence-v1\0" || R || LE32(count) || devices)
device = LE32(index) || field(architecture) || field(report) || field(certificate)
field(bytes) = LE32(byte_length) || bytes
```

Architecture is uppercase ASCII, reports/certificates are decoded bytes, and
`binding_version = 1` identifies this format. Timestamp and guest metadata are
not security inputs. A missing device, reordered list or substituted report
changes the CPU commitment. Shared protocol vectors in Rust and Go match the
paired Trustee implementation.

Upgrade Trustee and guest-components together for GPU workloads. Trustee must
verify the binding and then cryptographically validate every report, nonce,
device/RIM certificate chain, RIM signature and reference measurement. Its
default path is local NVIDIA NVAT RIM/OCSP verification, with NRAS optionally
selected through verifier configuration. Guest labels such as UUID, driver
version and `cc_enabled` do not replace device-authenticated claims.

Go builds without `-tags gpu` produce CPU-only evidence. Policies requiring
GPUs must require the expected GPU count and approved device identities;
successful CPU attestation alone does not meet that requirement.

```sh
cargo +1.88.0 test -p attester --no-default-features \
  --features tdx-attester,tokio/macros,tokio/rt-multi-thread --lib
# From attestation-agent/attester-go:
go test ./...
CGO_ENABLED=1 go test -tags gpu ./...
```

On 2026-11-17, both collectors were tested on a real H20 in an Alibaba Cloud
`ecs.gn8v-tee.4xlarge` TDX guest (driver `595.71.05`, VBIOS `96.00.CF.00.05`,
GPU CC ON). Each collected a 5006-byte TDX quote, 4129-byte GPU report and
4826-byte GPU attestation certificate chain for a random 64-byte challenge.
The paired Trustee verified the full evidence in both local RIM/OCSP and
NRAS modes, and rejected nonce/report/certificate changes and GPU removal.

This hardware run found and verified fixes for zero-device NVML fallback,
Rust selecting the empty CEC certificate chain, and Rust including unused
report buffer padding. Rust now uses `attestation_cert_chain` and NVML's
reported lengths. Actual device evidence is kept outside the repository.
