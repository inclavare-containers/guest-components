# attester-go

A pure-Go re-implementation of the `attester` crate
(`attestation-agent/attester`). It collects hardware attestation evidence from a
confidential guest and produces evidence whose **JSON representation is
byte-compatible with the Rust attester**, so the evidence can be verified by an
unmodified Trustee `attestation-service`.

The motivation is to let Go programs collect TEE evidence **without cgo and
without any external shared library** (in particular without `libtdx_attest.so`
/ DCAP). Every platform is driven through native kernel interfaces (ConfigFS
TSM, ioctl on `/dev/tdx_guest`, `/dev/sev-guest`, `/dev/csv-guest`, and vsock).

## Supported platforms

| Tee | Mechanism | External `.so` |
|-----|-----------|----------------|
| `sample` | software measurement register + event log | none |
| `tdx` | ConfigFS TSM **or** `GET_REPORT0` + QGS over vsock / `GET_QUOTE` TDVMCALL ioctl | none |
| `snp` | `/dev/sev-guest` `SNP_GET_EXT_REPORT` ioctl | none |
| `csv` | `/dev/csv-guest` `CSV_GET_REPORT` ioctl (SM3) | none |
| TDX GPU evidence | NVIDIA NVML (optional, `-tags gpu`) | `libnvidia-ml` via `dlopen` |

All TDX quote paths present in the Rust attester are implemented:

1. **ConfigFS TSM** (`/sys/kernel/config/tsm/report`) — primary, used when available.
2. **QGS over vsock** — used when `/etc/tdx-attest.conf` configures a port.
3. **`TDX_CMD_GET_QUOTE` TDVMCALL ioctl** — fallback (what `libtdx_attest`
   does internally, reimplemented here without the library).

`GET_REPORT0` (for `BindInitData` / `GetRuntimeMeasurement`) and RTMR extension
(sysfs + `TDX_CMD_EXTEND_RTMR` ioctl) are also implemented natively.

## Package layout

```
attester-go/
├── attester.go          # facade: New() / DetectTeeType() + re-exported API
├── api/                 # Attester interface + value types (leaf, no platform deps)
├── internal/            # implementation details
│   ├── ioctl/           #   Linux _IOC encoding + ioctl wrapper
│   ├── eventlog/        #   CCEL/AAEL event-log reader
│   ├── tsm/             #   ConfigFS TSM_REPORT
│   ├── sm3/             #   self-contained SM3 (for CSV)
│   └── util/            #   Pad / FileExists
├── platform/            # one package per TEE
│   ├── sample/
│   ├── tdx/             #   tdx.go / qgs.go / report.go / gpu*.go
│   ├── snp/
│   └── csv/
└── cmd/evidence_getter/
```

Platform packages import `api` (the interface they implement); the top-level
`attester` package imports `api` + the platform packages and wires them
together — so there is no import cycle.

## Build

Default build is pure Go with **no cgo** and **no external library**:

```sh
CGO_ENABLED=0 go build ./...
```

The resulting binary is fully static and starts on any host — a platform whose
device node is absent simply is not detected. To enable NVIDIA GPU evidence:

```sh
CGO_ENABLED=1 go build -tags gpu ./...
```

`-tags gpu` pulls in `github.com/NVIDIA/go-nvml`, which `dlopen`s
`libnvidia-ml` at runtime, so the binary still starts on machines without an
NVIDIA driver (GPU evidence is simply skipped).

## Library usage

```go
import attester "github.com/confidential-containers/guest-components/attestation-agent/attester-go"

tee := attester.DetectTeeType()          // e.g. attester.TeeTdx
att, _ := attester.New(tee)

reportData := make([]byte, 64)           // nonce / user data
evidence, err := att.GetEvidence(reportData) // evidence is compact JSON ([]byte)
```

The `Attester` interface mirrors the Rust trait: `GetEvidence`,
`ExtendRuntimeMeasurement`, `BindInitData`, `GetRuntimeMeasurement`,
`PcrToCcmr`, `CcelHashAlgorithm`.

## evidence_getter

A small CLI mirroring the Rust `evidence_getter` binary:

```sh
go build -o evidence_getter ./cmd/evidence_getter

./evidence_getter detect                 # print detected TEE
./evidence_getter commandline <data>     # get evidence, report_data=<data>
./evidence_getter stdio                  # report_data from stdin
./evidence_getter file <path>            # report_data from a file
./evidence_getter measurement <pcr>      # print a runtime measurement register
./evidence_getter -tee tdx commandline x # force a TEE type
```

## Evidence-format compatibility notes

The evidence JSON must match `serde_json`'s output of the Rust structs
byte-for-byte:

- Fixed-size `[u8; N]` fields are rendered as JSON **number arrays**
  (`[N]byte` in Go, never `[]byte`, which would base64-encode).
- `Vec<u8>` fields that must render as number arrays (SNP `CertTableEntry.data`,
  CSV `serial_number`) use a custom marshaler.
- Newtype wrappers (`GuestPolicy`, `PlatformInfo`, `Usage`, …) render as bare
  numbers.
- SNP `cert_type` renders as a bare string (`"VCEK"`) or `{"OTHER":"<uuid>"}`.
- `Option` fields keep the exact `null` / omitted behaviour of the Rust
  `#[serde(skip_serializing_if)]` annotations.

## Testing status

- **TDX**: validated end-to-end on real Intel TDX hardware (quote generation via
  the `GET_QUOTE` TDVMCALL ioctl path, report_data and RTMRs verified to be
  embedded in the produced quote; runtime measurements via `GET_REPORT0`).
- **Sample**: covered by unit tests.
- **SNP / CSV**: struct sizes and JSON byte-format are locked by unit tests; the
  ioctl collection paths follow the `sev` (4.0.0) and `csv-rs` ABIs but have not
  been exercised on real SNP/CSV hardware.
