# agent-go

`agent-go` is a pure-Go re-implementation of the guest-components
`attestation-agent` **library crate**
(`attestation-agent/attestation-agent`). It sits on top of
[`attester-go`](../attester-go) and exposes the attestation-agent service API to
Go programs, with no cgo and no external shared library.

## What it provides

The `AttestationAPIs` interface mirrors the Rust `AttestationAPIs` trait:

| Method | Description |
| --- | --- |
| `GetEvidence(runtimeData)` | TEE hardware-signed evidence (compact JSON) for the given runtime/report data. |
| `GetAdditionalEvidence(runtimeData)` | Evidence from additional (device) attesters; empty when none. |
| `GetToken(tokenType, additionalData)` | Attestation token from a remote service (`coco_as`). |
| `ExtendRuntimeMeasurement(domain, operation, content, registerIndex)` | Extend a runtime measurement register **and** record the event in the AA Event Log (AAEL). |
| `BindInitData(initData)` | Bind an init-data digest to the TEE. |
| `GetTeeType()` / `GetAdditionalTees()` | The detected primary / additional TEE types. |

Supporting packages, one per Rust module:

- `config` — parse the AA config (TOML or JSON) with the same defaults, plus
  `aa_kbc_params` resolution from the environment / kernel command line.
- `eventlog` — the AAEL: TCG2 event encoding, extend-into-register, and a
  write-ahead log (WAL) that makes the "extend register + append log" pair
  crash-recoverable. The TCG2 event-data digest is byte-compatible with the Rust
  implementation (locked by unit-test vectors).
- `initdata` — parse the Initdata TOML and compute its digest.
- `token` — obtain an attestation token (CoCoAS).

## Usage

```go
import "github.com/confidential-containers/guest-components/attestation-agent/agent-go"

aa, err := attestationagent.New(nil) // or .New(&path) to load a config file
if err != nil { /* ... */ }
if err := aa.Init(); err != nil {    // enables the event log if configured
    /* ... */
}

evidence, err := aa.GetEvidence([]byte("nonce"))
```

## Differences from the Rust crate

All of these follow the scope already established by `attester-go`:

- **No cgo / no shared library.** Every platform is reached through
  `attester-go`'s native kernel interfaces. The default build is
  `CGO_ENABLED=0`.
- **`instance_info` is not ported** (AA instance info / heartbeat). An
  `[aa_instance]` section in an existing config file is ignored.
- **KBS token is not ported.** Obtaining a KBS token needs the KBS
  background-check protocol (the Rust `kbs_protocol` crate: RCAR handshake + TEE
  key pair), which has no Go port yet; `token.KbsTokenGetter.GetToken` returns
  `token.ErrKbsNotImplemented`. The **CoCoAS** token is fully implemented.
- **No additional (device) attesters.** `attester-go` exposes none, so
  `GetAdditionalEvidence` returns empty and `GetAdditionalTees` is empty.

## Testing

```
go test ./...
```

Unit tests cover the TCG2 digest vectors (byte-compatibility with the Rust
attestation-agent), the event-log extend + WAL crash-recovery paths (with an
in-memory attester), config TOML/JSON parsing and defaults, `aa_kbc_params`,
Initdata digest, token dispatch and CoCoAS URL resolution.
