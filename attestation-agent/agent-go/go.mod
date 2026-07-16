module github.com/confidential-containers/guest-components/attestation-agent/agent-go

go 1.21

require (
	github.com/BurntSushi/toml v1.4.0
	github.com/confidential-containers/guest-components/attestation-agent/attester-go v0.0.0
)

require (
	github.com/NVIDIA/go-nvml v0.13.0-1 // indirect
	golang.org/x/sys v0.20.0 // indirect
)

replace github.com/confidential-containers/guest-components/attestation-agent/attester-go => ../attester-go
