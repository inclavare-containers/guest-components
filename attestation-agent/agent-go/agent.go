// Copyright (c) 2024 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0

// Package attestationagent is a pure-Go re-implementation of the guest-components
// `attestation-agent` library crate (attestation-agent/attestation-agent). It
// provides the attestation procedures used by confidential containers on top of
// the pure-Go attester-go module:
//
//   - GetToken: obtain an attestation token from a remote service (CoCoAS).
//   - GetEvidence: obtain TEE hardware-signed evidence for given runtime data.
//   - ExtendRuntimeMeasurement: extend a runtime measurement register and record
//     the event in the AA Event Log (AAEL).
//   - BindInitData: bind an init-data digest to the TEE.
//
// Differences from the Rust crate, all following the scope already established
// by attester-go:
//
//   - No cgo and no external shared library: every platform is reached through
//     attester-go's native kernel interfaces.
//   - The `instance_info` feature (AA instance info / heartbeat) is not ported.
//   - KBS token support is not ported (it needs a Go port of kbs_protocol); the
//     CoCoAS token is fully implemented. See package token.
//   - attester-go exposes no additional (device) attesters, so
//     GetAdditionalEvidence always returns empty and GetAdditionalTees is empty.
package attestationagent

import (
	"encoding/json"
	"fmt"
	"sync"

	attester "github.com/confidential-containers/guest-components/attestation-agent/attester-go"

	"github.com/confidential-containers/guest-components/attestation-agent/agent-go/config"
	"github.com/confidential-containers/guest-components/attestation-agent/agent-go/eventlog"
	"github.com/confidential-containers/guest-components/attestation-agent/agent-go/token"
)

// Re-exported attester types for convenience.
type (
	// Tee identifies the confidential computing platform.
	Tee = attester.Tee
	// InitDataResult is the outcome of BindInitData.
	InitDataResult = attester.InitDataResult
	// Config is the AA configuration.
	Config = config.Config
)

// AttestationAPIs is the service API surface of the attestation agent,
// mirroring the Rust `AttestationAPIs` trait.
type AttestationAPIs interface {
	// GetToken obtains an attestation token of the given type. additionalData
	// is forwarded to the CoCoAS token getter (pass nil for none).
	GetToken(tokenType string, additionalData *string) ([]byte, error)

	// GetEvidence returns TEE hardware-signed evidence that includes
	// runtimeData, as compact JSON bytes.
	GetEvidence(runtimeData []byte) ([]byte, error)

	// GetAdditionalEvidence returns evidence from all additional attesters. It
	// returns an empty slice when none are configured.
	GetAdditionalEvidence(runtimeData []byte) ([]byte, error)

	// ExtendRuntimeMeasurement extends a runtime measurement register with the
	// event (domain, operation, content) and records it in the AAEL.
	// registerIndex selects the target register; pass nil for the configured
	// default.
	ExtendRuntimeMeasurement(domain, operation, content string, registerIndex *uint64) error

	// BindInitData binds an init-data digest to the current TEE.
	BindInitData(initData []byte) (InitDataResult, error)

	// GetTeeType returns the detected primary TEE type.
	GetTeeType() Tee

	// GetAdditionalTees returns the additional (device) TEE types.
	GetAdditionalTees() []Tee
}

// AttestationAgent provides the attestation service. Create it with New and,
// before extending runtime measurements, call Init.
type AttestationAgent struct {
	primaryTee Tee

	configMu sync.RWMutex
	config   *config.Config

	eventlogMu sync.Mutex
	eventlog   *eventlog.EventLog

	initdata *string

	primaryAttester     attester.Attester
	additionalAttesters map[Tee]attester.Attester
}

// Compile-time assertion that AttestationAgent satisfies AttestationAPIs.
var _ AttestationAPIs = (*AttestationAgent)(nil)

// New creates an AttestationAgent. If configPath is nil, a default
// configuration is used; otherwise the file (TOML or JSON) is loaded. Mirrors
// Rust AttestationAgent::new.
func New(configPath *string) (*AttestationAgent, error) {
	var cfg *config.Config
	var err error
	if configPath != nil {
		if cfg, err = config.Load(*configPath); err != nil {
			return nil, err
		}
	} else {
		if cfg, err = config.New(); err != nil {
			return nil, err
		}
	}

	primaryTee := attester.DetectTeeType()
	primaryAttester, err := attester.New(primaryTee)
	if err != nil {
		return nil, err
	}

	// attester-go exposes no additional (device) attesters; the map stays empty.
	return &AttestationAgent{
		primaryTee:          primaryTee,
		config:              cfg,
		primaryAttester:     primaryAttester,
		additionalAttesters: map[Tee]attester.Attester{},
	}, nil
}

// Init initializes the event log if it is enabled in the configuration.
// Mirrors Rust AttestationAgent::init (minus the dropped instance_info setup).
func (a *AttestationAgent) Init() error {
	a.configMu.RLock()
	enable := a.config.EventlogConfig.EnableEventlog
	initPCR := a.config.EventlogConfig.InitPcr
	a.configMu.RUnlock()

	if !enable {
		return nil
	}

	el, err := eventlog.New(a.primaryAttester, initPCR)
	if err != nil {
		return err
	}
	a.eventlogMu.Lock()
	a.eventlog = el
	a.eventlogMu.Unlock()
	return nil
}

// SetInitdataToml records the init-data TOML as the state of this AA instance,
// mirroring Rust set_initdata_toml.
func (a *AttestationAgent) SetInitdataToml(initdataToml string) {
	a.initdata = &initdataToml
}

// Config returns the current configuration (read-locked copy of the pointer).
func (a *AttestationAgent) Config() *config.Config {
	a.configMu.RLock()
	defer a.configMu.RUnlock()
	return a.config
}

// GetToken implements AttestationAPIs.
func (a *AttestationAgent) GetToken(tokenType string, additionalData *string) ([]byte, error) {
	tt, err := token.ParseTokenType(tokenType)
	if err != nil {
		return nil, fmt.Errorf("Unsupported token type: %w", err)
	}

	a.configMu.RLock()
	tokenConfigs := a.config.TokenConfigs
	initdata := a.initdata
	a.configMu.RUnlock()

	switch tt {
	case token.TokenTypeKbs:
		if tokenConfigs.Kbs == nil {
			return nil, fmt.Errorf("kbs token config not configured in config file")
		}
		return token.NewKbs(tokenConfigs.Kbs).GetToken(initdata)
	case token.TokenTypeCoCoAS:
		if tokenConfigs.CoCoAS == nil {
			return nil, fmt.Errorf("coco_as token config not configured in config file")
		}
		return token.NewCoCoAS(tokenConfigs.CoCoAS).GetToken(additionalData)
	default:
		return nil, fmt.Errorf("Unsupported token type: %s", tokenType)
	}
}

// GetEvidence implements AttestationAPIs.
func (a *AttestationAgent) GetEvidence(runtimeData []byte) ([]byte, error) {
	evidence, err := a.primaryAttester.GetEvidence(runtimeData)
	if err != nil {
		return nil, err
	}
	// evidence is already compact JSON, matching the Rust
	// evidence.to_string().into_bytes().
	return []byte(evidence), nil
}

// GetAdditionalEvidence implements AttestationAPIs.
func (a *AttestationAgent) GetAdditionalEvidence(runtimeData []byte) ([]byte, error) {
	if len(a.additionalAttesters) == 0 {
		// No additional attesters configured, return empty evidence.
		return []byte{}, nil
	}

	evidence := make(map[Tee]json.RawMessage, len(a.additionalAttesters))
	for tee, att := range a.additionalAttesters {
		ev, err := att.GetEvidence(runtimeData)
		if err != nil {
			return nil, err
		}
		evidence[tee] = json.RawMessage(ev)
	}
	out, err := json.Marshal(evidence)
	if err != nil {
		return nil, fmt.Errorf("Failed to serialize additional evidence: %w", err)
	}
	return out, nil
}

// ExtendRuntimeMeasurement implements AttestationAPIs.
func (a *AttestationAgent) ExtendRuntimeMeasurement(domain, operation, content string, registerIndex *uint64) error {
	a.eventlogMu.Lock()
	defer a.eventlogMu.Unlock()

	if a.eventlog == nil {
		return fmt.Errorf("Extend eventlog not enabled when launching!")
	}

	pcr := a.defaultPCR()
	if registerIndex != nil {
		pcr = *registerIndex
	}

	event, err := eventlog.NewEvent(domain, operation, content)
	if err != nil {
		return err
	}
	return a.eventlog.ExtendEntry(event, pcr)
}

func (a *AttestationAgent) defaultPCR() uint64 {
	a.configMu.RLock()
	defer a.configMu.RUnlock()
	return a.config.EventlogConfig.InitPcr
}

// BindInitData implements AttestationAPIs.
func (a *AttestationAgent) BindInitData(initData []byte) (InitDataResult, error) {
	return a.primaryAttester.BindInitData(initData)
}

// GetTeeType implements AttestationAPIs.
func (a *AttestationAgent) GetTeeType() Tee {
	return a.primaryTee
}

// GetAdditionalTees implements AttestationAPIs.
func (a *AttestationAgent) GetAdditionalTees() []Tee {
	tees := make([]Tee, 0, len(a.additionalAttesters))
	for tee := range a.additionalAttesters {
		tees = append(tees, tee)
	}
	return tees
}
