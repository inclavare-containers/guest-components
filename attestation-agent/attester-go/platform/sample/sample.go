// Copyright (c) 2024 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0

// Package sample implements the always-available software-backed attester.
package sample

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/confidential-containers/guest-components/attestation-agent/attester-go/api"
	"github.com/confidential-containers/guest-components/attestation-agent/attester-go/internal/eventlog"
)

const (
	measureRegisterPath = "/run/attestation-agent/sample_measure_register"
	measureDigestLen    = 32
)

// quote is the sample evidence. Field order matches the Rust SampleQuote.
type quote struct {
	Svn             string  `json:"svn"`
	ReportData      string  `json:"report_data"`
	MeasureRegister string  `json:"measure_register"`
	CcEventlog      *string `json:"cc_eventlog"`
}

// DetectPlatform always returns true: the sample attester is the fallback.
func DetectPlatform() bool { return true }

// measureRegister is a minimal software-backed measurement register.
type measureRegister struct {
	path string
	mu   sync.Mutex
}

func newMeasureRegister(path string) *measureRegister {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		if parent := filepath.Dir(path); parent != "" {
			_ = os.MkdirAll(parent, 0o755)
		}
		zeros := make([]byte, measureDigestLen)
		_ = os.WriteFile(path, []byte(hex.EncodeToString(zeros)), 0o644)
	}
	return &measureRegister{path: path}
}

func (m *measureRegister) currentValue() ([]byte, error) {
	content, err := os.ReadFile(m.path)
	if err != nil {
		return nil, fmt.Errorf("read sample measure register %s: %w", m.path, err)
	}
	trimmed := strings.TrimSpace(string(content))
	if trimmed == "" {
		return nil, fmt.Errorf("sample measure register %s is empty", m.path)
	}
	decoded, err := hex.DecodeString(trimmed)
	if err != nil {
		return nil, fmt.Errorf("decode sample measure register %s: %w", m.path, err)
	}
	if len(decoded) != measureDigestLen {
		return nil, fmt.Errorf("sample measure register length %d != %d", len(decoded), measureDigestLen)
	}
	return decoded, nil
}

func (m *measureRegister) store(value []byte) error {
	if len(value) != measureDigestLen {
		return fmt.Errorf("invalid measurement length %d, expected %d", len(value), measureDigestLen)
	}
	if parent := filepath.Dir(m.path); parent != "" {
		if err := os.MkdirAll(parent, 0o755); err != nil {
			return err
		}
	}
	return os.WriteFile(m.path, []byte(hex.EncodeToString(value)), 0o644)
}

func (m *measureRegister) extend(eventDigest []byte) ([]byte, error) {
	material, err := m.currentValue()
	if err != nil {
		return nil, err
	}
	material = append(material, eventDigest...)
	updated := sha256.Sum256(material)
	if err := m.store(updated[:]); err != nil {
		return nil, err
	}
	return updated[:], nil
}

// Attester is the sample attester.
type Attester struct {
	api.Base
	reg *measureRegister
}

// New creates a sample Attester.
func New() *Attester {
	return &Attester{reg: newMeasureRegister(measureRegisterPath)}
}

func (a *Attester) GetEvidence(reportData []byte) (api.TeeEvidence, error) {
	a.reg.mu.Lock()
	defer a.reg.mu.Unlock()

	bytes, err := a.reg.currentValue()
	if err != nil {
		return nil, err
	}
	ccEventlog, err := eventlog.Read()
	if err != nil {
		return nil, err
	}

	ev := quote{
		Svn:             "1",
		ReportData:      base64.StdEncoding.EncodeToString(reportData),
		MeasureRegister: hex.EncodeToString(bytes),
		CcEventlog:      ccEventlog,
	}
	return json.Marshal(ev)
}

func (a *Attester) ExtendRuntimeMeasurement(eventDigest []byte, _ uint64) error {
	if len(eventDigest) != measureDigestLen {
		return fmt.Errorf("sample attester requires %d-byte digest (SHA256), got %d", measureDigestLen, len(eventDigest))
	}
	a.reg.mu.Lock()
	defer a.reg.mu.Unlock()
	_, err := a.reg.extend(eventDigest)
	return err
}

func (a *Attester) GetRuntimeMeasurement(_ uint64) ([]byte, error) {
	a.reg.mu.Lock()
	defer a.reg.mu.Unlock()
	return a.reg.currentValue()
}

// PcrToCcmr maps all PCR indices to a single simulated register.
func (a *Attester) PcrToCcmr(_ uint64) uint64 { return 1 }

func (a *Attester) CcelHashAlgorithm() api.HashAlgorithm { return api.HashSha256 }
