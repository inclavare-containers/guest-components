// Copyright (c) 2024 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0

// Package api defines the platform-agnostic attester contract: the Attester
// interface and the small value types it exchanges. It is a leaf package (it
// imports nothing from the platform implementations), which lets every platform
// package depend on it without creating an import cycle with the top-level
// factory in package attester.
package api

import (
	"encoding/json"
	"errors"
)

// Tee identifies the confidential computing platform. The string values match
// kbs_types::Tee so they can be surfaced through the AttestationAgent
// GetTeeType RPC unchanged.
type Tee string

const (
	TeeSample Tee = "sample"
	TeeTdx    Tee = "tdx"
	TeeSnp    Tee = "snp"
	TeeCsv    Tee = "csv"
)

// TeeEvidence is the platform specific evidence, ready to be JSON-serialized.
// It mirrors the Rust `TeeEvidence = serde_json::Value`: GetEvidence returns the
// already-marshaled, compact JSON so it matches serde_json byte-for-byte.
type TeeEvidence = json.RawMessage

// InitDataResult is the outcome of BindInitData.
type InitDataResult int

const (
	// InitDataOk means the init-data digest was bound / matches.
	InitDataOk InitDataResult = iota
	// InitDataUnsupported means the platform does not support init data.
	InitDataUnsupported
)

// HashAlgorithm identifies the digest algorithm used by a platform's runtime
// measurement / event log.
type HashAlgorithm string

const (
	HashSha256 HashAlgorithm = "sha256"
	HashSha384 HashAlgorithm = "sha384"
	HashSm3    HashAlgorithm = "sm3"
)

// ErrUnimplemented is returned by optional Attester methods that a given
// platform does not support, matching the Rust trait default behaviour.
var ErrUnimplemented = errors.New("attester: unimplemented")

// Attester is the platform-agnostic interface implemented by every TEE
// attester. It mirrors the Rust `Attester` trait.
type Attester interface {
	// GetEvidence calls the hardware to produce evidence. reportData is bound
	// into the evidence (as user data / nonce) to defeat replay; it is padded
	// or truncated to the platform's fixed report-data size.
	GetEvidence(reportData []byte) (TeeEvidence, error)

	// ExtendRuntimeMeasurement extends a TEE dynamic measurement register with
	// eventDigest, enabling runtime measurement of data.
	ExtendRuntimeMeasurement(eventDigest []byte, registerIndex uint64) error

	// BindInitData checks that the platform's init-data field matches the given
	// digest.
	BindInitData(initDataDigest []byte) (InitDataResult, error)

	// GetRuntimeMeasurement returns the value of the runtime measurement
	// register mapped from the given PCR index.
	GetRuntimeMeasurement(pcrIndex uint64) ([]byte, error)

	// PcrToCcmr maps a TPM PCR index to the platform's CC measurement register.
	PcrToCcmr(pcrIndex uint64) uint64

	// CcelHashAlgorithm returns the hash algorithm used by the platform CCEL.
	CcelHashAlgorithm() HashAlgorithm
}

// Base provides the Rust-trait default implementations so concrete attesters
// only override what they support. Embed it by value.
type Base struct{}

func (Base) ExtendRuntimeMeasurement(_ []byte, _ uint64) error {
	return ErrUnimplemented
}

func (Base) BindInitData(_ []byte) (InitDataResult, error) {
	return InitDataUnsupported, nil
}

func (Base) GetRuntimeMeasurement(_ uint64) ([]byte, error) {
	return nil, ErrUnimplemented
}

func (Base) PcrToCcmr(_ uint64) uint64 {
	panic("attester: PcrToCcmr unimplemented")
}

func (Base) CcelHashAlgorithm() HashAlgorithm {
	panic("attester: CcelHashAlgorithm unimplemented")
}
