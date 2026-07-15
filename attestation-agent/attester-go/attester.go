// Copyright (c) 2024 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0

// Package attester is a pure-Go re-implementation of the guest-components
// `attester` crate (attestation-agent/attester). It collects hardware
// attestation evidence from a confidential guest and produces evidence whose
// JSON representation is byte-compatible with the Rust attester, so it can be
// verified by an unmodified Trustee attestation-service.
//
// Supported TEE platforms: Sample, Intel TDX (+ optional NVIDIA GPU evidence),
// AMD SEV-SNP and Hygon CSV.
//
// The contract (interface and value types) lives in package api; each platform
// is implemented in its own package under platform/. This file is a thin facade
// that re-exports the public API and provides the New / DetectTeeType factory.
//
// Unlike the Rust crate, all platforms are accessed through native kernel
// interfaces (ConfigFS TSM, ioctl on /dev/tdx_guest, /dev/sev-guest,
// /dev/csv-guest, vsock), so the default build has no cgo and no external
// shared-library dependency. NVIDIA GPU evidence is the only optional native
// dependency and is gated behind the `gpu` build tag.
package attester

import (
	"errors"

	"github.com/confidential-containers/guest-components/attestation-agent/attester-go/api"
	"github.com/confidential-containers/guest-components/attestation-agent/attester-go/platform/csv"
	"github.com/confidential-containers/guest-components/attestation-agent/attester-go/platform/sample"
	"github.com/confidential-containers/guest-components/attestation-agent/attester-go/platform/snp"
	"github.com/confidential-containers/guest-components/attestation-agent/attester-go/platform/tdx"
)

// Re-exported API types (see package api).
type (
	Attester       = api.Attester
	Tee            = api.Tee
	TeeEvidence    = api.TeeEvidence
	InitDataResult = api.InitDataResult
	HashAlgorithm  = api.HashAlgorithm
)

// Re-exported API constants.
const (
	TeeSample = api.TeeSample
	TeeTdx    = api.TeeTdx
	TeeSnp    = api.TeeSnp
	TeeCsv    = api.TeeCsv

	InitDataOk          = api.InitDataOk
	InitDataUnsupported = api.InitDataUnsupported

	HashSha256 = api.HashSha256
	HashSha384 = api.HashSha384
	HashSm3    = api.HashSm3
)

// ErrUnimplemented is returned by unsupported optional Attester methods.
var ErrUnimplemented = api.ErrUnimplemented

// New returns the Attester for the given Tee, mirroring the Rust
// `TryFrom<Tee> for BoxedAttester`.
func New(tee Tee) (Attester, error) {
	switch tee {
	case TeeSample:
		return sample.New(), nil
	case TeeTdx:
		return tdx.New(), nil
	case TeeSnp:
		return snp.New(), nil
	case TeeCsv:
		return csv.New(), nil
	default:
		return nil, errors.New("attester: TEE is not supported: " + string(tee))
	}
}

// DetectTeeType detects which TEE platform the current environment is running
// on, falling back to Sample. Order matches the Rust detect_tee_type.
func DetectTeeType() Tee {
	switch {
	case tdx.DetectPlatform():
		return TeeTdx
	case snp.DetectPlatform():
		return TeeSnp
	case csv.DetectPlatform():
		return TeeCsv
	default:
		return TeeSample
	}
}
