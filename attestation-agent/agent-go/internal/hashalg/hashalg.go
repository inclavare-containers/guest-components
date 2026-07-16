// Copyright (c) 2024 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0

// Package hashalg resolves the platform hash algorithm (as reported by an
// attester's CcelHashAlgorithm) to a concrete digest, mirroring the Rust
// kbs_types::HashAlgorithm::digest / digest_len helpers used by the event log.
package hashalg

import (
	"crypto/sha256"
	"crypto/sha512"
	"fmt"

	"github.com/confidential-containers/guest-components/attestation-agent/agent-go/internal/sm3"
)

// Algorithm identifiers, matching the lowercase kbs_types::HashAlgorithm
// serialization surfaced through attester-go's api.HashAlgorithm.
const (
	SHA256 = "sha256"
	SHA384 = "sha384"
	SHA512 = "sha512"
	SM3    = "sm3"
)

// Len returns the digest length in bytes for alg.
func Len(alg string) (int, error) {
	switch alg {
	case SHA256, SM3:
		return 32, nil
	case SHA384:
		return 48, nil
	case SHA512:
		return 64, nil
	default:
		return 0, fmt.Errorf("hashalg: unsupported algorithm %q", alg)
	}
}

// Digest computes the digest of data under alg.
func Digest(alg string, data []byte) ([]byte, error) {
	switch alg {
	case SHA256:
		d := sha256.Sum256(data)
		return d[:], nil
	case SHA384:
		d := sha512.Sum384(data)
		return d[:], nil
	case SHA512:
		d := sha512.Sum512(data)
		return d[:], nil
	case SM3:
		d := sm3.Sum(data)
		return d[:], nil
	default:
		return nil, fmt.Errorf("hashalg: unsupported algorithm %q", alg)
	}
}
