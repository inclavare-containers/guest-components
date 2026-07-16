// Copyright (c) 2025 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0

// Package initdata is a pure-Go re-implementation of the attestation-agent
// crate `initdata` module. It parses the Initdata TOML document and computes
// its digest under the declared algorithm.
package initdata

import (
	"fmt"

	"github.com/BurntSushi/toml"

	"github.com/confidential-containers/guest-components/attestation-agent/agent-go/internal/hashalg"
)

// Initdata is the parsed Initdata document. See
// https://github.com/confidential-containers/trustee/blob/main/kbs/docs/initdata.md
type Initdata struct {
	// Version is the Initdata format version.
	Version string `toml:"version"`

	// Algorithm is the hash algorithm used to digest the raw TOML.
	Algorithm string `toml:"algorithm"`

	// Data is the arbitrary key/value payload.
	Data map[string]string `toml:"data"`
}

// ParseAndGetDigest parses the Initdata TOML and returns it together with the
// digest of the raw TOML bytes under the declared algorithm, mirroring the Rust
// Initdata::parse_and_get_digest.
func ParseAndGetDigest(tomlStr string) (*Initdata, []byte, error) {
	var initdata Initdata
	if _, err := toml.Decode(tomlStr, &initdata); err != nil {
		return nil, nil, fmt.Errorf("initdata: parse toml: %w", err)
	}
	digest, err := hashalg.Digest(initdata.Algorithm, []byte(tomlStr))
	if err != nil {
		return nil, nil, err
	}
	return &initdata, digest, nil
}
