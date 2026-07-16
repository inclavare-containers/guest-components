// Copyright (c) 2024 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0

package token

import (
	"errors"
	"os"

	"github.com/confidential-containers/guest-components/attestation-agent/agent-go/config"
)

// ErrKbsNotImplemented is returned by KbsTokenGetter.GetToken. Obtaining a KBS
// token requires the KBS background-check protocol (RCAR handshake + TEE key
// pair), implemented by the Rust `kbs_protocol` crate, which has not yet been
// ported to Go.
var ErrKbsNotImplemented = errors.New("token: KBS token is not implemented in the Go port (requires a Go port of kbs_protocol)")

// KbsTokenGetter obtains an attestation token from a Key Broker Service.
//
// The configuration surface (host URL resolution, optional cert) mirrors the
// Rust KbsTokenGetter, but GetToken is not yet functional; see
// ErrKbsNotImplemented.
type KbsTokenGetter struct {
	kbsHostURL string
	cert       *string
}

// NewKbs builds a KbsTokenGetter from config, mirroring the Rust
// KbsTokenGetter::new: TRUSTEE_URL takes precedence over the config URL.
func NewKbs(cfg *config.KbsConfig) *KbsTokenGetter {
	hostURL := cfg.URL
	if envURL, ok := os.LookupEnv("TRUSTEE_URL"); ok {
		hostURL = envURL
	}
	return &KbsTokenGetter{kbsHostURL: hostURL, cert: cfg.Cert}
}

// GetToken is not implemented; see ErrKbsNotImplemented.
func (g *KbsTokenGetter) GetToken(initdata *string) ([]byte, error) {
	return nil, ErrKbsNotImplemented
}
