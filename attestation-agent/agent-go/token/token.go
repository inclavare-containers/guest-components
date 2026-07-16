// Copyright (c) 2024 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0

// Package token is a pure-Go re-implementation of the attestation-agent crate
// `token` module. It obtains an attestation token from a remote service.
//
// The CoCoAS token getter is fully implemented. The KBS token getter requires
// the KBS background-check protocol (the Rust `kbs_protocol` crate, including
// the RCAR handshake and TEE key pair), which is not yet ported to Go; its
// GetToken therefore returns ErrKbsNotImplemented.
package token

import "fmt"

// TokenType identifies the remote attestation-token source.
type TokenType string

const (
	// TokenTypeKbs obtains a token from a Key Broker Service.
	TokenTypeKbs TokenType = "kbs"
	// TokenTypeCoCoAS obtains a token from a CoCo Attestation Service.
	TokenTypeCoCoAS TokenType = "coco_as"
)

// ParseTokenType parses a token type string, mirroring the Rust
// TokenType::from_str.
func ParseTokenType(s string) (TokenType, error) {
	switch TokenType(s) {
	case TokenTypeKbs:
		return TokenTypeKbs, nil
	case TokenTypeCoCoAS:
		return TokenTypeCoCoAS, nil
	default:
		return "", fmt.Errorf("token: unsupported token type %q", s)
	}
}
