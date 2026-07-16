// Copyright (c) 2024 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0

package token

import (
	"os"
	"testing"

	"github.com/confidential-containers/guest-components/attestation-agent/agent-go/config"
)

func TestParseTokenType(t *testing.T) {
	for _, s := range []string{"kbs", "coco_as"} {
		if _, err := ParseTokenType(s); err != nil {
			t.Errorf("ParseTokenType(%q): unexpected error %v", s, err)
		}
	}
	if _, err := ParseTokenType("bogus"); err == nil {
		t.Error("expected error for unknown token type")
	}
}

func TestKbsNotImplemented(t *testing.T) {
	g := NewKbs(&config.KbsConfig{URL: "https://127.0.0.1:8080"})
	if _, err := g.GetToken(nil); err != ErrKbsNotImplemented {
		t.Errorf("expected ErrKbsNotImplemented, got %v", err)
	}
}

func TestCoCoASURLResolution(t *testing.T) {
	orig, had := os.LookupEnv("TRUSTEE_URL")
	os.Unsetenv("TRUSTEE_URL")
	t.Cleanup(func() {
		if had {
			os.Setenv("TRUSTEE_URL", orig)
		}
	})

	// Without TRUSTEE_URL, the config URL is used as-is.
	g := NewCoCoAS(&config.CoCoASConfig{URL: "http://as.example.com"})
	if g.asURI != "http://as.example.com" {
		t.Errorf("asURI = %q, want config url", g.asURI)
	}

	// With TRUSTEE_URL, the gateway path is appended.
	t.Setenv("TRUSTEE_URL", "http://trustee.example.com")
	g = NewCoCoAS(&config.CoCoASConfig{URL: "http://as.example.com"})
	if g.asURI != "http://trustee.example.com/attestation-service" {
		t.Errorf("asURI = %q, want gateway path", g.asURI)
	}
}
