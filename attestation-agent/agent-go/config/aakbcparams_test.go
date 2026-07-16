// Copyright (c) 2024 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"testing"
)

// TestNewAaKbcParamsDefault verifies the fallback: with no AA_KBC_PARAMS
// environment variable and no `agent.aa_kbc_params` on the kernel command line
// (the case in the test environment), the default is returned.
func TestNewAaKbcParamsDefault(t *testing.T) {
	orig, had := os.LookupEnv("AA_KBC_PARAMS")
	os.Unsetenv("AA_KBC_PARAMS")
	t.Cleanup(func() {
		if had {
			os.Setenv("AA_KBC_PARAMS", orig)
		}
	})

	params, err := NewAaKbcParams()
	if err != nil {
		t.Skipf("kernel command line provides aa_kbc_params in this environment: %v", err)
	}
	if params.Kbc != "offline_fs_kbc" || params.Uri != "" {
		t.Errorf("params = %+v, want default {offline_fs_kbc }", params)
	}
}

func TestParseAaKbcParams(t *testing.T) {
	p, err := parseAaKbcParams("cc_kbc::http://127.0.0.1:8080")
	if err != nil {
		t.Fatal(err)
	}
	if p.Kbc != "cc_kbc" || p.Uri != "http://127.0.0.1:8080" {
		t.Errorf("params = %+v", p)
	}

	if _, err := parseAaKbcParams("not-a-pair"); err == nil {
		t.Error("expected error for malformed params")
	}
}

func TestNewAaKbcParamsFromEnv(t *testing.T) {
	t.Setenv("AA_KBC_PARAMS", "cc_kbc::https://kbs.example.com")
	p, err := NewAaKbcParams()
	if err != nil {
		t.Fatal(err)
	}
	if p.Kbc != "cc_kbc" || p.Uri != "https://kbs.example.com" {
		t.Errorf("params = %+v", p)
	}
}
