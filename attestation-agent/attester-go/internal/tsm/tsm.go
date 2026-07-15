// Copyright (c) 2024 Intel Corporation
// Copyright (c) 2024 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0

// Package tsm drives the ConfigFS TSM_REPORT interface, mirroring the Rust
// attester tsm_report module.
package tsm

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const basePath = "/sys/kernel/config/tsm/report"

// TSM provider strings as written to the ConfigFS `provider` attribute (note
// the trailing newline the kernel appends).
const (
	ProviderTdx = "tdx_guest\n"
	ProviderSev = "sev_guest\n"
	ProviderCca = "arm_cca_guest\n"
)

// Available reports whether the ConfigFS TSM_REPORT interface is present.
func Available() bool {
	_, err := os.Stat(basePath)
	return err == nil
}

// GetReport drives one one-shot TSM_REPORT request through ConfigFS: it creates
// a temporary report entry, verifies the provider, writes the report data to
// `inblob`, reads the resulting `outblob` (the quote), and removes the entry.
//
// privlevel is only written for the SEV provider (pass -1 to skip).
func GetReport(wantProvider string, reportData []byte, privlevel int) ([]byte, error) {
	if !Available() {
		return nil, fmt.Errorf("tsm: %s not available", basePath)
	}

	dir, err := os.MkdirTemp(basePath, "")
	if err != nil {
		return nil, fmt.Errorf("tsm: create report entry: %w", err)
	}
	defer func() { _ = os.Remove(dir) }()

	if err := checkProvider(dir, wantProvider); err != nil {
		return nil, err
	}

	if privlevel >= 0 {
		if err := os.WriteFile(filepath.Join(dir, "privlevel"), []byte{byte(privlevel)}, 0o644); err != nil {
			return nil, fmt.Errorf("tsm: write privlevel: %w", err)
		}
	}

	if len(reportData) == 0 {
		return nil, fmt.Errorf("tsm: empty inblob")
	}
	if err := os.WriteFile(filepath.Join(dir, "inblob"), reportData, 0o644); err != nil {
		return nil, fmt.Errorf("tsm: write inblob: %w", err)
	}

	outblob, err := os.ReadFile(filepath.Join(dir, "outblob"))
	if err != nil {
		return nil, fmt.Errorf("tsm: read outblob: %w", err)
	}

	if err := checkWriteRace(dir); err != nil {
		return nil, err
	}
	return outblob, nil
}

func checkProvider(dir, wantProvider string) error {
	got, err := os.ReadFile(filepath.Join(dir, "provider"))
	if err != nil {
		return fmt.Errorf("tsm: read provider: %w", err)
	}
	if string(got) != wantProvider {
		return fmt.Errorf("tsm: missing provider: want %q got %q", wantProvider, string(got))
	}
	return nil
}

// checkWriteRace ensures no other writer raced on the same entry: the
// `generation` counter must be exactly 1 after our single inblob write.
func checkWriteRace(dir string) error {
	g, err := os.ReadFile(filepath.Join(dir, "generation"))
	if err != nil {
		return fmt.Errorf("tsm: read generation: %w", err)
	}
	generation, err := strconv.ParseUint(strings.TrimSpace(string(g)), 10, 32)
	if err != nil {
		return fmt.Errorf("tsm: parse generation: %w", err)
	}
	if generation > 1 {
		return fmt.Errorf("tsm: inblob write conflict (generation=%d)", generation)
	}
	return nil
}
