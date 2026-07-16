// Copyright (c) 2024 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"os"
	"strings"
)

// AaKbcParams mirrors the Rust aa_kbc_params: the `kbc::uri` pair sourced from
// the AA_KBC_PARAMS environment variable or the kernel command line.
type AaKbcParams struct {
	Kbc string
	Uri string
}

// DefaultAaKbcParams is used when neither the environment variable nor the
// kernel command line provides a value.
func DefaultAaKbcParams() AaKbcParams {
	return AaKbcParams{Kbc: "offline_fs_kbc", Uri: ""}
}

// NewAaKbcParams resolves the aa_kbc_params, falling back to the default when
// no value is found. Mirrors Rust AaKbcParams::new.
func NewAaKbcParams() (AaKbcParams, error) {
	value, err := aaKbcParamsValue()
	if err != nil {
		// failed to get from either env or kernel cmdline: use default.
		return DefaultAaKbcParams(), nil
	}
	return parseAaKbcParams(value)
}

func aaKbcParamsValue() (string, error) {
	if params, ok := os.LookupEnv("AA_KBC_PARAMS"); ok {
		return params, nil
	}
	return aaKbcParamsFromCmdline()
}

func aaKbcParamsFromCmdline() (string, error) {
	cmdline, err := os.ReadFile("/proc/cmdline")
	if err != nil {
		return "", err
	}
	const prefix = "agent.aa_kbc_params="
	for _, field := range strings.Fields(string(cmdline)) {
		if v, ok := strings.CutPrefix(field, prefix); ok {
			return v, nil
		}
	}
	return "", fmt.Errorf("no `agent.aa_kbc_params` provided in kernel commandline")
}

func parseAaKbcParams(value string) (AaKbcParams, error) {
	segments := strings.Split(value, "::")
	if len(segments) != 2 {
		return AaKbcParams{}, fmt.Errorf("illegal aa_kbc_params format: %s", value)
	}
	return AaKbcParams{Kbc: segments[0], Uri: segments[1]}, nil
}
