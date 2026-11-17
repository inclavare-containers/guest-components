// Copyright (c) 2026 Alibaba Cloud
// SPDX-License-Identifier: Apache-2.0

//go:build gpu

package tdx

import (
	"os"
	"path/filepath"
	"strings"
)

// NVML may return zero devices after GPU initialization fails. Check the PCI
// inventory before accepting CPU-only evidence; exclude NVIDIA PCI bridges.
func nvidiaPciGpuCount(root string) (int, error) {
	entries, err := os.ReadDir(root)
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	count := 0
	for _, entry := range entries {
		vendor, err := os.ReadFile(filepath.Join(root, entry.Name(), "vendor"))
		if err != nil {
			return 0, err
		}
		class, err := os.ReadFile(filepath.Join(root, entry.Name(), "class"))
		if err != nil {
			return 0, err
		}
		if strings.TrimSpace(string(vendor)) == "0x10de" && strings.HasPrefix(strings.TrimSpace(string(class)), "0x03") {
			count++
		}
	}
	return count, nil
}
