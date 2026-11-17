// Copyright (c) 2026 Alibaba Cloud
// SPDX-License-Identifier: Apache-2.0

//go:build gpu

package tdx

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPciInventoryExcludesNvidiaBridges(t *testing.T) {
	root := t.TempDir()
	for _, device := range []struct{ name, vendor, class string }{
		{"cpu", "0x8086\n", "0x030000\n"},
		{"switch", "0x10de\n", "0x060400\n"},
		{"h20", "0x10de\n", "0x030200\n"},
		{"vga", "0x10de\n", "0x030000\n"},
	} {
		path := filepath.Join(root, device.name)
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(path, "vendor"), []byte(device.vendor), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(path, "class"), []byte(device.class), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if count, err := nvidiaPciGpuCount(root); err != nil || count != 2 {
		t.Fatalf("count=%d, err=%v", count, err)
	}
	if err := os.Remove(filepath.Join(root, "h20", "vendor")); err != nil {
		t.Fatal(err)
	}
	if _, err := nvidiaPciGpuCount(root); err == nil {
		t.Fatal("unreadable PCI inventory accepted")
	}
}
