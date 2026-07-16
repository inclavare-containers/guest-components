// Copyright (c) 2024 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"testing"
)

func writeTemp(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadTOML(t *testing.T) {
	const cfg = `
[token_configs.coco_as]
url = "http://127.0.0.1:8000"

[token_configs.kbs]
url = "https://127.0.0.1:8080"
cert = "cert"

[eventlog_config]
init_pcr = 17
enable_eventlog = false
`
	c, err := Load(writeTemp(t, "config.toml", cfg))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.TokenConfigs.CoCoAS == nil || c.TokenConfigs.CoCoAS.URL != "http://127.0.0.1:8000" {
		t.Errorf("coco_as = %+v", c.TokenConfigs.CoCoAS)
	}
	if c.TokenConfigs.Kbs == nil || c.TokenConfigs.Kbs.URL != "https://127.0.0.1:8080" {
		t.Errorf("kbs = %+v", c.TokenConfigs.Kbs)
	}
	if c.TokenConfigs.Kbs.Cert == nil || *c.TokenConfigs.Kbs.Cert != "cert" {
		t.Errorf("kbs cert = %v", c.TokenConfigs.Kbs.Cert)
	}
	if c.EventlogConfig.InitPcr != 17 || c.EventlogConfig.EnableEventlog {
		t.Errorf("eventlog = %+v", c.EventlogConfig)
	}
}

func TestLoadJSON(t *testing.T) {
	const cfg = `{
  "token_configs": { "coco_as": { "url": "http://127.0.0.1:8000" } },
  "eventlog_config": { "init_pcr": 19, "enable_eventlog": true }
}`
	c, err := Load(writeTemp(t, "config.json", cfg))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.TokenConfigs.CoCoAS == nil || c.TokenConfigs.CoCoAS.URL != "http://127.0.0.1:8000" {
		t.Errorf("coco_as = %+v", c.TokenConfigs.CoCoAS)
	}
	if c.TokenConfigs.Kbs != nil {
		t.Errorf("kbs should be nil, got %+v", c.TokenConfigs.Kbs)
	}
	if c.EventlogConfig.InitPcr != 19 || !c.EventlogConfig.EnableEventlog {
		t.Errorf("eventlog = %+v", c.EventlogConfig)
	}
}

// TestLoadDefaultsApplied checks that a config file omitting the event-log
// section still gets the defaults (17, false), mirroring the Rust builder.
func TestLoadDefaultsApplied(t *testing.T) {
	const cfg = `
[token_configs.kbs]
url = "https://127.0.0.1:8080"
`
	c, err := Load(writeTemp(t, "config.toml", cfg))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.EventlogConfig.InitPcr != DefaultPcrIndex || c.EventlogConfig.EnableEventlog {
		t.Errorf("expected defaults, got %+v", c.EventlogConfig)
	}
	if c.TokenConfigs.Kbs.Cert != nil {
		t.Errorf("expected nil cert, got %v", c.TokenConfigs.Kbs.Cert)
	}
}

func TestNewDefaults(t *testing.T) {
	c, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if c.EventlogConfig.InitPcr != DefaultPcrIndex {
		t.Errorf("init_pcr = %d, want %d", c.EventlogConfig.InitPcr, DefaultPcrIndex)
	}
	if c.EventlogConfig.EnableEventlog {
		t.Error("enable_eventlog should default to false")
	}
}
