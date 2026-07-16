// Copyright (c) 2024 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0

// Package config is a pure-Go re-implementation of the attestation-agent crate
// `config` module. It parses the AA configuration (TOML or JSON) and provides
// the same defaults, so an existing attestation-agent.conf works unchanged.
//
// Note: the `instance_info` feature (aa_instance / heartbeat) is intentionally
// not ported. An `[aa_instance]` section in an existing config file is ignored.
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"
)

// DefaultPcrIndex is the default PCR index used by AA (17, the dynamic root of
// trust for measurement register).
const DefaultPcrIndex uint64 = 17

// DefaultAAConfigPath is the default on-disk location of the AA config file.
const DefaultAAConfigPath = "/etc/attestation-agent.conf"

// Config is the top-level AA configuration.
type Config struct {
	// TokenConfigs holds attestation-token related configuration.
	TokenConfigs TokenConfigs `toml:"token_configs" json:"token_configs"`

	// EventlogConfig holds event-log related configuration.
	EventlogConfig EventlogConfig `toml:"eventlog_config" json:"eventlog_config"`
}

// TokenConfigs groups the per-token-type configuration.
type TokenConfigs struct {
	// CoCoAS is the CoCo Attestation Service token configuration.
	CoCoAS *CoCoASConfig `toml:"coco_as" json:"coco_as"`

	// Kbs is the Key Broker Service token configuration.
	Kbs *KbsConfig `toml:"kbs" json:"kbs"`
}

// CoCoASConfig configures the CoCoAS token getter.
type CoCoASConfig struct {
	// URL is the address of the Attestation Service.
	URL string `toml:"url" json:"url"`
}

// KbsConfig configures the KBS token getter.
type KbsConfig struct {
	// URL is the address of the KBS.
	URL string `toml:"url" json:"url"`

	// Cert is the optional KBS HTTPS certificate (PEM).
	Cert *string `toml:"cert" json:"cert"`
}

// EventlogConfig configures the runtime-measurement event log.
type EventlogConfig struct {
	// InitPcr is the PCR register used to extend event-log entries.
	InitPcr uint64 `toml:"init_pcr" json:"init_pcr"`

	// EnableEventlog toggles event-log recording.
	EnableEventlog bool `toml:"enable_eventlog" json:"enable_eventlog"`
}

// DefaultEventlogConfig mirrors the Rust EventlogConfig::default.
func DefaultEventlogConfig() EventlogConfig {
	return EventlogConfig{InitPcr: DefaultPcrIndex, EnableEventlog: false}
}

// New builds a default configuration, sourcing the KBS token config from the
// kernel command line, mirroring Rust Config::new.
func New() (*Config, error) {
	return &Config{
		TokenConfigs:   tokenConfigsFromKernelCmdline(),
		EventlogConfig: DefaultEventlogConfig(),
	}, nil
}

// tokenConfigsFromKernelCmdline mirrors TokenConfigs::from_kernel_cmdline: the
// KBS URL comes from aa_kbc_params, CoCoAS is left unset.
func tokenConfigsFromKernelCmdline() TokenConfigs {
	var kbs *KbsConfig
	if params, err := NewAaKbcParams(); err == nil {
		kbs = &KbsConfig{URL: params.Uri, Cert: nil}
	}
	return TokenConfigs{Kbs: kbs}
}

// Load parses the configuration file at path (TOML or JSON, detected by
// extension). Missing event-log fields fall back to the defaults, mirroring the
// Rust `config` builder defaults.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config file %q: %w", path, err)
	}

	// Pre-populate event-log defaults so absent keys keep the default value,
	// matching the Rust builder's set_default calls.
	cfg := Config{EventlogConfig: DefaultEventlogConfig()}

	if filepath.Ext(path) == ".json" {
		if err := json.Unmarshal(data, &cfg); err != nil {
			return nil, fmt.Errorf("parse json config %q: %w", path, err)
		}
	} else {
		if err := toml.Unmarshal(data, &cfg); err != nil {
			return nil, fmt.Errorf("parse toml config %q: %w", path, err)
		}
	}

	return &cfg, nil
}
