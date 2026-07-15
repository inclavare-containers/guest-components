// Copyright (c) 2024 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0

//go:build !gpu

package tdx

// collectGpuEvidence is a no-op in the default (pure-Go, no-cgo) build. Build
// with `-tags gpu` to enable NVIDIA GPU evidence collection via go-nvml.
func collectGpuEvidence(_ []byte) *GpuEvidenceList {
	return nil
}
