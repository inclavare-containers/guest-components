// Copyright (c) 2024 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0

package tdx

import "time"

// GpuEvidence is per-GPU attestation evidence. Field order and tags match the
// Rust tdx::gpu::evidence::GpuEvidence.
type GpuEvidence struct {
	Index             uint32  `json:"index"`
	UUID              string  `json:"uuid"`
	Name              string  `json:"name"`
	DriverVersion     string  `json:"driver_version"`
	VbiosVersion      string  `json:"vbios_version"`
	AttestationReport *string `json:"attestation_report"`
	Certificate       *string `json:"certificate"`
	CcEnabled         bool    `json:"cc_enabled"`
}

// GpuEvidenceList is the collection of per-GPU evidence with a collection
// timestamp. Matches the Rust GpuEvidenceList.
type GpuEvidenceList struct {
	EvidenceList   []GpuEvidence `json:"evidence_list"`
	CollectionTime time.Time     `json:"collection_time"`
}
