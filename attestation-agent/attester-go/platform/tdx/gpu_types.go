// Copyright (c) 2024 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0

package tdx

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"time"
)

// GpuEvidence is per-GPU attestation evidence. Field order and tags match the
// Rust tdx::gpu::evidence::GpuEvidence.
type GpuEvidence struct {
	Arch              string  `json:"arch"`
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
	BindingVersion uint32        `json:"binding_version"`
	EvidenceList   []GpuEvidence `json:"evidence_list"`
	CollectionTime time.Time     `json:"collection_time"`
}

func gpuNonce(paddedReportData []byte) [32]byte {
	h := sha256.New()
	h.Write([]byte("tdx-nvidia-nonce-v1\x00"))
	h.Write(paddedReportData)
	var nonce [32]byte
	copy(nonce[:], h.Sum(nil))
	return nonce
}

// boundReportData uses the same binary commitment as the Rust attester and
// Trustee. Metadata and JSON serialization are not used as security facts.
func boundReportData(reportData []byte, gpus *GpuEvidenceList) ([]byte, error) {
	if len(reportData) > 64 {
		return nil, fmt.Errorf("TDX report data exceeds 64 bytes")
	}
	padded := make([]byte, 64)
	copy(padded, reportData)
	if gpus == nil {
		return padded, nil
	}
	if gpus.BindingVersion != 1 || len(gpus.EvidenceList) == 0 || len(gpus.EvidenceList) > 32 {
		return nil, fmt.Errorf("invalid GPU binding version or count")
	}
	h := sha512.New()
	h.Write([]byte("tdx-nvidia-evidence-v1\x00"))
	h.Write(padded)
	binary.Write(h, binary.LittleEndian, uint32(len(gpus.EvidenceList)))
	indices := make(map[uint32]bool)
	for _, gpu := range gpus.EvidenceList {
		if indices[gpu.Index] {
			return nil, fmt.Errorf("duplicate GPU index")
		}
		indices[gpu.Index] = true
		if gpu.Arch != "HOPPER" && gpu.Arch != "BLACKWELL" {
			return nil, fmt.Errorf("unsupported GPU architecture")
		}
		if gpu.AttestationReport == nil || gpu.Certificate == nil {
			return nil, fmt.Errorf("missing GPU report or certificate")
		}
		report, err := base64.StdEncoding.DecodeString(*gpu.AttestationReport)
		if err != nil {
			return nil, err
		}
		cert, err := base64.StdEncoding.DecodeString(*gpu.Certificate)
		if err != nil {
			return nil, err
		}
		if len(report) == 0 || len(cert) == 0 || len(report) > 128*1024 || len(cert) > 128*1024 {
			return nil, fmt.Errorf("invalid GPU evidence size")
		}
		binary.Write(h, binary.LittleEndian, gpu.Index)
		for _, field := range [][]byte{[]byte(gpu.Arch), report, cert} {
			binary.Write(h, binary.LittleEndian, uint32(len(field)))
			h.Write(field)
		}
	}
	return h.Sum(nil), nil
}
