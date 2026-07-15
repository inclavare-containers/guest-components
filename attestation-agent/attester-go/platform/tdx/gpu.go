// Copyright (c) 2024 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0

//go:build gpu

// This file is only compiled with `-tags gpu`. It uses github.com/NVIDIA/go-nvml
// which dlopen()s libnvidia-ml at runtime, so a binary built with this tag still
// starts on machines without an NVIDIA driver (GPU evidence is simply skipped).
package tdx

import (
	"encoding/base64"
	"log"
	"time"

	"github.com/NVIDIA/go-nvml/pkg/nvml"
)

// collectGpuEvidence collects confidential-computing evidence from all NVIDIA
// GPUs, mirroring tdx::gpu::evidence::GpuEvidenceCollector. Any failure to
// initialise NVML or query a device is non-fatal and yields nil / a partial
// list, matching the Rust best-effort behaviour.
func collectGpuEvidence(reportData []byte) *GpuEvidenceList {
	if ret := nvml.Init(); ret != nvml.SUCCESS {
		log.Printf("GPU: NVML init failed (%s), skipping GPU evidence", nvml.ErrorString(ret))
		return nil
	}
	defer nvml.Shutdown()

	count, ret := nvml.DeviceGetCount()
	if ret != nvml.SUCCESS || count == 0 {
		return nil
	}

	var nonce [32]byte
	switch {
	case len(reportData) == 0:
		// leave zero
	case len(reportData) <= 32:
		copy(nonce[:], reportData)
	default:
		copy(nonce[:], reportData[:32])
	}

	driverVersion, _ := nvml.SystemGetDriverVersion()

	ccEnabled := false
	if state, ret := nvml.SystemGetConfComputeState(); ret == nvml.SUCCESS {
		ccEnabled = state.CcFeature != 0
	}

	list := &GpuEvidenceList{CollectionTime: time.Now().UTC()}
	for i := 0; i < count; i++ {
		device, ret := nvml.DeviceGetHandleByIndex(i)
		if ret != nvml.SUCCESS {
			log.Printf("GPU: get handle %d failed: %s", i, nvml.ErrorString(ret))
			continue
		}
		uuid, _ := device.GetUUID()
		name, _ := device.GetName()
		vbios, _ := device.GetVbiosVersion()

		ev := GpuEvidence{
			Index:         uint32(i),
			UUID:          uuid,
			Name:          name,
			DriverVersion: driverVersion,
			VbiosVersion:  vbios,
			CcEnabled:     ccEnabled,
		}

		report := nvml.ConfComputeGpuAttestationReport{Nonce: nonce}
		if ret := nvml.DeviceGetConfComputeGpuAttestationReport(device, &report); ret == nvml.SUCCESS {
			b := base64.StdEncoding.EncodeToString(report.AttestationReport[:report.AttestationReportSize])
			ev.AttestationReport = &b
		} else {
			log.Printf("GPU %d: get attestation report failed: %s", i, nvml.ErrorString(ret))
		}

		if ccEnabled {
			if cert, ret := nvml.DeviceGetConfComputeGpuCertificate(device); ret == nvml.SUCCESS {
				b := base64.StdEncoding.EncodeToString(cert.AttestationCertChain[:cert.AttestationCertChainSize])
				ev.Certificate = &b
			} else {
				log.Printf("GPU %d: get certificate failed: %s", i, nvml.ErrorString(ret))
			}
		}

		list.EvidenceList = append(list.EvidenceList, ev)
	}

	if len(list.EvidenceList) == 0 {
		return nil
	}
	return list
}
