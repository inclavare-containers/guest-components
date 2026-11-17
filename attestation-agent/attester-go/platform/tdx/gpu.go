// Copyright (c) 2024-2026 Alibaba Cloud
// SPDX-License-Identifier: Apache-2.0

//go:build gpu

package tdx

import (
	"encoding/base64"
	"fmt"
	"os"
	"time"

	"github.com/NVIDIA/go-nvml/pkg/nvml"
)

// A CPU-only machine may omit GPU evidence. Once devices are discovered,
// collection must succeed for every device; partial lists are not accepted.
func collectGpuEvidence(reportData []byte) (*GpuEvidenceList, error) {
	if ret := nvml.Init(); ret != nvml.SUCCESS {
		if _, err := os.Stat("/dev/nvidiactl"); os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("GPU NVML initialization failed: %s", nvml.ErrorString(ret))
	}
	defer nvml.Shutdown()
	count, ret := nvml.DeviceGetCount()
	if ret != nvml.SUCCESS {
		return nil, fmt.Errorf("GPU enumeration failed: %s", nvml.ErrorString(ret))
	}
	if count == 0 {
		return nil, nil
	}
	if count > 32 {
		return nil, fmt.Errorf("GPU count exceeds 32")
	}
	state, ret := nvml.SystemGetConfComputeState()
	if ret != nvml.SUCCESS || state.CcFeature == 0 {
		return nil, fmt.Errorf("GPU confidential computing unavailable")
	}
	driverVersion, ret := nvml.SystemGetDriverVersion()
	if ret != nvml.SUCCESS {
		return nil, fmt.Errorf("GPU driver query failed: %s", nvml.ErrorString(ret))
	}
	nonce := gpuNonce(reportData)
	list := &GpuEvidenceList{BindingVersion: 1, CollectionTime: time.Now().UTC()}
	for i := 0; i < count; i++ {
		device, ret := nvml.DeviceGetHandleByIndex(i)
		if ret != nvml.SUCCESS {
			return nil, fmt.Errorf("GPU %d handle failed: %s", i, nvml.ErrorString(ret))
		}
		architecture, ret := device.GetArchitecture()
		if ret != nvml.SUCCESS {
			return nil, fmt.Errorf("GPU %d architecture query failed", i)
		}
		arch := ""
		switch architecture {
		case nvml.DEVICE_ARCH_HOPPER:
			arch = "HOPPER"
		case nvml.DEVICE_ARCH_BLACKWELL:
			arch = "BLACKWELL"
		default:
			return nil, fmt.Errorf("GPU %d architecture unsupported", i)
		}
		uuid, _ := device.GetUUID()
		name, _ := device.GetName()
		vbios, _ := device.GetVbiosVersion()
		report := nvml.ConfComputeGpuAttestationReport{Nonce: nonce}
		if ret := nvml.DeviceGetConfComputeGpuAttestationReport(device, &report); ret != nvml.SUCCESS {
			return nil, fmt.Errorf("GPU %d report failed: %s", i, nvml.ErrorString(ret))
		}
		if report.AttestationReportSize == 0 || int(report.AttestationReportSize) > len(report.AttestationReport) {
			return nil, fmt.Errorf("GPU %d report size invalid", i)
		}
		reportB64 := base64.StdEncoding.EncodeToString(report.AttestationReport[:report.AttestationReportSize])
		cert, ret := nvml.DeviceGetConfComputeGpuCertificate(device)
		if ret != nvml.SUCCESS {
			return nil, fmt.Errorf("GPU %d certificate failed: %s", i, nvml.ErrorString(ret))
		}
		if cert.AttestationCertChainSize == 0 || int(cert.AttestationCertChainSize) > len(cert.AttestationCertChain) {
			return nil, fmt.Errorf("GPU %d certificate size invalid", i)
		}
		certB64 := base64.StdEncoding.EncodeToString(cert.AttestationCertChain[:cert.AttestationCertChainSize])
		list.EvidenceList = append(list.EvidenceList, GpuEvidence{Arch: arch, Index: uint32(i),
			UUID: uuid, Name: name, DriverVersion: driverVersion, VbiosVersion: vbios,
			CcEnabled: true, AttestationReport: &reportB64, Certificate: &certB64})
	}
	return list, nil
}
