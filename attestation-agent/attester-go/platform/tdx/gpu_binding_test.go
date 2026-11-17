package tdx

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func TestSharedCPUGPUBindingVector(t *testing.T) {
	raw, err := os.ReadFile("testdata/tdx_gpu_binding_v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		ReportData string          `json:"report_data"`
		Nonce      string          `json:"nonce"`
		Bound      string          `json:"bound_report_data"`
		GPUs       GpuEvidenceList `json:"gpu_evidence"`
	}
	if err := json.Unmarshal(raw, &vector); err != nil {
		t.Fatal(err)
	}
	data, err := hex.DecodeString(vector.ReportData)
	if err != nil {
		t.Fatal(err)
	}
	bound, err := boundReportData(data, &vector.GPUs)
	if err != nil || hex.EncodeToString(bound) != vector.Bound {
		t.Fatalf("binding mismatch: %v", err)
	}
	nonce := gpuNonce(data)
	if hex.EncodeToString(nonce[:]) != vector.Nonce {
		t.Fatal("nonce mismatch")
	}
	changed := append([]byte{}, data...)
	changed[63] ^= 1
	if nonce == gpuNonce(changed) {
		t.Fatal("second half of report data not bound")
	}
	cpuOnly, err := boundReportData(data, nil)
	if err != nil || !bytes.Equal(cpuOnly, data) {
		t.Fatal("CPU-only data changed")
	}
	vector.GPUs.EvidenceList = vector.GPUs.EvidenceList[:1]
	partial, err := boundReportData(data, &vector.GPUs)
	if err != nil || bytes.Equal(bound, partial) {
		t.Fatal("GPU removal not bound")
	}
	vector.GPUs.EvidenceList[0].Certificate = nil
	if _, err := boundReportData(data, &vector.GPUs); err == nil {
		t.Fatal("missing certificate accepted")
	}
}
