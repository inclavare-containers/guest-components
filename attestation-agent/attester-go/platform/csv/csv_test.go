// Copyright (c) 2024 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0

package csv

import (
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"
)

func TestSizes(t *testing.T) {
	if got := binary.Size(Certificate{}); got != pekCertLen {
		t.Fatalf("Certificate size = %d, want %d", got, pekCertLen)
	}
	if got := binary.Size(CaCertificate{}); got != hskCertLen {
		t.Fatalf("CaCertificate size = %d, want %d", got, hskCertLen)
	}
	if got := binary.Size(reportRequest{}); got != 16 {
		t.Fatalf("reportRequest size = %d, want 16", got)
	}
	if got := binary.Size(rtmrRequest{}); got != 24 {
		t.Fatalf("rtmrRequest size = %d, want 24", got)
	}
}

func TestEvidenceJSON(t *testing.T) {
	var wrapper AttestationReportWrapper
	copy(wrapper.Magic[:], []byte("ATTESTATION_EXT\x00"))
	wrapper.Flags = 1

	ev := Evidence{
		AttestationReport: wrapper,
		CertChain:         CertificateChain{}, // HskCek nil -> omitted
		SerialNumber:      NumberBytes{1, 2, 3},
		CcEventlog:        nil, // -> null
	}
	b, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)

	for _, c := range []string{
		`"serial_number":[1,2,3]`,
		`"cc_eventlog":null`,
		`"flags":1`,
		`"magic":[65,84,84,69,83,84,65,84,73,79,78,95,69,88,84,0]`,
	} {
		if !strings.Contains(s, c) {
			t.Errorf("CSV evidence JSON missing %q", c)
		}
	}
	if strings.Contains(s, `"hsk_cek"`) {
		t.Errorf("hsk_cek should be omitted when nil, got: %s", s)
	}
}
