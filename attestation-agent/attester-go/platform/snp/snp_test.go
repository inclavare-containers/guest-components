// Copyright (c) 2024 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0

package snp

import (
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"
)

func TestSizes(t *testing.T) {
	if got := binary.Size(AttestationReport{}); got != reportSize {
		t.Fatalf("AttestationReport size = %d, want %d", got, reportSize)
	}
	if got := binary.Size(guestRequest{}); got != 32 {
		t.Fatalf("guestRequest size = %d, want 32", got)
	}
	if got := binary.Size(reportRequest{}); got != 96 {
		t.Fatalf("reportRequest size = %d, want 96", got)
	}
	if got := binary.Size(extReportRequest{}); got != 112 {
		t.Fatalf("extReportRequest size = %d, want 112", got)
	}
}

func TestEvidenceJSON(t *testing.T) {
	var ar AttestationReport
	ar.Version = 2
	ar.Policy = 196608 // GuestPolicy(u64) -> bare number
	ar.ReportData[0] = 1

	ev := Evidence{AttestationReport: ar, CertChain: nil}
	b, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)

	for _, c := range []string{
		`"policy":196608`,
		`"_author_key_en":0`,
		`"_reserved_0":0`,
		`"report_data":[1,0,0,`,
		`"current_tcb":{"bootloader":0,"tee":0,"_reserved":[0,0,0,0],"snp":0,"microcode":0}`,
		`"signature":{"r":[`,
		`"cert_chain":null`,
	} {
		if !strings.Contains(s, c) {
			t.Errorf("SNP evidence JSON missing %q\ngot: %s", c, s)
		}
	}
}

func TestCertEntryJSON(t *testing.T) {
	e := CertTableEntry{CertType: CertType{Name: "VCEK"}, Data: ByteSlice{48, 130, 5}}
	if b, _ := json.Marshal(e); string(b) != `{"cert_type":"VCEK","data":[48,130,5]}` {
		t.Fatalf("cert entry JSON = %s", b)
	}
	other := CertTableEntry{
		CertType: CertType{Name: "OTHER", OtherUUID: "12345678-1234-1234-1234-123456789abc"},
		Data:     ByteSlice{},
	}
	want := `{"cert_type":{"OTHER":"12345678-1234-1234-1234-123456789abc"},"data":[]}`
	if b, _ := json.Marshal(other); string(b) != want {
		t.Fatalf("OTHER cert entry JSON = %s", b)
	}
}
