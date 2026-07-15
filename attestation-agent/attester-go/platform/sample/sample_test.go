// Copyright (c) 2024 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0

package sample

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"path/filepath"
	"testing"
)

func TestSampleAttester(t *testing.T) {
	reg := newMeasureRegister(filepath.Join(t.TempDir(), "reg"))
	a := &Attester{reg: reg}

	ev, err := a.GetEvidence([]byte{1, 2, 3, 4, 5})
	if err != nil {
		t.Fatal(err)
	}
	var q quote
	if err := json.Unmarshal(ev, &q); err != nil {
		t.Fatalf("evidence not valid JSON: %v (%s)", err, ev)
	}
	if q.Svn != "1" {
		t.Errorf("svn = %q, want 1", q.Svn)
	}
	if got, _ := base64.StdEncoding.DecodeString(q.ReportData); !bytes.Equal(got, []byte{1, 2, 3, 4, 5}) {
		t.Errorf("report_data roundtrip failed: %q", q.ReportData)
	}
	if len(q.MeasureRegister) != 64 {
		t.Errorf("measure_register hex len = %d, want 64", len(q.MeasureRegister))
	}

	before, _ := reg.currentValue()
	if err := a.ExtendRuntimeMeasurement(make([]byte, 32), 0); err != nil {
		t.Fatal(err)
	}
	after, _ := reg.currentValue()
	if bytes.Equal(before, after) {
		t.Error("extend did not change measure register")
	}

	if err := a.ExtendRuntimeMeasurement(make([]byte, 16), 0); err == nil {
		t.Error("expected error for 16-byte digest")
	}
}
