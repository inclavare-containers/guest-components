// Copyright (c) 2024 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0

package attestationagent

import (
	"testing"

	attester "github.com/confidential-containers/guest-components/attestation-agent/attester-go"
)

// TestAttestationAgent mirrors the Rust test_attestation_agent: on a
// non-confidential host the sample attester is used, evidence and init-data
// binding succeed, token retrieval fails, and extending a measurement fails
// because the event log is not enabled.
func TestAttestationAgent(t *testing.T) {
	aa, err := New(nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if aa.GetTeeType() != attester.TeeSample {
		t.Errorf("tee type = %q, want sample", aa.GetTeeType())
	}

	// No token config for coco_as, and KBS is not implemented: both fail.
	if _, err := aa.GetToken("coco_as", nil); err == nil {
		t.Error("expected GetToken(coco_as) to fail without config")
	}
	if _, err := aa.GetToken("kbs", nil); err == nil {
		t.Error("expected GetToken(kbs) to fail")
	}

	if _, err := aa.GetEvidence(nil); err != nil {
		t.Errorf("GetEvidence: unexpected error %v", err)
	}

	if _, err := aa.BindInitData(nil); err != nil {
		t.Errorf("BindInitData: unexpected error %v", err)
	}

	// Event log not enabled -> extend must fail.
	if err := aa.ExtendRuntimeMeasurement("domain", "operation", "content", nil); err == nil {
		t.Error("expected ExtendRuntimeMeasurement to fail when event log disabled")
	}
}

func TestGetAdditionalEvidenceEmpty(t *testing.T) {
	aa, err := New(nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ev, err := aa.GetAdditionalEvidence(nil)
	if err != nil {
		t.Fatalf("GetAdditionalEvidence: %v", err)
	}
	if len(ev) != 0 {
		t.Errorf("expected empty additional evidence, got %q", string(ev))
	}
	if tees := aa.GetAdditionalTees(); len(tees) != 0 {
		t.Errorf("expected no additional tees, got %v", tees)
	}
}
