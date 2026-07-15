// Copyright (c) 2024 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0

package attester

import "testing"

func TestNewAndDetect(t *testing.T) {
	for _, tee := range []Tee{TeeSample, TeeTdx, TeeSnp, TeeCsv} {
		if _, err := New(tee); err != nil {
			t.Errorf("New(%s) error: %v", tee, err)
		}
	}
	if _, err := New("bogus"); err == nil {
		t.Error("New(bogus) should fail")
	}
	_ = DetectTeeType() // host-dependent; just ensure it runs
}
