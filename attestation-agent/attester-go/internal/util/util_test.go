// Copyright (c) 2024 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0

package util

import (
	"bytes"
	"testing"
)

func TestPad(t *testing.T) {
	if got := Pad([]byte{1, 2, 3}, 5); !bytes.Equal(got, []byte{1, 2, 3, 0, 0}) {
		t.Fatalf("pad short = %v", got)
	}
	if got := Pad([]byte{1, 2, 3, 4, 5, 6}, 4); !bytes.Equal(got, []byte{1, 2, 3, 4}) {
		t.Fatalf("pad long = %v", got)
	}
}
