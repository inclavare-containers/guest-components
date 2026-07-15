// Copyright (c) 2024 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0

package sm3

import (
	"encoding/hex"
	"testing"
)

func TestSum(t *testing.T) {
	got := Sum([]byte("abc"))
	want := "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"
	if hex.EncodeToString(got[:]) != want {
		t.Fatalf("SM3(abc) = %x, want %s", got, want)
	}
}
