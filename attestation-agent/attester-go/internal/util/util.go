// Copyright (c) 2024 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0

// Package util holds small helpers shared across the attester implementation.
package util

import "os"

// Pad copies input into a fixed-size buffer of length n, truncating if input is
// longer and zero-padding if shorter. Equivalent to the Rust utils::pad.
func Pad(input []byte, n int) []byte {
	out := make([]byte, n)
	if len(input) > n {
		copy(out, input[:n])
	} else {
		copy(out, input)
	}
	return out
}

// FileExists reports whether the given path exists.
func FileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}
