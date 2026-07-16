// Copyright (c) 2025 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0

package initdata

import (
	"bytes"
	"crypto/sha512"
	"testing"
)

func TestParseAndGetDigest(t *testing.T) {
	const doc = `version = "0.1.0"
algorithm = "sha384"

[data]
"key1" = "value1"
"key2" = "value2"
`
	initdata, digest, err := ParseAndGetDigest(doc)
	if err != nil {
		t.Fatalf("ParseAndGetDigest: %v", err)
	}
	if initdata.Version != "0.1.0" {
		t.Errorf("version = %q", initdata.Version)
	}
	if initdata.Algorithm != "sha384" {
		t.Errorf("algorithm = %q", initdata.Algorithm)
	}
	if initdata.Data["key1"] != "value1" || initdata.Data["key2"] != "value2" {
		t.Errorf("data = %+v", initdata.Data)
	}

	want := sha512.Sum384([]byte(doc))
	if !bytes.Equal(digest, want[:]) {
		t.Errorf("digest mismatch: got %x want %x", digest, want[:])
	}
}

func TestParseAndGetDigestUnsupportedAlg(t *testing.T) {
	const doc = `version = "0.1.0"
algorithm = "md5"

[data]
`
	if _, _, err := ParseAndGetDigest(doc); err == nil {
		t.Error("expected error for unsupported algorithm")
	}
}
