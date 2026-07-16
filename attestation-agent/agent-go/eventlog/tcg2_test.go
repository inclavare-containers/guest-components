// Copyright (c) 2025 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0

package eventlog

import (
	"encoding/hex"
	"testing"
)

// TestEventDigest reproduces the Rust attestation-agent tcg2 digest vectors,
// confirming the TCG2 event-data byte layout is compatible.
func TestEventDigest(t *testing.T) {
	cases := []struct {
		alg  string
		want string
	}{
		{"sha256", "46df8dacf00a07d34a83cdf56d7978697790787cf2ba1432ef7c38f22cd96351"},
		{"sha384", "dad5f0e226318ffa9839b75a472c6aa7fdb5834949d0a0a22990cf04d5692440fb00f3aa0609db7e49cd8d793f670d02"},
		{"sha512", "b708d222ca8bd44dfe6ba0c4ca2cbb72379276fba8091025217064be45a813e5d6124ccf073219edb617d1faf007d55061465bdf34b7437dbdc9a7405bd4e9c0"},
	}
	for _, c := range cases {
		event, err := NewEvent("domain", "operation", "content")
		if err != nil {
			t.Fatalf("NewEvent: %v", err)
		}
		_, digest, err := newTcg2Entry(event).digest(c.alg)
		if err != nil {
			t.Fatalf("digest(%s): %v", c.alg, err)
		}
		got := hex.EncodeToString(digest)
		if got != c.want {
			t.Errorf("digest(%s) = %s, want %s", c.alg, got, c.want)
		}
	}
}

func TestNewEventRejectsNewline(t *testing.T) {
	if _, err := NewEvent("d", "o", "has\nnewline"); err == nil {
		t.Fatal("expected error for content containing newline")
	}
	if _, err := NewEvent("d", "o", "ok"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseEventRoundTrip(t *testing.T) {
	e, err := NewEvent("domain", "operation", "some content with spaces")
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := parseEvent(e.String())
	if err != nil {
		t.Fatalf("parseEvent: %v", err)
	}
	if parsed.String() != e.String() {
		t.Errorf("round trip mismatch: %q != %q", parsed.String(), e.String())
	}
	if parsed.domain != "domain" || parsed.operation != "operation" || parsed.content != "some content with spaces" {
		t.Errorf("parsed fields wrong: %+v", parsed)
	}
}

func TestParseEventErrors(t *testing.T) {
	if _, err := parseEvent("nospace"); err == nil {
		t.Error("expected error for string without spaces")
	}
	if _, err := parseEvent("onlyone space"); err == nil {
		t.Error("expected error for string with a single space")
	}
}
