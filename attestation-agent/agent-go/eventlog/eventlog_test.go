// Copyright (c) 2024 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0

package eventlog

import (
	"bytes"
	"crypto/sha512"
	"os"
	"path/filepath"
	"testing"

	attester "github.com/confidential-containers/guest-components/attestation-agent/attester-go"
)

// fakeExtender is an in-memory attester used to exercise the event log without
// touching real hardware or the platform's fixed register/log paths. It
// measures with SHA-384 (48-byte register).
type fakeExtender struct {
	reg []byte
}

func newFakeExtender() *fakeExtender { return &fakeExtender{reg: make([]byte, 48)} }

func (f *fakeExtender) GetEvidence(_ []byte) (attester.TeeEvidence, error) { return nil, nil }

func (f *fakeExtender) ExtendRuntimeMeasurement(digest []byte, _ uint64) error {
	d := sha512.Sum384(append(append([]byte{}, f.reg...), digest...))
	f.reg = d[:]
	return nil
}

func (f *fakeExtender) BindInitData(_ []byte) (attester.InitDataResult, error) {
	return attester.InitDataUnsupported, nil
}

func (f *fakeExtender) GetRuntimeMeasurement(_ uint64) ([]byte, error) {
	return append([]byte{}, f.reg...), nil
}

func (f *fakeExtender) PcrToCcmr(_ uint64) uint64                 { return 1 }
func (f *fakeExtender) CcelHashAlgorithm() attester.HashAlgorithm { return attester.HashSha384 }

// captureWriter is an in-memory writer implementing the unexported writer
// interface.
type captureWriter struct {
	buf []byte
	pos uint64
}

func (w *captureWriter) write(data []byte) error {
	w.buf = append(w.buf, data...)
	w.pos += uint64(len(data))
	return nil
}
func (w *captureWriter) seek(pos uint64) error { w.pos = pos; return nil }
func (w *captureWriter) currentPos() uint64    { return w.pos }

// redirectPaths points the event log at a temporary directory for the duration
// of a test.
func redirectPaths(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	oldParent, oldLog, oldWal := parentDir, logPath, walCachePath
	parentDir = dir
	logPath = filepath.Join(dir, "eventlog")
	walCachePath = filepath.Join(dir, ".wal_event_entry")
	t.Cleanup(func() {
		parentDir, logPath, walCachePath = oldParent, oldLog, oldWal
	})
}

func TestExtendEntry(t *testing.T) {
	redirectPaths(t)
	fe := newFakeExtender()
	cw := &captureWriter{}
	el := &EventLog{writer: cw, extender: fe, alg: "sha384", pcr: 17}

	prevReg := append([]byte{}, fe.reg...)
	for _, content := range []string{"content1", "content2"} {
		event, err := NewEvent("domain", "operation", content)
		if err != nil {
			t.Fatal(err)
		}

		// Independently derive the expected entry bytes and register value.
		entry, digest, err := newTcg2Entry(event).withTargetMeasurementRegister(1).digest("sha384")
		if err != nil {
			t.Fatal(err)
		}
		wantReg := sha512.Sum384(append(append([]byte{}, prevReg...), digest...))
		wantBuf := entry.bytes()

		if err := el.ExtendEntry(event, 17); err != nil {
			t.Fatalf("ExtendEntry(%s): %v", content, err)
		}

		if !bytes.Equal(fe.reg, wantReg[:]) {
			t.Errorf("register mismatch after %s", content)
		}
		if !bytes.HasSuffix(cw.buf, wantBuf) {
			t.Errorf("writer did not receive expected entry bytes for %s", content)
		}
		if _, err := os.Stat(walCachePath); !os.IsNotExist(err) {
			t.Errorf("WAL cache not cleaned after %s (err=%v)", content, err)
		}
		prevReg = wantReg[:]
	}
}

// TestRecoverExtendsAndAppends simulates a crash after the WAL was written but
// before the register was extended and the entry appended: New must replay it.
func TestRecoverExtendsAndAppends(t *testing.T) {
	redirectPaths(t)
	fe := newFakeExtender()

	event, err := NewEvent("domain", "operation", "content")
	if err != nil {
		t.Fatal(err)
	}
	// Recovery re-derives the entry with the default target measurement register.
	entry, digest, err := newTcg2Entry(event).digest("sha384")
	if err != nil {
		t.Fatal(err)
	}
	expected := sha512.Sum384(append(append([]byte{}, fe.reg...), digest...))

	if err := writeWalCache(walCache{
		expectedPCR: expected[:],
		eventData:   event.String(),
		eventOffset: 0,
	}); err != nil {
		t.Fatal(err)
	}

	el, err := New(fe, 17)
	if err != nil {
		t.Fatalf("New (recovery): %v", err)
	}
	_ = el

	if !bytes.Equal(fe.reg, expected[:]) {
		t.Error("register was not extended during recovery")
	}
	if _, err := os.Stat(walCachePath); !os.IsNotExist(err) {
		t.Error("WAL cache not cleaned after recovery")
	}
	logged, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(logged, entry.bytes()) {
		t.Error("recovered entry not appended to the log file")
	}
}
