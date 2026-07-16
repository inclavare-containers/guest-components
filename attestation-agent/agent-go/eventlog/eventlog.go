// Copyright (c) 2024 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0

// Package eventlog is a pure-Go re-implementation of the attestation-agent
// crate `eventlog` module. It maintains the AA Event Log (AAEL): each entry is
// written as a TCG2 event and, atomically, extended into a TEE runtime
// measurement register through the attester. A write-ahead log (WAL) makes the
// "extend register + append log" pair crash-recoverable.
package eventlog

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/confidential-containers/guest-components/attestation-agent/agent-go/internal/hashalg"
	attester "github.com/confidential-containers/guest-components/attestation-agent/attester-go"
)

// Filesystem locations of the AA event log and its WAL cache.
const (
	// ParentDir is the directory holding the AA event log.
	ParentDir = "/run/attestation-agent"
	// Path is the AA event log file.
	Path = ParentDir + "/eventlog"
	// WalCachePath caches a pending entry before it is committed.
	WalCachePath = ParentDir + "/.wal_event_entry"
)

// Effective filesystem locations, defaulting to the exported constants. They
// are package variables (not consts) so tests can redirect the event log to a
// temporary directory.
var (
	parentDir    = ParentDir
	logPath      = Path
	walCachePath = WalCachePath
)

// writer abstracts the append-only backing store, matching the Rust Writer
// trait. It is unexported; production code uses fileWriter.
type writer interface {
	write(data []byte) error
	seek(pos uint64) error
	currentPos() uint64
}

type fileWriter struct {
	file *os.File
	pos  uint64
}

func (w *fileWriter) write(data []byte) error {
	n, err := w.file.Write(data)
	if err != nil {
		return fmt.Errorf("failed to write log: %w", err)
	}
	if err := w.file.Sync(); err != nil {
		return fmt.Errorf("failed to flush log to I/O media: %w", err)
	}
	w.pos += uint64(n)
	return nil
}

func (w *fileWriter) seek(pos uint64) error {
	if _, err := w.file.Seek(int64(pos), io.SeekStart); err != nil {
		return fmt.Errorf("failed to seek log: %w", err)
	}
	w.pos = pos
	return nil
}

func (w *fileWriter) currentPos() uint64 { return w.pos }

// walCache is the write-ahead log record.
type walCache struct {
	// expectedPCR is the target register value after the entry is committed.
	expectedPCR []byte
	// eventData is the AAEL plaintext of the pending entry.
	eventData string
	// eventOffset is the offset of the entry in the event-log file.
	eventOffset uint64
}

// EventLog maintains the AAEL and extends entries into a measurement register.
type EventLog struct {
	writer   writer
	extender attester.Attester
	alg      string
	pcr      uint64
}

// New opens (creating if necessary) the AA event log and returns an EventLog
// that extends into pcr, recovering from any WAL left by a previous crash.
func New(extender attester.Attester, pcr uint64) (*EventLog, error) {
	if err := os.MkdirAll(parentDir, 0o755); err != nil {
		return nil, fmt.Errorf("create eventlog parent dir: %w", err)
	}
	file, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, fmt.Errorf("open AAEL file: %w", err)
	}
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, fmt.Errorf("stat AAEL file: %w", err)
	}
	w := &fileWriter{file: file, pos: uint64(info.Size())}

	alg := string(extender.CcelHashAlgorithm())
	digestLen, err := hashalg.Len(alg)
	if err != nil {
		file.Close()
		return nil, err
	}

	el := &EventLog{writer: w, extender: extender, alg: alg, pcr: pcr}

	wal, err := readWalCache(digestLen)
	if err != nil {
		file.Close()
		return nil, fmt.Errorf("failed to read wal cache. This is a significant error caused by a previous crash. Please try delete %q and restart the attestation agent: %w", walCachePath, err)
	}
	if wal == nil {
		return el, nil
	}

	if err := el.recover(wal); err != nil {
		file.Close()
		return nil, err
	}
	return el, nil
}

// recover replays a pending WAL record after a crash: it re-extends the
// register if that step did not complete, then re-appends the log entry.
func (el *EventLog) recover(wal *walCache) error {
	currentPCR, err := el.extender.GetRuntimeMeasurement(el.pcr)
	if err != nil {
		return fmt.Errorf("get runtime measurement: %w", err)
	}

	event, err := parseEvent(wal.eventData)
	if err != nil {
		return err
	}
	entry, eventDigest, err := newTcg2Entry(event).digest(el.alg)
	if err != nil {
		return err
	}
	entryBytes := entry.bytes()

	// If the register has not been extended yet, extend it now.
	if !bytes.Equal(currentPCR, wal.expectedPCR) {
		status := append(append([]byte{}, currentPCR...), eventDigest...)
		updated, err := hashalg.Digest(el.alg, status)
		if err != nil {
			return err
		}
		if !bytes.Equal(updated, wal.expectedPCR) {
			return fmt.Errorf("fatal error when recovering. The eventlog file %s is probably corrupted, or other process has extended the target PCR %d", logPath, el.pcr)
		}
		if err := el.extender.ExtendRuntimeMeasurement(eventDigest, el.pcr); err != nil {
			return err
		}
	}

	if err := el.writer.seek(wal.eventOffset); err != nil {
		return err
	}
	if err := el.writer.write(entryBytes); err != nil {
		return err
	}
	return cleanWalCache()
}

// ExtendEntry atomically extends the register with event and appends it to the
// AAEL. The ordering (WAL write, extend register, append log, clean WAL) makes
// the pair recoverable after a crash at any point.
func (el *EventLog) ExtendEntry(event Event, pcr uint64) error {
	aaelEventData := event.String()
	rtmr := el.extender.PcrToCcmr(el.pcr)
	entry, eventDigest, err := newTcg2Entry(event).
		withTargetMeasurementRegister(uint32(rtmr)).
		digest(el.alg)
	if err != nil {
		return err
	}
	entryBytes := entry.bytes()

	currentPCR, err := el.extender.GetRuntimeMeasurement(pcr)
	if err != nil {
		return err
	}
	status := append(append([]byte{}, currentPCR...), eventDigest...)
	expectedPCR, err := hashalg.Digest(el.alg, status)
	if err != nil {
		return err
	}

	if err := writeWalCache(walCache{
		expectedPCR: expectedPCR,
		eventData:   aaelEventData,
		eventOffset: el.writer.currentPos(),
	}); err != nil {
		return fmt.Errorf("write wal cache file failed: %w", err)
	}

	if err := el.extender.ExtendRuntimeMeasurement(eventDigest, pcr); err != nil {
		return err
	}
	if err := el.writer.write(entryBytes); err != nil {
		return fmt.Errorf("write log entry: %w", err)
	}
	if err := cleanWalCache(); err != nil {
		return fmt.Errorf("remove wal cache file failed: %w", err)
	}
	return nil
}

// writeWalCache persists a pending record before the register is extended.
//
// The record layout is event_offset(u64) || expected_pcr || event_data. We use
// little-endian for the offset consistently on both the write and read paths
// (the upstream Rust writes big-endian but reads little-endian; the WAL file is
// process-local and never shared across implementations, so a self-consistent
// little-endian encoding is correct here).
func writeWalCache(w walCache) error {
	file, err := os.Create(walCachePath)
	if err != nil {
		return err
	}
	defer file.Close()

	var offset [8]byte
	binary.LittleEndian.PutUint64(offset[:], w.eventOffset)
	if _, err := file.Write(offset[:]); err != nil {
		return err
	}
	if _, err := file.Write(w.expectedPCR); err != nil {
		return err
	}
	if _, err := file.Write([]byte(w.eventData)); err != nil {
		return err
	}
	return file.Sync()
}

// cleanWalCache removes the WAL cache file.
func cleanWalCache() error {
	return os.Remove(walCachePath)
}

// readWalCache reads the WAL cache file, or returns (nil, nil) if none exists.
func readWalCache(digestLen int) (*walCache, error) {
	data, err := os.ReadFile(walCachePath)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if len(data) < 8+digestLen {
		return nil, fmt.Errorf("wal cache too short: %d bytes", len(data))
	}
	offset := binary.LittleEndian.Uint64(data[:8])
	expectedPCR := append([]byte{}, data[8:8+digestLen]...)
	eventData := string(data[8+digestLen:])
	return &walCache{
		expectedPCR: expectedPCR,
		eventData:   eventData,
		eventOffset: offset,
	}, nil
}
