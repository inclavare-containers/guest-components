// Copyright (c) 2025 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0

package eventlog

import (
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/confidential-containers/guest-components/attestation-agent/agent-go/internal/hashalg"
)

// TCG algorithm identifiers (TCG Algorithm Registry), used in the digest list
// of a TCG2 event entry.
const (
	tcgAlgSha256 uint16 = 0xB
	tcgAlgSha384 uint16 = 0xC
	tcgAlgSha512 uint16 = 0xD
	tcgAlgSm3    uint16 = 0x12
)

// tcgAlgorithm maps a hash-algorithm identifier to its TCG registry code.
func tcgAlgorithm(alg string) (uint16, error) {
	switch alg {
	case hashalg.SHA256:
		return tcgAlgSha256, nil
	case hashalg.SHA384:
		return tcgAlgSha384, nil
	case hashalg.SHA512:
		return tcgAlgSha512, nil
	case hashalg.SM3:
		return tcgAlgSm3, nil
	default:
		return 0, fmt.Errorf("eventlog: unsupported hash algorithm %q", alg)
	}
}

// Tagged event type ID (EV_EVENT_TAG).
const evEventTagType uint32 = 0x6

// AAEL tagged event ID, ASCII of "AAEL".
const aaelTaggedEventID uint32 = 0x4141454c

// Event is a single AAEL log entry: a `domain operation content` triple. The
// content must not contain a newline.
type Event struct {
	domain    string
	operation string
	content   string
}

// NewEvent validates and builds an Event, mirroring Rust Event::new.
func NewEvent(domain, operation, content string) (Event, error) {
	if strings.ContainsRune(content, '\n') {
		return Event{}, fmt.Errorf("eventlog: content contains newline")
	}
	return Event{domain: domain, operation: operation, content: content}, nil
}

// parseEvent parses an Event from its `domain operation content` string form,
// mirroring the Rust TryFrom<&str> for Event.
func parseEvent(s string) (Event, error) {
	first := strings.IndexByte(s, ' ')
	if first < 0 {
		return Event{}, fmt.Errorf("eventlog: no space found in event string")
	}
	rel := strings.IndexByte(s[first+1:], ' ')
	if rel < 0 {
		return Event{}, fmt.Errorf("eventlog: no second space found in event string")
	}
	second := first + 1 + rel
	return NewEvent(s[:first], s[first+1:second], s[second+1:])
}

// String renders the AAEL plaintext form `domain operation content`.
func (e Event) String() string {
	return e.domain + " " + e.operation + " " + e.content
}

// taggedEventBytes serializes the AAEL tagged event: tagged_id(LE u32) ||
// size(LE u32) || plaintext.
func (e Event) taggedEventBytes() []byte {
	plaintext := []byte(e.String())
	buf := make([]byte, 0, 8+len(plaintext))
	buf = binary.LittleEndian.AppendUint32(buf, aaelTaggedEventID)
	buf = binary.LittleEndian.AppendUint32(buf, uint32(len(plaintext)))
	buf = append(buf, plaintext...)
	return buf
}

// tcg2Entry is a TCG2 event entry (event type EV_EVENT_TAG) wrapping an AAEL
// tagged event as its event-data section.
type tcg2Entry struct {
	targetMeasurementRegister uint32
	eventTypeNum              uint32
	digestCount               uint32
	digestAlg                 uint16
	digestValue               []byte
	eventData                 []byte
}

// newTcg2Entry builds a TCG2 entry from an Event, mirroring the Rust
// From<Event> for Tcg2EventEntry (default target measurement register 1, empty
// digest list).
func newTcg2Entry(e Event) tcg2Entry {
	return tcg2Entry{
		targetMeasurementRegister: 1,
		eventTypeNum:              evEventTagType,
		digestCount:               0,
		eventData:                 e.taggedEventBytes(),
	}
}

// withTargetMeasurementRegister sets the target measurement register.
func (t tcg2Entry) withTargetMeasurementRegister(reg uint32) tcg2Entry {
	t.targetMeasurementRegister = reg
	return t
}

// digest computes the digest of the event-data section under alg, populating
// the single-entry digest list, and returns the updated entry together with the
// raw digest (used to extend the measurement register).
func (t tcg2Entry) digest(alg string) (tcg2Entry, []byte, error) {
	code, err := tcgAlgorithm(alg)
	if err != nil {
		return tcg2Entry{}, nil, err
	}
	d, err := hashalg.Digest(alg, t.eventData)
	if err != nil {
		return tcg2Entry{}, nil, err
	}
	t.digestCount = 1
	t.digestAlg = code
	t.digestValue = d
	return t, d, nil
}

// bytes serializes the TCG2 event entry in little-endian wire form.
func (t tcg2Entry) bytes() []byte {
	buf := make([]byte, 0, 16+len(t.digestValue)+len(t.eventData))
	buf = binary.LittleEndian.AppendUint32(buf, t.targetMeasurementRegister)
	buf = binary.LittleEndian.AppendUint32(buf, t.eventTypeNum)
	buf = binary.LittleEndian.AppendUint32(buf, t.digestCount)
	if t.digestCount > 0 {
		buf = binary.LittleEndian.AppendUint16(buf, t.digestAlg)
		buf = append(buf, t.digestValue...)
	}
	buf = binary.LittleEndian.AppendUint32(buf, uint32(len(t.eventData)))
	buf = append(buf, t.eventData...)
	return buf
}
