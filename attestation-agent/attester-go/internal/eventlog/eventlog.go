// Copyright (c) 2024 Microsoft Corporation
// Copyright (c) 2024 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0

// Package eventlog reads the confidential-computing event log (CCEL and/or
// AAEL), mirroring the Rust attester utils::read_eventlog.
package eventlog

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"os"
)

// elHeader is a fixed event log header prepended before an AAEL log when no
// CCEL is present. Copied verbatim from utils::EL_HEADER.
var elHeader = [73]byte{
	0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x29, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x0C, 0x00, 0x30, 0x00,
	0x12, 0x00, 0x20, 0x00, 0x0B, 0x00, 0x20, 0x00, 0x00,
}

// elEndFlag is appended after the event log. Copied from utils::EL_END_FLAG.
var elEndFlag = [8]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}

const (
	defaultAAELPath = "/run/attestation-agent/eventlog"
	ccelPath        = "/sys/firmware/acpi/tables/data/CCEL"
)

// trimCcel trims trailing zero padding from a raw CCEL blob, mirroring
// utils::trim_ccel.
func trimCcel(ccel []byte) ([]byte, error) {
	ccelLen := len(ccel)
	index := 4
	if ccelLen < index+4 {
		return nil, errors.New("invalid ccel: not enough length")
	}
	eventTypeNum := binary.LittleEndian.Uint32(ccel[index : index+4])
	index += 4
	index += 20

	// if it is EV_NO_ACTION
	if eventTypeNum == 0x3 {
		if ccelLen < index+4 {
			return nil, errors.New("invalid ccel: not enough length")
		}
		eventDataSize := binary.LittleEndian.Uint32(ccel[index : index+4])
		index += 4
		index += int(eventDataSize)
	}

	for {
		if ccelLen < index+8 {
			return nil, errors.New("invalid ccel: no end flag")
		}
		stopFlag := binary.LittleEndian.Uint64(ccel[index : index+8])
		if stopFlag == 0xFFFFFFFFFFFFFFFF || stopFlag == 0x0000000000000000 {
			return ccel[:index], nil
		}

		// skip target mr, event type
		index += 4 + 4
		if ccelLen < index+4 {
			return nil, errors.New("invalid ccel: no digest length")
		}
		digestsLength := binary.LittleEndian.Uint32(ccel[index : index+4])
		index += 4

		for i := uint32(0); i < digestsLength; i++ {
			if ccelLen < index+2 {
				return nil, errors.New("invalid ccel: no digest algorithm")
			}
			digestType := binary.LittleEndian.Uint16(ccel[index : index+2])
			index += 2
			var digestLen int
			switch digestType {
			case 0xb, 0x12:
				digestLen = 0x20
			case 0xc:
				digestLen = 0x30
			case 0xd:
				digestLen = 0x40
			default:
				return nil, errors.New("invalid ccel: unsupported digest algorithm")
			}
			index += digestLen
		}

		if ccelLen < index+4 {
			return nil, errors.New("invalid ccel: no event data size")
		}
		eventDataSize := binary.LittleEndian.Uint32(ccel[index : index+4])
		index += 4
		index += int(eventDataSize)
	}
}

// Read reads the CC event log (CCEL and/or AAEL) and returns it as a base64
// (standard) string, or nil if there is no event log.
func Read() (*string, error) {
	aaelPath := os.Getenv("AAEL_PATH")
	if aaelPath == "" {
		aaelPath = defaultAAELPath
	}

	var log []byte
	if _, err := os.Stat(ccelPath); err == nil {
		raw, err := os.ReadFile(ccelPath)
		if err != nil {
			return nil, err
		}
		trimmed, err := trimCcel(raw)
		if err != nil {
			return nil, err
		}
		log = trimmed
	}

	if _, err := os.Stat(aaelPath); err == nil {
		if len(log) == 0 {
			log = append(log, elHeader[:]...)
		}
		raw, err := os.ReadFile(aaelPath)
		if err != nil {
			return nil, err
		}
		log = append(log, raw...)
	}

	if len(log) == 0 {
		return nil, nil
	}

	log = append(log, elEndFlag[:]...)
	s := base64.StdEncoding.EncodeToString(log)
	return &s, nil
}
