// Copyright (c) 2024 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0

package tdx

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestQgsRoundtrip(t *testing.T) {
	tdreport := make([]byte, tdReportSize)
	tdreport[0] = 0x42
	req := buildGetQuoteReq(tdreport)

	if binary.LittleEndian.Uint16(req[0:]) != qgsMsgMajorVer {
		t.Error("bad major version")
	}
	if binary.LittleEndian.Uint32(req[4:]) != qgsGetQuoteReq {
		t.Error("bad msg type")
	}
	if int(binary.LittleEndian.Uint32(req[8:])) != len(req) {
		t.Error("bad size field")
	}
	if binary.LittleEndian.Uint32(req[16:]) != uint32(tdReportSize) {
		t.Error("bad report_size")
	}
	if req[24] != 0x42 {
		t.Error("report not embedded")
	}

	quote := []byte{0xde, 0xad, 0xbe, 0xef}
	resp := make([]byte, qgsHeaderLen+8+len(quote))
	binary.LittleEndian.PutUint16(resp[0:], qgsMsgMajorVer)
	binary.LittleEndian.PutUint16(resp[2:], qgsMsgMinorVer)
	binary.LittleEndian.PutUint32(resp[4:], qgsGetQuoteResp)
	binary.LittleEndian.PutUint32(resp[8:], uint32(len(resp)))
	binary.LittleEndian.PutUint32(resp[12:], 0)
	binary.LittleEndian.PutUint32(resp[16:], 0)
	binary.LittleEndian.PutUint32(resp[20:], uint32(len(quote)))
	copy(resp[24:], quote)

	got, err := parseGetQuoteResp(resp)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, quote) {
		t.Fatalf("parsed quote = %v, want %v", got, quote)
	}
}
