// Copyright (c) 2024 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0

package tdx

import (
	"fmt"
	"os"
	"unsafe"

	"github.com/confidential-containers/guest-components/attestation-agent/attester-go/internal/ioctl"
	"github.com/confidential-containers/guest-components/attestation-agent/attester-go/internal/util"
)

const (
	guestDevice = "/dev/tdx_guest"

	reportDataSize = 64
	tdReportSize   = 1024

	// Byte offsets into the 1024-byte TDREPORT (see attester tdx/report.rs).
	offsetMrConfigID = 576 // TdInfo.mrconfigid [48]
	lenMrConfigID    = 48
	offsetRtmr       = 720 // TdInfo.rtmr [24]u64
	rtmrEntryLen     = 48  // 6 * u64
)

// reportReq mirrors `struct tdx_report_req` used by TDX_CMD_GET_REPORT0.
type reportReq struct {
	ReportData [reportDataSize]byte
	TdReport   [tdReportSize]byte
}

var cmdGetReport0 = ioctl.IOWR('T', 1, unsafe.Sizeof(reportReq{}))

// getTdReport issues TDX_CMD_GET_REPORT0 to obtain the raw 1024-byte TDREPORT
// bound to reportData (64 bytes).
func getTdReport(reportData []byte) ([]byte, error) {
	f, err := os.OpenFile(guestDevice, os.O_RDWR|os.O_SYNC, 0)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", guestDevice, err)
	}
	defer f.Close()

	var req reportReq
	copy(req.ReportData[:], util.Pad(reportData, reportDataSize))

	if err := ioctl.Do(int(f.Fd()), cmdGetReport0, unsafe.Pointer(&req)); err != nil {
		return nil, fmt.Errorf("TDX_CMD_GET_REPORT0 ioctl: %w", err)
	}
	out := make([]byte, tdReportSize)
	copy(out, req.TdReport[:])
	return out, nil
}

// mrConfigID returns the 48-byte MRCONFIGID from a raw TDREPORT.
func mrConfigID(report []byte) ([]byte, error) {
	if len(report) < offsetMrConfigID+lenMrConfigID {
		return nil, fmt.Errorf("tdreport too short: %d", len(report))
	}
	return report[offsetMrConfigID : offsetMrConfigID+lenMrConfigID], nil
}

// getRtmr returns the 48-byte RTMR value at the given index (0..3) from a raw
// TDREPORT. Since the register is stored as little-endian u64s, the raw bytes
// are already the desired output (matches TdReport::get_rtmr).
func getRtmr(report []byte, rtmrIndex int) ([]byte, error) {
	start := offsetRtmr + rtmrIndex*rtmrEntryLen
	if rtmrIndex < 0 || len(report) < start+rtmrEntryLen {
		return nil, fmt.Errorf("tdreport too short for rtmr %d", rtmrIndex)
	}
	out := make([]byte, rtmrEntryLen)
	copy(out, report[start:start+rtmrEntryLen])
	return out, nil
}
