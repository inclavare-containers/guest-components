// Copyright (c) 2022-2024 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0

// Package tdx implements the Intel TDX attester. All quote paths of the Rust
// attester are supported natively (no libtdx_attest): ConfigFS TSM, plus
// GET_REPORT0 + QGS over vsock or the GetQuote TDVMCALL ioctl.
package tdx

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/confidential-containers/guest-components/attestation-agent/attester-go/api"
	"github.com/confidential-containers/guest-components/attestation-agent/attester-go/internal/eventlog"
	"github.com/confidential-containers/guest-components/attestation-agent/attester-go/internal/ioctl"
	"github.com/confidential-containers/guest-components/attestation-agent/attester-go/internal/tsm"
	"github.com/confidential-containers/guest-components/attestation-agent/attester-go/internal/util"
)

const (
	rtmrSysfsPath = "/sys/devices/virtual/misc/tdx_guest/measurements"
	extendDataLen = 48
)

// evidence is the TDX evidence. Field order matches the Rust TdxEvidence.
type evidence struct {
	Quote       string           `json:"quote"`
	CcEventlog  *string          `json:"cc_eventlog"`
	GpuEvidence *GpuEvidenceList `json:"gpu_evidence"`
}

// Attester collects Intel TDX evidence.
type Attester struct {
	api.Base
}

// New creates a TDX Attester.
func New() *Attester { return &Attester{} }

// DetectPlatform reports whether the guest is a TDX guest.
func DetectPlatform() bool {
	return tsm.Available() || util.FileExists(guestDevice)
}

func (a *Attester) GetEvidence(reportData []byte) (api.TeeEvidence, error) {
	if len(reportData) > reportDataSize {
		return nil, fmt.Errorf("TDX attester: report data must be <= %d bytes", reportDataSize)
	}
	rd := util.Pad(reportData, reportDataSize)

	quoteBytes, err := a.getQuote(rd)
	if err != nil {
		return nil, err
	}

	ccEventlog, err := eventlog.Read()
	if err != nil {
		return nil, err
	}

	// GPU evidence is best-effort (nil when unsupported / not built with -tags gpu).
	gpuEvidence := collectGpuEvidence(rd)

	ev := evidence{
		Quote:       base64.StdEncoding.EncodeToString(quoteBytes),
		CcEventlog:  ccEventlog,
		GpuEvidence: gpuEvidence,
	}
	return json.Marshal(ev)
}

// getQuote produces a TD quote. Primary path is ConfigFS TSM (no external lib);
// when TSM is unavailable it falls back to the DCAP-equivalent path (GET_REPORT0
// ioctl + QGS message over vsock or the GetQuote TDVMCALL ioctl). This mirrors
// the Rust attester (TSM primary, tdx_att_get_quote fallback).
func (a *Attester) getQuote(reportData []byte) ([]byte, error) {
	if tsm.Available() {
		return tsm.GetReport(tsm.ProviderTdx, reportData, -1)
	}
	return getQuoteViaQgs(reportData)
}

// getQuoteViaQgs reimplements tdx_att_get_quote without libtdx_attest: it reads
// the TDREPORT via ioctl, builds a QGS request, and tries the vsock transport
// then the GetQuote TDVMCALL ioctl (transport order matches DCAP).
func getQuoteViaQgs(reportData []byte) ([]byte, error) {
	tdreport, err := getTdReport(reportData)
	if err != nil {
		return nil, err
	}
	qgsReq := buildGetQuoteReq(tdreport)

	// vsock first (only when /etc/tdx-attest.conf configures a port).
	resp, err := vsockGetQuote(qgsReq)
	if err == nil {
		return parseGetQuoteResp(resp)
	}
	if !errors.Is(err, errTransportUnsupported) {
		// A configured vsock that fails is a hard error, matching DCAP.
		return nil, err
	}

	// GetQuote TDVMCALL ioctl.
	resp, err = tdcallGetQuote(qgsReq)
	if err != nil {
		return nil, err
	}
	return parseGetQuoteResp(resp)
}

func (a *Attester) BindInitData(initDataDigest []byte) (api.InitDataResult, error) {
	report, err := getTdReport(make([]byte, reportDataSize))
	if err != nil {
		return api.InitDataUnsupported, err
	}
	mrConfig, err := mrConfigID(report)
	if err != nil {
		return api.InitDataUnsupported, err
	}
	if !bytes.Equal(util.Pad(initDataDigest, 48), mrConfig) {
		return api.InitDataUnsupported, errors.New("TDX attester: init data does not match")
	}
	return api.InitDataOk, nil
}

func (a *Attester) GetRuntimeMeasurement(pcrIndex uint64) ([]byte, error) {
	report, err := getTdReport(make([]byte, reportDataSize))
	if err != nil {
		return nil, err
	}
	ccmr := a.PcrToCcmr(pcrIndex)
	return getRtmr(report, int(ccmr)-1)
}

func (a *Attester) ExtendRuntimeMeasurement(eventDigest []byte, registerIndex uint64) error {
	if !util.FileExists(guestDevice) && !util.FileExists(rtmrSysfsPath) {
		return errors.New("TDX attester: runtime measurement extend is not available")
	}
	ccmr := a.PcrToCcmr(registerIndex)
	rtmrIndex := ccmr - 1
	extendData := util.Pad(eventDigest, extendDataLen)

	// sysfs first, ioctl fallback (matches DCAP tdx_att_extend).
	if err := extendRtmrViaSysfs(rtmrIndex, extendData); err != nil {
		log.Printf("TDX attester: sysfs RTMR extend failed (%v), trying ioctl", err)
		if err2 := extendRtmrViaIoctl(rtmrIndex, extendData); err2 != nil {
			return fmt.Errorf("TDX attester: extend RTMR failed: sysfs=%v ioctl=%v", err, err2)
		}
	}
	return nil
}

func extendRtmrViaSysfs(rtmrIndex uint64, extendData []byte) error {
	p := filepath.Join(rtmrSysfsPath, fmt.Sprintf("rtmr%d:sha384", rtmrIndex))
	return os.WriteFile(p, extendData, 0o644)
}

// extendRtmrReq mirrors `struct tdx_extend_rtmr_req { __u8 data[48]; __u8 index; }`.
type extendRtmrReq struct {
	Data  [extendDataLen]byte
	Index uint8
}

var cmdExtendRtmrVariants = []uintptr{
	ioctl.IOW('T', 3, unsafe.Sizeof(extendRtmrReq{})),
	ioctl.IOR('T', 3, unsafe.Sizeof(extendRtmrReq{})),
}

func extendRtmrViaIoctl(rtmrIndex uint64, extendData []byte) error {
	f, err := os.OpenFile(guestDevice, os.O_RDWR|os.O_SYNC, 0)
	if err != nil {
		return err
	}
	defer f.Close()

	var req extendRtmrReq
	copy(req.Data[:], extendData)
	req.Index = uint8(rtmrIndex)

	var ioErr error
	for _, r := range cmdExtendRtmrVariants {
		ioErr = ioctl.Do(int(f.Fd()), r, unsafe.Pointer(&req))
		if errors.Is(ioErr, unix.ENOTTY) {
			continue
		}
		return ioErr
	}
	return ioErr
}

// PcrToCcmr maps a PCR index to a TDX CC measurement register, per td-shim /
// UEFI CC spec.
func (a *Attester) PcrToCcmr(pcrIndex uint64) uint64 {
	switch {
	case pcrIndex == 1 || pcrIndex == 7:
		return 1
	case pcrIndex >= 2 && pcrIndex <= 6:
		return 2
	case pcrIndex >= 8 && pcrIndex <= 15:
		return 3
	default:
		return 4
	}
}

func (a *Attester) CcelHashAlgorithm() api.HashAlgorithm { return api.HashSha384 }
