// Copyright (C) Hygon Info Technologies Ltd.
// Copyright (c) 2024 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0

// Package csv implements the Hygon CSV attester via /dev/csv-guest ioctls.
package csv

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"unsafe"

	"github.com/confidential-containers/guest-components/attestation-agent/attester-go/api"
	"github.com/confidential-containers/guest-components/attestation-agent/attester-go/internal/eventlog"
	"github.com/confidential-containers/guest-components/attestation-agent/attester-go/internal/ioctl"
	"github.com/confidential-containers/guest-components/attestation-agent/attester-go/internal/sm3"
	"github.com/confidential-containers/guest-components/attestation-agent/attester-go/internal/util"
)

const (
	guestDevice = "/dev/csv-guest"

	reportBufSize = 4096
	rtmrRegSize   = 32

	// V2 report layout offsets inside the 4096-byte report data.
	v2SignerOffset = 1168
	pekCertLen     = 2084
	snLen          = 64
	v2PekOffset    = v2SignerOffset // signer.pek_cert
	v2SnOffset     = v2SignerOffset + pekCertLen

	includeCertChainEnv = "CSV_INCLUDE_CERT_CHAIN_IN_ATTESTATION_REPORT"
	kdsURL              = "https://cert.hygon.cn/hsk_cek?snumber="

	hskCertLen = 832 // ca::Certificate serialized size
)

// CSV ioctl numbers (/dev/csv-guest).
var (
	cmdGetReport = ioctl.IOWR('D', 0x1, unsafe.Sizeof(reportRequest{}))
	cmdRtmrReq   = ioctl.IOWR('D', 0x2, unsafe.Sizeof(rtmrRequest{}))
)

// reportRequest mirrors GuestReportRequest (16 bytes).
type reportRequest struct {
	Addr uint64
	Len  uint32
	_    uint32
}

// rtmrRequest mirrors GuestRtmrRequest (24 bytes, packed).
type rtmrRequest struct {
	Buf         uint64
	Len         uint64
	SubcmdID    uint16
	Rsvd        uint16
	FwErrorCode uint32
}

const (
	rtmrRead   = 3
	rtmrExtend = 4
)

// ---- evidence JSON structs (byte-compatible with the Rust CsvEvidence) ----

// NumberBytes serializes like a Rust Vec<u8>: a JSON array of numbers.
type NumberBytes []byte

func (b NumberBytes) MarshalJSON() ([]byte, error) {
	buf := make([]byte, 0, len(b)*4+2)
	buf = append(buf, '[')
	for i, v := range b {
		if i > 0 {
			buf = append(buf, ',')
		}
		buf = strconv.AppendUint(buf, uint64(v), 10)
	}
	buf = append(buf, ']')
	return buf, nil
}

func (b *NumberBytes) UnmarshalJSON(data []byte) error {
	var nums []uint8
	if err := json.Unmarshal(data, &nums); err != nil {
		return err
	}
	*b = nums
	return nil
}

type Version struct {
	Major uint8 `json:"major"`
	Minor uint8 `json:"minor"`
}

type EccPubKey struct {
	G uint32   `json:"g"`
	X [72]byte `json:"x"`
	Y [72]byte `json:"y"`
}

type EcdsaSignature struct {
	R [72]byte `json:"r"`
	S [72]byte `json:"s"`
}

// ---- ca::Certificate ----

type CaData struct {
	Kid      [16]byte `json:"kid"`
	Sid      [16]byte `json:"sid"`
	Usage    uint32   `json:"usage"`
	Reserved [24]byte `json:"reserved"`
}

type CaPreamble struct {
	Ver  uint32 `json:"ver"`
	Data CaData `json:"data"`
}

type CaBody struct {
	Preamble CaPreamble `json:"preamble"`
	Pubkey   EccPubKey  `json:"pubkey"`
	UidSize  uint16     `json:"uid_size"`
	UserID   [254]byte  `json:"user_id"`
	Reserved [108]byte  `json:"reserved"`
}

type CaCertificate struct {
	Body      CaBody         `json:"body"`
	Signature EcdsaSignature `json:"signature"`
	Reserved  [112]byte      `json:"_reserved"`
}

// ---- csv::Certificate ----

type KeyPubKey struct {
	Usage uint32    `json:"usage"`
	Algo  uint32    `json:"algo"`
	Key   EccPubKey `json:"key"`
}

type Data struct {
	Firmware  Version   `json:"firmware"`
	Reserved1 uint16    `json:"reserved1"`
	Pubkey    KeyPubKey `json:"pubkey"`
	UidSize   uint16    `json:"uid_size"`
	UserID    [254]byte `json:"user_id"`
	Sid       [16]byte  `json:"sid"`
	Reserved2 [608]byte `json:"reserved2"`
}

type Body struct {
	Ver  uint32 `json:"ver"`
	Data Data   `json:"data"`
}

type Signatures struct {
	Usage     uint32         `json:"usage"`
	Algo      uint32         `json:"algo"`
	Signature EcdsaSignature `json:"signature"`
	Reserved  [368]byte      `json:"_reserved"`
}

type Certificate struct {
	Body Body          `json:"body"`
	Sigs [2]Signatures `json:"sigs"`
}

// ---- top-level ----

type HskCek struct {
	Hsk CaCertificate `json:"hsk"`
	Cek Certificate   `json:"cek"`
}

type CertificateChain struct {
	HskCek *HskCek     `json:"hsk_cek,omitempty"`
	Pek    Certificate `json:"pek"`
}

type AttestationReportWrapper struct {
	Magic [16]byte   `json:"magic"`
	Flags uint32     `json:"flags"`
	Data  [4096]byte `json:"data"`
}

type Evidence struct {
	AttestationReport AttestationReportWrapper `json:"attestation_report"`
	CertChain         CertificateChain         `json:"cert_chain"`
	SerialNumber      NumberBytes              `json:"serial_number"`
	CcEventlog        *string                  `json:"cc_eventlog"`
}

// Attester collects Hygon CSV evidence.
type Attester struct {
	api.Base
}

// New creates a CSV Attester.
func New() *Attester { return &Attester{} }

// DetectPlatform reports whether the guest is a CSV guest.
func DetectPlatform() bool {
	return util.FileExists(guestDevice)
}

func (a *Attester) GetEvidence(reportData []byte) (api.TeeEvidence, error) {
	if len(reportData) > 64 {
		return nil, errors.New("CSV attester: report data must be <= 64 bytes")
	}
	report, err := getReportExt(util.Pad(reportData, 64))
	if err != nil {
		return nil, err
	}

	// AttestationReportWrapper: raw 4096 report + V2 magic/flags.
	var wrapper AttestationReportWrapper
	copy(wrapper.Magic[:], []byte("ATTESTATION_EXT\x00"))
	wrapper.Flags = 1
	copy(wrapper.Data[:], report)

	// Extract PEK cert and serial number from the signer (V2 offsets).
	var pek Certificate
	if err := binary.Read(bytes.NewReader(report[v2PekOffset:v2PekOffset+pekCertLen]), binary.LittleEndian, &pek); err != nil {
		return nil, fmt.Errorf("CSV attester: parse pek cert: %w", err)
	}
	sn := make([]byte, snLen)
	copy(sn, report[v2SnOffset:v2SnOffset+snLen])

	chain := CertificateChain{Pek: pek}
	if os.Getenv(includeCertChainEnv) == "true" {
		hskCek, err := downloadHskCek(sn)
		if err != nil {
			return nil, err
		}
		chain.HskCek = hskCek
	}

	ccEventlog, err := eventlog.Read()
	if err != nil {
		return nil, err
	}

	ev := Evidence{
		AttestationReport: wrapper,
		CertChain:         chain,
		SerialNumber:      sn,
		CcEventlog:        ccEventlog,
	}
	return json.Marshal(ev)
}

// getReportExt issues CSV_GET_REPORT (V2 extended) and returns the raw
// 4096-byte report buffer.
func getReportExt(reportData []byte) ([]byte, error) {
	f, err := os.OpenFile(guestDevice, os.O_RDONLY, 0)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", guestDevice, err)
	}
	defer f.Close()

	buf := make([]byte, reportBufSize)
	// V2 ReportReqExt at head: data[64], mnonce[16], hash[32], magic[16], flags u32
	copy(buf[0:64], reportData)
	var mnonce [16]byte
	if _, err := rand.Read(mnonce[:]); err != nil {
		return nil, err
	}
	copy(buf[64:80], mnonce[:])
	h := sm3.Sum(append(append([]byte{}, reportData...), mnonce[:]...))
	copy(buf[80:112], h[:])
	copy(buf[112:128], []byte("ATTESTATION_EXT\x00"))
	binary.LittleEndian.PutUint32(buf[128:132], 1) // flags

	req := reportRequest{
		Addr: uint64(uintptr(unsafe.Pointer(&buf[0]))),
		Len:  reportBufSize,
	}
	if err := ioctl.Do(int(f.Fd()), cmdGetReport, unsafe.Pointer(&req)); err != nil {
		return nil, fmt.Errorf("CSV_GET_REPORT ioctl: %w", err)
	}
	return buf, nil
}

func (a *Attester) ExtendRuntimeMeasurement(eventDigest []byte, registerIndex uint64) error {
	if len(eventDigest) < rtmrRegSize {
		return fmt.Errorf("CSV attester: extend data must be >= %d bytes", rtmrRegSize)
	}
	ccmr := a.PcrToCcmr(registerIndex)

	// CsvGuestUserRtmrExtend: index u8, rsvd u8, data_len u16, data[32] (packed, 36B)
	sub := make([]byte, 36)
	sub[0] = uint8(ccmr)
	binary.LittleEndian.PutUint16(sub[2:4], rtmrRegSize)
	copy(sub[4:36], eventDigest[:rtmrRegSize])

	return rtmrIoctl(rtmrExtend, sub)
}

func (a *Attester) GetRuntimeMeasurement(pcrIndex uint64) ([]byte, error) {
	ccmr := a.PcrToCcmr(pcrIndex)
	bitmap := uint32(1) << ccmr

	// CsvGuestUserRtmrRead: bitmap u32, data[32*N]
	n := popcount(bitmap & 0x1F)
	sub := make([]byte, 4+rtmrRegSize*n)
	binary.LittleEndian.PutUint32(sub[0:4], bitmap)

	if err := rtmrIoctl(rtmrRead, sub); err != nil {
		return nil, err
	}
	// single bit -> the register is the first one in the output
	out := make([]byte, rtmrRegSize)
	copy(out, sub[4:4+rtmrRegSize])
	return out, nil
}

func rtmrIoctl(subcmd uint16, sub []byte) error {
	f, err := os.OpenFile(guestDevice, os.O_RDONLY, 0)
	if err != nil {
		return fmt.Errorf("open %s: %w", guestDevice, err)
	}
	defer f.Close()

	req := rtmrRequest{
		Buf:      uint64(uintptr(unsafe.Pointer(&sub[0]))),
		Len:      uint64(len(sub)),
		SubcmdID: subcmd,
	}
	if err := ioctl.Do(int(f.Fd()), cmdRtmrReq, unsafe.Pointer(&req)); err != nil {
		return fmt.Errorf("CSV_RTMR_REQ ioctl: %w", err)
	}
	if req.FwErrorCode != 0 {
		return fmt.Errorf("CSV_RTMR_REQ fw_error: 0x%x", req.FwErrorCode)
	}
	return nil
}

func (a *Attester) PcrToCcmr(pcrIndex uint64) uint64 {
	switch {
	case pcrIndex == 0:
		return 0
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

func (a *Attester) CcelHashAlgorithm() api.HashAlgorithm { return api.HashSm3 }

// downloadHskCek fetches the HSK (ca::Certificate) and CEK (csv::Certificate)
// chain from the Hygon KDS, keyed by the chip serial number.
func downloadHskCek(sn []byte) (*HskCek, error) {
	chipID := strings.TrimRight(string(sn), "\x00")
	resp, err := http.Get(kdsURL + chipID)
	if err != nil {
		return nil, fmt.Errorf("CSV attester: download HSK/CEK: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if len(body) < hskCertLen+pekCertLen {
		return nil, fmt.Errorf("CSV attester: KDS response too short: %d", len(body))
	}

	var hsk CaCertificate
	if err := binary.Read(bytes.NewReader(body[:hskCertLen]), binary.LittleEndian, &hsk); err != nil {
		return nil, fmt.Errorf("CSV attester: parse HSK: %w", err)
	}
	var cek Certificate
	if err := binary.Read(bytes.NewReader(body[hskCertLen:hskCertLen+pekCertLen]), binary.LittleEndian, &cek); err != nil {
		return nil, fmt.Errorf("CSV attester: parse CEK: %w", err)
	}
	return &HskCek{Hsk: hsk, Cek: cek}, nil
}

func popcount(x uint32) int {
	n := 0
	for x != 0 {
		n += int(x & 1)
		x >>= 1
	}
	return n
}
