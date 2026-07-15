// Copyright (c) 2022 IBM
// Copyright (c) 2024 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0

// Package snp implements the AMD SEV-SNP attester via /dev/sev-guest ioctls.
package snp

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"unsafe"

	"github.com/confidential-containers/guest-components/attestation-agent/attester-go/api"
	"github.com/confidential-containers/guest-components/attestation-agent/attester-go/internal/ioctl"
	"github.com/confidential-containers/guest-components/attestation-agent/attester-go/internal/util"
)

const (
	guestDevice = "/dev/sev-guest"

	reportOffset = 0x20  // report offset inside ReportRsp buffer
	reportSize   = 0x4A0 // 1184
	respBufSize  = 4000
	hostDataOff  = reportOffset + 192 // host_data absolute offset

	vmmErrInvalidCertPageLen = 0x1
	vmmErrRateLimit          = 0x2
)

// SNP ioctl numbers (/dev/sev-guest), arg = guestRequest (32 bytes).
var (
	cmdGetReport    = ioctl.IOWR('S', 0x0, unsafe.Sizeof(guestRequest{}))
	cmdGetExtReport = ioctl.IOWR('S', 0x2, unsafe.Sizeof(guestRequest{}))
)

// guestRequest mirrors the kernel snp_guest_request_ioctl (32 bytes).
type guestRequest struct {
	MessageVersion uint8
	_              [7]byte
	RequestData    uint64
	ResponseData   uint64
	FwErr          uint64
}

// reportRequest mirrors ReportReq (96 bytes).
type reportRequest struct {
	ReportData [64]byte
	Vmpl       uint32
	Reserved   [28]byte
}

// extReportRequest mirrors ExtReportReq (112 bytes).
type extReportRequest struct {
	Data         reportRequest
	CertsAddress uint64
	CertsLen     uint32
	_            [4]byte
}

// ---- evidence JSON structs (byte-compatible with the Rust SnpEvidence) ----

// ByteSlice serializes like a Rust Vec<u8>: a JSON array of numbers.
type ByteSlice []byte

func (b ByteSlice) MarshalJSON() ([]byte, error) {
	out := make([]byte, 0, len(b)*4+2)
	out = append(out, '[')
	for i, v := range b {
		if i > 0 {
			out = append(out, ',')
		}
		out = strconv.AppendUint(out, uint64(v), 10)
	}
	out = append(out, ']')
	return out, nil
}

func (b *ByteSlice) UnmarshalJSON(data []byte) error {
	var nums []uint8
	if err := json.Unmarshal(data, &nums); err != nil {
		return err
	}
	*b = nums
	return nil
}

// CertType serializes like the Rust CertType enum (external tagging): unit
// variants -> bare string; OTHER(uuid) -> {"OTHER":"<uuid>"}.
type CertType struct {
	Name      string
	OtherUUID string
}

func (c CertType) MarshalJSON() ([]byte, error) {
	if c.Name == "OTHER" {
		return json.Marshal(map[string]string{"OTHER": c.OtherUUID})
	}
	return json.Marshal(c.Name)
}

// TcbVersion mirrors sev::firmware::host::TcbVersion.
type TcbVersion struct {
	Bootloader uint8    `json:"bootloader"`
	Tee        uint8    `json:"tee"`
	Reserved   [4]uint8 `json:"_reserved"`
	Snp        uint8    `json:"snp"`
	Microcode  uint8    `json:"microcode"`
}

// Signature mirrors sev::certs::snp::ecdsa::Signature.
type Signature struct {
	R        [72]uint8  `json:"r"`
	S        [72]uint8  `json:"s"`
	Reserved [368]uint8 `json:"_reserved"`
}

// AttestationReport mirrors sev::firmware::guest::AttestationReport. Its field
// order and types also match the raw 1184-byte report, so it can be filled
// directly with binary.Read (little-endian).
type AttestationReport struct {
	Version         uint32     `json:"version"`
	GuestSvn        uint32     `json:"guest_svn"`
	Policy          uint64     `json:"policy"`
	FamilyID        [16]uint8  `json:"family_id"`
	ImageID         [16]uint8  `json:"image_id"`
	Vmpl            uint32     `json:"vmpl"`
	SigAlgo         uint32     `json:"sig_algo"`
	CurrentTcb      TcbVersion `json:"current_tcb"`
	PlatInfo        uint64     `json:"plat_info"`
	AuthorKeyEn     uint32     `json:"_author_key_en"`
	Reserved0       uint32     `json:"_reserved_0"`
	ReportData      [64]uint8  `json:"report_data"`
	Measurement     [48]uint8  `json:"measurement"`
	HostData        [32]uint8  `json:"host_data"`
	IDKeyDigest     [48]uint8  `json:"id_key_digest"`
	AuthorKeyDigest [48]uint8  `json:"author_key_digest"`
	ReportID        [32]uint8  `json:"report_id"`
	ReportIDMa      [32]uint8  `json:"report_id_ma"`
	ReportedTcb     TcbVersion `json:"reported_tcb"`
	Reserved1       [24]uint8  `json:"_reserved_1"`
	ChipID          [64]uint8  `json:"chip_id"`
	CommittedTcb    TcbVersion `json:"committed_tcb"`
	CurrentBuild    uint8      `json:"current_build"`
	CurrentMinor    uint8      `json:"current_minor"`
	CurrentMajor    uint8      `json:"current_major"`
	Reserved2       uint8      `json:"_reserved_2"`
	CommittedBuild  uint8      `json:"committed_build"`
	CommittedMinor  uint8      `json:"committed_minor"`
	CommittedMajor  uint8      `json:"committed_major"`
	Reserved3       uint8      `json:"_reserved_3"`
	LaunchTcb       TcbVersion `json:"launch_tcb"`
	Reserved4       [168]uint8 `json:"_reserved_4"`
	Signature       Signature  `json:"signature"`
}

// CertTableEntry mirrors sev::firmware::host::CertTableEntry.
type CertTableEntry struct {
	CertType CertType  `json:"cert_type"`
	Data     ByteSlice `json:"data"`
}

// Evidence mirrors the attester/verifier SnpEvidence.
type Evidence struct {
	AttestationReport AttestationReport `json:"attestation_report"`
	CertChain         []CertTableEntry  `json:"cert_chain"`
}

// Attester collects AMD SEV-SNP evidence.
type Attester struct {
	api.Base
}

// New creates an SNP Attester.
func New() *Attester { return &Attester{} }

// DetectPlatform reports whether the guest is an SEV-SNP guest.
func DetectPlatform() bool {
	return util.FileExists("/sys/devices/platform/sev-guest")
}

func (a *Attester) GetEvidence(reportData []byte) (api.TeeEvidence, error) {
	if len(reportData) > 64 {
		return nil, errors.New("SNP attester: report data must be <= 64 bytes")
	}
	report, certs, err := getExtendedReport(util.Pad(reportData, 64))
	if err != nil {
		return nil, err
	}

	var ar AttestationReport
	if err := binary.Read(bytes.NewReader(report), binary.LittleEndian, &ar); err != nil {
		return nil, fmt.Errorf("SNP attester: parse report: %w", err)
	}

	ev := Evidence{AttestationReport: ar, CertChain: certs}
	return json.Marshal(ev)
}

func (a *Attester) BindInitData(initDataDigest []byte) (api.InitDataResult, error) {
	resp, err := getReportRaw(make([]byte, 64))
	if err != nil {
		return api.InitDataUnsupported, err
	}
	if len(resp) < hostDataOff+32 {
		return api.InitDataUnsupported, errors.New("SNP attester: response too short")
	}
	hostData := resp[hostDataOff : hostDataOff+32]
	if !bytes.Equal(util.Pad(initDataDigest, 32), hostData) {
		return api.InitDataUnsupported, errors.New("SNP attester: HOSTDATA does not match")
	}
	return api.InitDataOk, nil
}

// getReportRaw performs SNP_GET_REPORT and returns the raw response buffer.
func getReportRaw(reportData []byte) ([]byte, error) {
	f, err := os.OpenFile(guestDevice, os.O_RDONLY, 0)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", guestDevice, err)
	}
	defer f.Close()

	resp := make([]byte, respBufSize)
	var req reportRequest
	copy(req.ReportData[:], util.Pad(reportData, 64))

	gr := guestRequest{
		MessageVersion: 1,
		RequestData:    uint64(uintptr(unsafe.Pointer(&req))),
		ResponseData:   uint64(uintptr(unsafe.Pointer(&resp[0]))),
	}
	if err := ioctl.Do(int(f.Fd()), cmdGetReport, unsafe.Pointer(&gr)); err != nil {
		return nil, fmt.Errorf("SNP_GET_REPORT ioctl: %w", err)
	}
	if uint32(gr.FwErr) != 0 {
		return nil, fmt.Errorf("SNP_GET_REPORT fw_error: 0x%x", uint32(gr.FwErr))
	}
	return resp, nil
}

// getExtendedReport performs SNP_GET_EXT_REPORT, retrying once to size the
// certificate buffer, and returns the raw report bytes and parsed cert chain.
func getExtendedReport(reportData []byte) ([]byte, []CertTableEntry, error) {
	f, err := os.OpenFile(guestDevice, os.O_RDONLY, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("open %s: %w", guestDevice, err)
	}
	defer f.Close()

	resp := make([]byte, respBufSize)
	ext := extReportRequest{CertsAddress: ^uint64(0), CertsLen: 0}
	copy(ext.Data.ReportData[:], reportData)

	call := func() (uint32, error) {
		gr := guestRequest{
			MessageVersion: 1,
			RequestData:    uint64(uintptr(unsafe.Pointer(&ext))),
			ResponseData:   uint64(uintptr(unsafe.Pointer(&resp[0]))),
		}
		if err := ioctl.Do(int(f.Fd()), cmdGetExtReport, unsafe.Pointer(&gr)); err != nil {
			return uint32(gr.FwErr >> 32), fmt.Errorf("SNP_GET_EXT_REPORT ioctl: %w", err)
		}
		return uint32(gr.FwErr >> 32), nil
	}

	var certsBuf []byte
	vmmErr, ioErr := call()
	if vmmErr == vmmErrInvalidCertPageLen {
		// firmware wrote the required length into CertsLen; retry.
		certsBuf = make([]byte, ext.CertsLen)
		if len(certsBuf) > 0 {
			ext.CertsAddress = uint64(uintptr(unsafe.Pointer(&certsBuf[0])))
		}
		vmmErr, ioErr = call()
	}
	if vmmErr == vmmErrRateLimit {
		return nil, nil, errors.New("SNP attester: rate limit, retry required")
	}
	if ioErr != nil && vmmErr != 0 {
		return nil, nil, ioErr
	}

	report := make([]byte, reportSize)
	copy(report, resp[reportOffset:reportOffset+reportSize])

	certs := parseCertTable(certsBuf)
	return report, certs, nil
}

// known AMD certificate GUIDs (standard big-endian string order).
var certGuids = map[string]string{
	"c0b406a4-a803-4952-9743-3fb6014cd0ae": "ARK",
	"4ab7b379-bbac-4fe4-a02f-05aef327c782": "ASK",
	"63da758d-e664-4564-adc5-f4b93be8accd": "VCEK",
	"a8074bc2-a25a-483e-aae6-39c045a0b8a1": "VLEK",
	"92f81bc3-5811-4d3d-97ff-d19f88dc67ea": "CRL",
}

// parseCertTable parses the GET_EXT_REPORT certificate table (24-byte entries
// terminated by an all-zero GUID). Returns nil when empty (-> JSON null).
func parseCertTable(buf []byte) []CertTableEntry {
	if len(buf) < 24 {
		return nil
	}
	var out []CertTableEntry
	for off := 0; off+24 <= len(buf); off += 24 {
		guid := buf[off : off+16]
		if isZero(guid) {
			break
		}
		coff := binary.LittleEndian.Uint32(buf[off+16 : off+20])
		clen := binary.LittleEndian.Uint32(buf[off+20 : off+24])
		if int(coff)+int(clen) > len(buf) {
			break
		}
		data := make([]byte, clen)
		copy(data, buf[coff:coff+clen])

		guidStr := formatGUID(guid)
		ct := CertType{}
		if name, ok := certGuids[guidStr]; ok {
			ct.Name = name
		} else {
			ct.Name = "OTHER"
			ct.OtherUUID = guidStr
		}
		out = append(out, CertTableEntry{CertType: ct, Data: data})
	}
	return out
}

func isZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

// formatGUID renders 16 bytes as a standard big-endian UUID string.
func formatGUID(b []byte) string {
	const hexd = "0123456789abcdef"
	var sb [36]byte
	j := 0
	for i := 0; i < 16; i++ {
		if i == 4 || i == 6 || i == 8 || i == 10 {
			sb[j] = '-'
			j++
		}
		sb[j] = hexd[b[i]>>4]
		sb[j+1] = hexd[b[i]&0xF]
		j += 2
	}
	return string(sb[:])
}
