// Copyright (c) 2024 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0

package tdx

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"regexp"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/confidential-containers/guest-components/attestation-agent/attester-go/internal/ioctl"
)

// QGS message / transport constants, from Intel DCAP (tdx_attest.c, qgs_msg_lib).
const (
	qgsMsgMajorVer = 1
	qgsMsgMinorVer = 1

	qgsGetQuoteReq  = 0 // qgs_msg_type_t::GET_QUOTE_REQ
	qgsGetQuoteResp = 1 // qgs_msg_type_t::GET_QUOTE_RESP

	qgsHeaderLen = 16 // qgs_msg_header_t
	blobHeader   = 4  // big-endian length prefix (HEADER_SIZE)
	reqBufSize   = 4 * 4 * 1024

	tdxAttestConf = "/etc/tdx-attest.conf"

	getQuoteInFlight           = 0xffffffffffffffff
	getQuoteServiceUnavailable = 0x8000000000000001
)

// errTransportUnsupported means this transport is not usable in the current
// environment; the caller should try the next one.
var errTransportUnsupported = errors.New("tdx: quote transport not supported")

// buildGetQuoteReq serializes a QGS GET_QUOTE_REQ carrying the whole 1024-byte
// TDREPORT (id list empty). Mirrors qgs_msg_gen_get_quote_req.
func buildGetQuoteReq(tdreport []byte) []byte {
	reportSize := uint32(len(tdreport))
	msgSize := qgsHeaderLen + 4 + 4 + int(reportSize)
	msg := make([]byte, msgSize)
	// qgs_msg_header_t (little-endian native fields).
	binary.LittleEndian.PutUint16(msg[0:], qgsMsgMajorVer)
	binary.LittleEndian.PutUint16(msg[2:], qgsMsgMinorVer)
	binary.LittleEndian.PutUint32(msg[4:], qgsGetQuoteReq)
	binary.LittleEndian.PutUint32(msg[8:], uint32(msgSize))
	binary.LittleEndian.PutUint32(msg[12:], 0) // error_code
	// body
	binary.LittleEndian.PutUint32(msg[16:], reportSize)
	binary.LittleEndian.PutUint32(msg[20:], 0) // id_list_size
	copy(msg[24:], tdreport)
	return msg
}

// parseGetQuoteResp extracts the quote from a QGS GET_QUOTE_RESP message.
// Mirrors qgs_msg_inflate_get_quote_resp + extract_quote_from_blob_payload.
func parseGetQuoteResp(msg []byte) ([]byte, error) {
	if len(msg) < qgsHeaderLen+8 {
		return nil, fmt.Errorf("tdx: qgs resp too short: %d", len(msg))
	}
	major := binary.LittleEndian.Uint16(msg[0:])
	typ := binary.LittleEndian.Uint32(msg[4:])
	size := binary.LittleEndian.Uint32(msg[8:])
	errCode := binary.LittleEndian.Uint32(msg[12:])
	if major != qgsMsgMajorVer {
		return nil, fmt.Errorf("tdx: qgs resp bad version: %d", major)
	}
	if typ != qgsGetQuoteResp {
		return nil, fmt.Errorf("tdx: qgs resp bad type: %d", typ)
	}
	if errCode != 0 {
		return nil, fmt.Errorf("tdx: qgs resp error_code: 0x%x", errCode)
	}
	if int(size) > len(msg) {
		return nil, fmt.Errorf("tdx: qgs resp size %d > buffer %d", size, len(msg))
	}
	selectedIDSize := binary.LittleEndian.Uint32(msg[16:])
	quoteSize := binary.LittleEndian.Uint32(msg[20:])
	start := qgsHeaderLen + 8 + int(selectedIDSize)
	if start+int(quoteSize) > len(msg) {
		return nil, fmt.Errorf("tdx: qgs resp quote out of range")
	}
	quote := make([]byte, quoteSize)
	copy(quote, msg[start:start+int(quoteSize)])
	return quote, nil
}

// getVsockPort parses `port = N` from /etc/tdx-attest.conf, returning
// unsupported when absent.
var vsockPortRe = regexp.MustCompile(`(?m)^\s*port\s*=\s*([0-9]{1,10})`)

func getVsockPort() (uint32, error) {
	data, err := os.ReadFile(tdxAttestConf)
	if err != nil {
		return 0, errTransportUnsupported
	}
	m := vsockPortRe.FindSubmatch(data)
	if m == nil {
		return 0, errTransportUnsupported
	}
	var port uint64
	for _, c := range m[1] {
		port = port*10 + uint64(c-'0')
	}
	if port > 0xFFFF {
		return 0, errTransportUnsupported
	}
	return uint32(port), nil
}

// vsockGetQuote sends the QGS request over vsock to the host QGS and returns the
// raw response QGS message. Mirrors vsock_get_quote_payload.
func vsockGetQuote(qgsMsg []byte) ([]byte, error) {
	port, err := getVsockPort()
	if err != nil {
		return nil, err
	}

	fd, err := unix.Socket(unix.AF_VSOCK, unix.SOCK_STREAM, 0)
	if err != nil {
		return nil, fmt.Errorf("tdx: vsock socket: %w", err)
	}
	defer unix.Close(fd)

	sa := &unix.SockaddrVM{CID: unix.VMADDR_CID_HOST, Port: port}
	if err := unix.Connect(fd, sa); err != nil {
		return nil, fmt.Errorf("tdx: vsock connect: %w", err)
	}

	// payload = [4B big-endian msg_size][qgs_msg]
	payload := make([]byte, blobHeader+len(qgsMsg))
	binary.BigEndian.PutUint32(payload[:blobHeader], uint32(len(qgsMsg)))
	copy(payload[blobHeader:], qgsMsg)
	if err := writeAll(fd, payload); err != nil {
		return nil, fmt.Errorf("tdx: vsock send: %w", err)
	}

	// read 4-byte big-endian body size, then body
	hdr := make([]byte, blobHeader)
	if err := readFull(fd, hdr); err != nil {
		return nil, fmt.Errorf("tdx: vsock recv header: %w", err)
	}
	bodySize := binary.BigEndian.Uint32(hdr)
	if int(bodySize) > reqBufSize {
		return nil, fmt.Errorf("tdx: vsock body too big: %d", bodySize)
	}
	body := make([]byte, bodySize)
	if err := readFull(fd, body); err != nil {
		return nil, fmt.Errorf("tdx: vsock recv body: %w", err)
	}
	return body, nil
}

func writeAll(fd int, b []byte) error {
	for len(b) > 0 {
		n, err := unix.Write(fd, b)
		if err != nil {
			return err
		}
		b = b[n:]
	}
	return nil
}

func readFull(fd int, b []byte) error {
	for len(b) > 0 {
		n, err := unix.Read(fd, b)
		if err != nil {
			return err
		}
		if n == 0 {
			return errors.New("unexpected EOF")
		}
		b = b[n:]
	}
	return nil
}

// quoteReq mirrors `struct tdx_quote_req { __u64 buf; __u64 len; }`.
type quoteReq struct {
	Buf uint64
	Len uint64
}

// TDX_CMD_GET_QUOTE ioctl number encoding differs between kernel driver
// versions (upstream vs. backports use different _IOC direction bits). Try each
// until one is accepted (i.e. not ENOTTY).
var cmdGetQuoteVariants = []uintptr{
	ioctl.IOR('T', 4, unsafe.Sizeof(quoteReq{})),
	ioctl.IOWR('T', 4, unsafe.Sizeof(quoteReq{})),
	ioctl.IOW('T', 4, unsafe.Sizeof(quoteReq{})),
}

// tdcallGetQuote asks the kernel (GetQuote TDVMCALL, TDX_CMD_GET_QUOTE ioctl) to
// forward the QGS request to the host and returns the response QGS message.
// Mirrors tdcall_get_quote_payload.
func tdcallGetQuote(qgsMsg []byte) ([]byte, error) {
	f, err := os.OpenFile(guestDevice, os.O_RDWR|os.O_SYNC, 0)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", guestDevice, err)
	}
	defer f.Close()

	// blob layout: version u64 | status u64 | in_len u32 | out_len u32 |
	//              [4B BE msg_size][qgs_msg]
	blob := make([]byte, reqBufSize)
	const dataOff = 24
	inLen := blobHeader + len(qgsMsg)
	if dataOff+inLen > reqBufSize {
		return nil, fmt.Errorf("tdx: request too big for blob")
	}
	binary.LittleEndian.PutUint64(blob[0:], 1) // version
	binary.LittleEndian.PutUint64(blob[8:], 0) // status
	binary.LittleEndian.PutUint32(blob[16:], uint32(inLen))
	binary.LittleEndian.PutUint32(blob[20:], 0) // out_len
	binary.BigEndian.PutUint32(blob[dataOff:], uint32(len(qgsMsg)))
	copy(blob[dataOff+blobHeader:], qgsMsg)

	arg := quoteReq{
		Buf: uint64(uintptr(unsafe.Pointer(&blob[0]))),
		Len: reqBufSize,
	}

	var ioErr error
	accepted := false
	for _, req := range cmdGetQuoteVariants {
		ioErr = ioctl.Do(int(f.Fd()), req, unsafe.Pointer(&arg))
		if errors.Is(ioErr, unix.ENOTTY) {
			continue // wrong ioctl number for this kernel, try next encoding
		}
		accepted = true
		break
	}
	if !accepted {
		return nil, fmt.Errorf("tdx: TDX_CMD_GET_QUOTE not supported by kernel: %w", ioErr)
	}
	if ioErr != nil {
		return nil, fmt.Errorf("tdx: TDX_CMD_GET_QUOTE ioctl: %w", ioErr)
	}

	status := binary.LittleEndian.Uint64(blob[8:])
	outLen := binary.LittleEndian.Uint32(blob[20:])
	if status != 0 || outLen <= blobHeader {
		switch status {
		case getQuoteInFlight:
			return nil, errors.New("tdx: get quote in flight")
		case getQuoteServiceUnavailable:
			return nil, errTransportUnsupported
		default:
			return nil, fmt.Errorf("tdx: get quote status=0x%x", status)
		}
	}

	bodySize := binary.BigEndian.Uint32(blob[dataOff:])
	if bodySize != outLen-blobHeader {
		return nil, fmt.Errorf("tdx: body size mismatch: %d vs %d", bodySize, outLen-blobHeader)
	}
	body := make([]byte, bodySize)
	copy(body, blob[dataOff+blobHeader:dataOff+blobHeader+int(bodySize)])
	return body, nil
}
