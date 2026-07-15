// Copyright (c) 2024 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0

// Command evidence_getter is the Go counterpart of the Rust `evidence_getter`
// binary: it detects the TEE, collects evidence for a 64-byte report data and
// prints the evidence JSON to stdout.
//
// Usage:
//
//	evidence_getter stdio                # read 64 bytes of report data from stdin
//	evidence_getter commandline <data>   # use <data> (truncated/padded to 64B)
//	evidence_getter file <path>          # read report data from a file
//	evidence_getter detect               # just print the detected TEE type
//
// An optional -tee flag forces a specific attester (sample|tdx|snp|csv).
package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"

	attester "github.com/confidential-containers/guest-components/attestation-agent/attester-go"
)

func main() {
	teeFlag := flag.String("tee", "", "force TEE type (sample|tdx|snp|csv); default: auto-detect")
	flag.Parse()
	args := flag.Args()

	tee := attester.DetectTeeType()
	if *teeFlag != "" {
		tee = attester.Tee(*teeFlag)
	}

	if len(args) > 0 && args[0] == "detect" {
		fmt.Println(tee)
		return
	}

	// measurement <pcrIndex>: exercise the GET_REPORT0 / runtime-measurement path.
	if len(args) >= 2 && args[0] == "measurement" {
		att, err := attester.New(tee)
		if err != nil {
			fatal("create attester: %v", err)
		}
		idx, err := strconv.ParseUint(args[1], 10, 64)
		if err != nil {
			fatal("bad pcr index: %v", err)
		}
		m, err := att.GetRuntimeMeasurement(idx)
		if err != nil {
			fatal("get runtime measurement: %v", err)
		}
		fmt.Println(hex.EncodeToString(m))
		return
	}

	reportData := make([]byte, 64)
	if len(args) > 0 {
		switch args[0] {
		case "stdio":
			buf, err := io.ReadAll(os.Stdin)
			if err != nil {
				fatal("read stdin: %v", err)
			}
			copyReport(reportData, buf)
		case "commandline":
			if len(args) < 2 {
				fatal("commandline requires <data>")
			}
			copyReport(reportData, []byte(args[1]))
		case "file":
			if len(args) < 2 {
				fatal("file requires <path>")
			}
			buf, err := os.ReadFile(args[1])
			if err != nil {
				fatal("read file: %v", err)
			}
			copyReport(reportData, buf)
		default:
			fatal("unknown subcommand %q", args[0])
		}
	}

	att, err := attester.New(tee)
	if err != nil {
		fatal("create attester: %v", err)
	}
	evidence, err := att.GetEvidence(reportData)
	if err != nil {
		fatal("get evidence: %v", err)
	}
	fmt.Println(string(evidence))
}

func copyReport(dst, src []byte) {
	n := len(src)
	if n > 64 {
		n = 64
	}
	copy(dst[:n], src[:n])
}

func fatal(format string, a ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", a...)
	os.Exit(1)
}
