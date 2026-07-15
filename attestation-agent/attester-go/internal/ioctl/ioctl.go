// Copyright (c) 2024 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0

// Package ioctl provides the Linux _IOC request-number encoding and a small
// ioctl syscall wrapper.
package ioctl

import (
	"unsafe"

	"golang.org/x/sys/unix"
)

// Linux ioctl _IOC encoding (asm-generic, valid on x86_64/aarch64).
const (
	nrBits   = 8
	typeBits = 8
	sizeBits = 14

	nrShift   = 0
	typeShift = nrShift + nrBits
	sizeShift = typeShift + typeBits
	dirShift  = sizeShift + sizeBits

	dirNone  = 0
	dirWrite = 1
	dirRead  = 2
)

func code(dir, typ, nr, size uintptr) uintptr {
	return (dir << dirShift) | (typ << typeShift) | (nr << nrShift) | (size << sizeShift)
}

// IOW builds a _IOW(type, nr, size) request number.
func IOW(typ, nr, size uintptr) uintptr { return code(dirWrite, typ, nr, size) }

// IOR builds a _IOR(type, nr, size) request number.
func IOR(typ, nr, size uintptr) uintptr { return code(dirRead, typ, nr, size) }

// IOWR builds a _IOWR(type, nr, size) request number.
func IOWR(typ, nr, size uintptr) uintptr { return code(dirWrite|dirRead, typ, nr, size) }

// Do issues an ioctl on fd with the given request and a pointer argument.
func Do(fd int, request uintptr, arg unsafe.Pointer) error {
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), request, uintptr(arg))
	if errno != 0 {
		return errno
	}
	return nil
}
