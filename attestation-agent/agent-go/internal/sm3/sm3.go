// Copyright (c) 2024 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0

// Package sm3 implements the SM3 (GB/T 32905-2016) hash, so the event log has
// no external crypto dependency when a platform (e.g. Hygon CSV) measures with
// SM3. It is a verbatim copy of the attester-go internal/sm3 implementation;
// Go's internal/ visibility rule prevents importing it across modules.
package sm3

import "encoding/binary"

// Sum computes the SM3 256-bit digest of data.
func Sum(data []byte) [32]byte {
	iv := [8]uint32{
		0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600,
		0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e,
	}

	// padding
	msgLen := uint64(len(data)) * 8
	msg := make([]byte, len(data))
	copy(msg, data)
	msg = append(msg, 0x80)
	for len(msg)%64 != 56 {
		msg = append(msg, 0x00)
	}
	var lenBuf [8]byte
	binary.BigEndian.PutUint64(lenBuf[:], msgLen)
	msg = append(msg, lenBuf[:]...)

	ff0 := func(x, y, z uint32) uint32 { return x ^ y ^ z }
	ff1 := func(x, y, z uint32) uint32 { return (x & y) | (x & z) | (y & z) }
	gg0 := func(x, y, z uint32) uint32 { return x ^ y ^ z }
	gg1 := func(x, y, z uint32) uint32 { return (x & y) | (^x & z) }
	rotl := func(x uint32, n uint) uint32 { return (x << n) | (x >> (32 - n)) }
	p0 := func(x uint32) uint32 { return x ^ rotl(x, 9) ^ rotl(x, 17) }
	p1 := func(x uint32) uint32 { return x ^ rotl(x, 15) ^ rotl(x, 23) }

	v := iv
	for b := 0; b < len(msg); b += 64 {
		block := msg[b : b+64]
		var w [68]uint32
		for i := 0; i < 16; i++ {
			w[i] = binary.BigEndian.Uint32(block[i*4:])
		}
		for i := 16; i < 68; i++ {
			w[i] = p1(w[i-16]^w[i-9]^rotl(w[i-3], 15)) ^ rotl(w[i-13], 7) ^ w[i-6]
		}
		var w1 [64]uint32
		for i := 0; i < 64; i++ {
			w1[i] = w[i] ^ w[i+4]
		}

		a, bb, c, d := v[0], v[1], v[2], v[3]
		e, f, g, h := v[4], v[5], v[6], v[7]
		for j := 0; j < 64; j++ {
			var tj uint32
			if j < 16 {
				tj = 0x79cc4519
			} else {
				tj = 0x7a879d8a
			}
			ss1 := rotl(rotl(a, 12)+e+rotl(tj, uint(j)%32), 7)
			ss2 := ss1 ^ rotl(a, 12)
			var tt1, tt2 uint32
			if j < 16 {
				tt1 = ff0(a, bb, c) + d + ss2 + w1[j]
				tt2 = gg0(e, f, g) + h + ss1 + w[j]
			} else {
				tt1 = ff1(a, bb, c) + d + ss2 + w1[j]
				tt2 = gg1(e, f, g) + h + ss1 + w[j]
			}
			d = c
			c = rotl(bb, 9)
			bb = a
			a = tt1
			h = g
			g = rotl(f, 19)
			f = e
			e = p0(tt2)
		}
		v[0] ^= a
		v[1] ^= bb
		v[2] ^= c
		v[3] ^= d
		v[4] ^= e
		v[5] ^= f
		v[6] ^= g
		v[7] ^= h
	}

	var out [32]byte
	for i := 0; i < 8; i++ {
		binary.BigEndian.PutUint32(out[i*4:], v[i])
	}
	return out
}
