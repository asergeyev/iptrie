// Package iptrie implements trie for keeping IP/mask info
package iptrie

import (
	"encoding/binary"
	"io"
)

// Copyright (c) 2016 Alex Sergeyev. All rights reserved. See LICENSE file for terms of use.

var DEBUG io.Writer

func iptou(ip []byte, mask byte) []uint32 {
	iplen := len(ip)
	if iplen == 0 || mask == 0 {
		return []uint32{0}
	}
	if iplen < int(mask>>3) { // mask / 8
		panic("Unable to look for empty key that's shorter than it's mask")
	}

	u32 := make([]uint32, (mask+31)/32)
	for pos := 0; pos < iplen; pos += 4 {
		if diff := iplen - pos; diff > 2 {
			if diff == 3 {
				u32[pos/4] = uint32(ip[pos])<<24 | uint32(ip[pos+1])<<16 | uint32(ip[pos+2])<<8
			} else {
				u32[pos/4] = uint32(ip[pos])<<24 | uint32(ip[pos+1])<<16 | uint32(ip[pos+2])<<8 | uint32(ip[pos+3])
			}
		} else {
			if diff == 1 {
				u32[pos/4] = uint32(ip[pos]) << 24
			} else {
				u32[pos/4] = uint32(ip[pos])<<24 | uint32(ip[pos+1])<<16
			}
		}
	}
	// wipe bits that should be empty in last word:
	if mask > 0 && mask%32 != 0 {
		u32[len(u32)-1] = u32[len(u32)-1] &^ (uint32(0xffffffff) >> (mask % 32))
	}
	return u32
}

func utoip(words []uint32, mask byte) []byte {
	ln := ((mask + 31) / 32) * 4 // yes, return 0.0.0.0 and ::0 as empty array
	ret := make([]byte, ln)
	for i := byte(0); i < ln; i += 4 {
		binary.BigEndian.PutUint32(ret[i:], words[i/4])
	}
	return ret
}

type Trie32 struct {
	*tree32
}

type Trie64 struct {
	*tree64
}

type Trie128 struct {
	*tree128
}

type Trie160 struct {
	*tree160
}
