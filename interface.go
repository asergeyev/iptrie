// Package iptrie implements trie for keeping IP/mask info
package iptrie

import "io"

// Copyright (c) 2016 Alex Sergeyev. All rights reserved. See LICENSE file for terms of use.

var DEBUG io.Writer

var emptyUint32 = []uint32{0}

func iptou(ip []byte, mask byte) []uint32 {
	if mask == 0 {
		return emptyUint32
	}
	iplen := int(mask+7) / 8
	if iplen > len(ip) { // mask / 8
		panic("Unable to look for key that's shorter than it's mask")
	}
	var u32 [MAXBITS / 32]uint32
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
	return u32[:(mask+31)/32]
}

func utoip(words []uint32, mask byte) []byte {
	ln := int(mask+31) / 32 // yes, return 0.0.0.0 and ::0 as empty array
	var ret [MAXBITS / 8]byte
	for start, i := 0, 0; i < ln; start, i = start+4, i+1 {
		ret[start], ret[start+1], ret[start+2], ret[start+3] = byte(words[i]>>24), byte(words[i]>>16), byte(words[i]>>8), byte(words[i])
	}
	return ret[:ln*4]
}
