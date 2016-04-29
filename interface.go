// Package iptrie implements trie for keeping IP/mask info
package iptrie

import "io"

// Copyright (c) 2016 Alex Sergeyev. All rights reserved. See LICENSE file for terms of use.

var DEBUG io.Writer

var emptyUint32 = []uint32{0}

func mkuint32(key []byte, ln byte) uint32 {
	mask := uint32(0xffffffff)
	if ln < 32 {
		mask = ^(mask >> ln)
	}
	if ln > 16 && len(key) > 2 {
		if ln > 24 && len(key) > 3 {
			// now see if there is enough bytes
			return (uint32(key[0])<<24 | uint32(key[1])<<16 | uint32(key[2])<<8 | uint32(key[3])) & mask
		}
		return (uint32(key[0])<<24 | uint32(key[1])<<16 | uint32(key[2])<<8) & mask
	}
	if ln > 8 && len(key) > 1 {
		return (uint32(key[0])<<24 | uint32(key[1])<<16) & mask
	}
	return (uint32(key[0]) << 24) & mask
}
