// Package iptrie implements trie for keeping IP/mask info
package iptrie

import "io"

// Copyright (c) 2016 Alex Sergeyev. All rights reserved. See LICENSE file for terms of use.

var DEBUG io.Writer

var emptyUint32 = []uint32{0}

func mkuint32(key []byte, ln byte) uint32 {
	if ln > 16 {
		if ln > 24 {
			return uint32(key[0])<<24 + uint32(key[1])<<16 + uint32(key[2])<<8 + uint32(key[3])
		}
		return uint32(key[0])<<24 + uint32(key[1])<<16 + uint32(key[2])<<8
	}
	if ln > 8 {
		return uint32(key[0])<<24 + uint32(key[1])<<16
	}
	return uint32(key[0]) << 24
}
