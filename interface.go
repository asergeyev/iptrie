// Package iptrie implements trie for keeping IP/mask info
package iptrie

import (
	"encoding/binary"
	"io"
	"unsafe"
)

// Copyright (c) 2016 Alex Sergeyev. All rights reserved. See LICENSE file for terms of use.

var DEBUG io.Writer

type RegularTrie struct {
	t4 *tree32
	t6 *tree128
}

// TODO: implement v6 calls... generate as with different trie code?

func NewTrie() *RegularTrie {
	return &RegularTrie{new(tree32), new(tree128)}
}

func (rt *RegularTrie) GetIp4(ip []byte, mask byte) (bool, []byte, byte, unsafe.Pointer) {
	if mask > 32 {
		panic("Invalid mask")
	}
	u32 := binary.BigEndian.Uint32(ip) &^ (0xffffffff >> mask)

	var ct *btrienode32
	exact, node := rt.t4.findBestMatch([]uint32{u32}, mask, &ct)

	// when found non-dummy node:
	if node.dummy == 0 {
		v := make([]byte, 4)
		binary.BigEndian.PutUint32(v, node.bits[0])
		return exact, v, node.prefixlen, node.data
	}

	// if there was no proper container
	if ct == nil {
		return false, nil, 0, nil
	}

	// accept container ase right answer
	v := make([]byte, 4)
	binary.BigEndian.PutUint32(v, ct.bits[0])

	// our interpretation of exat match is different than internally:
	return false, v, ct.prefixlen, ct.data
}

func (rt *RegularTrie) AppendIp4(ip []byte, mask byte, value unsafe.Pointer) (bool, unsafe.Pointer) {
	if mask > 32 {
		panic("Invalid mask")
	}
	u32 := binary.BigEndian.Uint32(ip) &^ (0xffffffff >> mask)

	set, olval := rt.t4.addRoute([]uint32{u32}, mask, value, false)
	return set, olval
}

func (rt *RegularTrie) ForceIp4(ip []byte, mask byte, value unsafe.Pointer) (bool, unsafe.Pointer) {
	if mask > 32 {
		panic("Invalid mask")
	}
	u32 := binary.BigEndian.Uint32(ip) &^ (0xffffffff >> mask)

	set, olval := rt.t4.addRoute([]uint32{u32}, mask, value, true)
	return set, olval
}

// ExactTree creates deep structure to track up to 32-bits of per-ip collected info
// It's not quite optimal to keep it in a tree but for certain tasks it's somewhat useful.
type ExactTree struct {
	t4 *tree64
	t6 *tree160
}

func NewExactTree() *ExactTree {
	return &ExactTree{new(tree64), new(tree160)}
}

func (et *ExactTree) GetIp4(ip []byte, word uint32) (bool, unsafe.Pointer) {
	u32 := binary.BigEndian.Uint32(ip)
	exact, node := et.t4.findBestMatch([]uint32{u32, word}, 64, nil)
	return exact, node.data
}

func (et *ExactTree) AppendIp4(ip []byte, word uint32, value unsafe.Pointer) (bool, unsafe.Pointer) {
	u32 := binary.BigEndian.Uint32(ip)
	set, olval := et.t4.addRoute([]uint32{u32, word}, 64, value, false)
	return set, olval
}

func (et *ExactTree) ForceIp4(ip []byte, word uint32, value unsafe.Pointer) (bool, unsafe.Pointer) {
	u32 := binary.BigEndian.Uint32(ip)
	set, olval := et.t4.addRoute([]uint32{u32, word}, 64, value, true)
	return set, olval
}
