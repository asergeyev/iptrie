package iptrie

// Copyright (c) 2016 Alex Sergeyev. All rights reserved. See LICENSE file for terms of use.

import (
	"fmt"
	"unsafe"
)

const MAXBITS = 160 // max length is IPV6+32bitASN

func hasBit(k []uint32, b byte) bool {
	return (k[(b-1)/32] >> (31 - ((b - 1) % 32)) & 0x1) != 0
}

func keyStr(s []uint32, ln byte) string {
	if ln <= 32 {
		// assume IPv4 for now
		return fmt.Sprintf("%d.%d.%d.%d/%d", byte(s[0]>>24), byte(s[0]>>16), byte(s[0]>>8), byte(s[0]), ln)
	} else {
		return "ipv6"
	}
}

// Command below marks beginning of template for auto-generated code.
// DO NOT REMOVE IT!

//go:generate go run ./tree_generate.go -o tree_auto.go

type Trie160 struct {
	*tree160
}

type Node160 btrienode160

type btrienode160 struct {
	a, b      *btrienode160
	data      unsafe.Pointer
	bits      [MAXBITS / 32]uint32
	prefixlen byte
	dummy     byte
}

// sweep goes thru whole subtree calling f. Could be used for cleanup,
// e.g.  tree.sweep(0, func(_ int, n *node) { n.a, n.b, n.data = nil, nil, nil })
func (node *btrienode160) sweep(level int, f func(int, *btrienode160)) {
	if node.a != nil {
		node.a.sweep(level+1, f)
	}
	if node.b != nil {
		node.b.sweep(level+1, f)
	}
	f(level, node)
}

// match returns true if key/ln is valid child of node or node itself
func (node *btrienode160) match(key []uint32, ln byte) bool {
	npl := node.prefixlen
	if ln < npl {
		return false
	}

	if npl != 0 {
		var mask uint32
		if npl%32 != 0 {
			mask = ^(0xffffffff >> (npl % 32))
		} else {
			mask = 0xffffffff
		}
		if npl <= 32 {
			return node.bits[0]&mask == key[0]&mask
		}

		m := int(npl-1) / 32
		for s := m - 1; s >= 0; s-- {
			if node.bits[s] != key[s] {
				return false
			}
		}
		if node.bits[m]&mask != key[m]&mask {
			return false
		}
	}
	return true
}

func (node *btrienode160) bitsMatched(key []uint32, ln byte) byte {
	npl := node.prefixlen
	if ln < npl {
		npl = ln // limit matching to min length
	}
	if npl == 0 {
		return 0
	}
	var n, plen byte
	for n = 0; n < npl/32; n++ {
		// how many should be equal?
		if key[n] != node.bits[n] {
			// compare that bit
			break
		}
		plen += 32 // skip checking every bit in this word
	}

	var mask uint32

	for plen < npl {
		mask = (mask >> 1) | 0x80000000 // move 1 and set 32nd bit to 1
		if (node.bits[n] & mask) != (key[n] & mask) {
			break
		}
		plen++
	}

	return plen
}

type tree160 struct {
	*btrienode160
	nodes []btrienode160
}

func (t *tree160) newnode(bits []uint32, prefixlen, dummy byte) *btrienode160 {
	if len(t.nodes) == 0 {
		t.nodes = make([]btrienode160, 20) // 20 nodes at once to prepare
	}

	idx := len(t.nodes) - 1
	node := &(t.nodes[idx])
	t.nodes = t.nodes[:idx]

	node.prefixlen, node.dummy = prefixlen, dummy
	copy(node.bits[:], bits)
	return node
}

func (t *tree160) isEmpty() bool {
	return t.btrienode160 == nil
}

func (t *tree160) findBestMatch(key []uint32, ln byte) (bool, *btrienode160, *btrienode160) {
	var (
		exact   bool
		cparent *btrienode160
		parent  *btrienode160
		node    = t.btrienode160
	)
	for node != nil && node.match(key, ln) {
		if parent != nil && parent.dummy == 0 {
			cparent = parent
		}
		if DEBUG != nil {
			if node.dummy != 0 {
				fmt.Fprintf(DEBUG, "dummy %s for %s\n", keyStr(node.bits[:], node.prefixlen), keyStr(key, ln))
			} else {
				fmt.Fprintf(DEBUG, "found %s for %s\n", keyStr(node.bits[:], node.prefixlen), keyStr(key, ln))
			}
		}
		parent = node
		if node.prefixlen == ln {
			exact = true
			break
		}
		if hasBit(key, parent.prefixlen+1) {
			node = node.a
		} else {
			node = node.b
		}
	}
	return exact, parent, cparent
}

func (t *tree160) addRoute(key []uint32, ln byte, value unsafe.Pointer, replace bool) (set bool, newnode *btrienode160) {
	if ln > MAXBITS {
		panic("Unable to add prefix longer than MAXBITS")
	}
	set = true
	if t.btrienode160 == nil {
		// just starting a tree
		if DEBUG != nil {
			fmt.Fprintf(DEBUG, "root=%s (no subtree)\n", keyStr(key, ln))
		}
		t.btrienode160 = t.newnode(key[:(ln+31)/32], ln, 0)
		t.btrienode160.data = value
		return
	}
	var (
		exact bool
		node  *btrienode160
		down  *btrienode160
	)
	if exact, node, _ = t.findBestMatch(key, ln); exact {
		if node.dummy != 0 {
			node.dummy = 0
			node.data = value
			if DEBUG != nil {
				fmt.Fprintf(DEBUG, "setting empty child's %v/%d value\n", key, ln)
			}
		} else {
			if replace {
				node.data = value
			} else {
				set = false // this is only time we don't set
			}
			if DEBUG != nil {
				fmt.Fprintf(DEBUG, "hit previously set %v/%d node\n", key, ln)
			}
		}
		return set, node
	}
	newnode = t.newnode(key[:(ln+31)/32], ln, 0)
	newnode.data = value
	if node != nil {
		if hasBit(key, node.prefixlen+1) {
			if node.a == nil {
				node.a = newnode
				if DEBUG != nil {
					fmt.Fprintf(DEBUG, "a-child %s for %s\n", keyStr(key, ln), keyStr(node.bits[:], node.prefixlen))
				}
				return set, newnode
			}
			// newnode fits between node and node.a
			down = node.a
		} else {
			if node.b == nil {
				node.b = newnode
				if DEBUG != nil {
					fmt.Fprintf(DEBUG, "b-child %s for %s\n", keyStr(key, ln), keyStr(node.bits[:], node.prefixlen))
				}
				return set, newnode
			}
			// newnode fits between node and node.b
			down = node.b
		}
	} else {
		// newnode goes in front of root node
		down = t.btrienode160
	}

	parent := node
	if parent != nil && parent.prefixlen >= ln {
		panic("parent's prefix could not be larger than key len")
	}

	matched := down.bitsMatched(newnode.bits[:], ln)

	// Well. We fit somewhere between parent and down
	// parent.bits match up to parent.prefixlen          1111111111100000000000
	//                                                   11111111111..11
	// down.bits match up to matched                     11111111111..1111

	if matched == ln {
		// down is child of key
		if hasBit(down.bits[:], ln+1) {
			newnode.a = down
		} else {
			newnode.b = down
		}
		if parent != nil {
			use_a := hasBit(newnode.bits[:], parent.prefixlen+1)
			if use_a != hasBit(down.bits[:], parent.prefixlen+1) {
				panic("something is wrong with branch that we intend to append to")
			}
			if use_a {
				if DEBUG != nil {
					fmt.Fprintf(DEBUG, "insert a-child %s to %s before %s\n", keyStr(key, ln), keyStr(parent.bits[:], parent.prefixlen), keyStr(down.bits[:], down.prefixlen))
				}
				parent.a = newnode
			} else {
				if DEBUG != nil {
					fmt.Fprintf(DEBUG, "insert b-child %s to %s before %s\n", keyStr(key, ln), keyStr(parent.bits[:], parent.prefixlen), keyStr(down.bits[:], down.prefixlen))
				}
				parent.b = newnode
			}
		} else {
			if DEBUG != nil {
				m := "b"
				if hasBit(newnode.bits[:], 1) {
					m = "a"
				}
				fmt.Fprintf(DEBUG, "root=%s (uses %s as %s-child)\n", keyStr(key, ln), keyStr(down.bits[:], down.prefixlen), m)
			}
			t.btrienode160 = newnode
		}
	} else {
		// down and newnode should have new dummy parent under parent
		node = t.newnode(key[:(ln+31)/32], matched, 1)
		use_a := hasBit(down.bits[:], matched+1)
		if use_a == hasBit(newnode.bits[:], matched+1) {
			panic("tangled branches while creating new intermediate parent")
		}
		if use_a {
			node.a = down
			node.b = newnode
			if DEBUG != nil {
				fmt.Fprintf(DEBUG, "created a-dummy %s with %s and %s\n", keyStr(node.bits[:], node.prefixlen), keyStr(down.bits[:], down.prefixlen), keyStr(key, ln))
			}
		} else {
			node.b = down
			node.a = newnode
			if DEBUG != nil {
				fmt.Fprintf(DEBUG, "created b-dummy %s with %s and %s\n", keyStr(node.bits[:], node.prefixlen), keyStr(key, ln), keyStr(down.bits[:], down.prefixlen))
			}
		}

		//insert b-child 1.2.3.0/25 to 1.2.3.0/24 before 1.2.3.0/29
		if parent != nil {
			if hasBit(node.bits[:], parent.prefixlen+1) {
				parent.a = node
				if DEBUG != nil {
					fmt.Fprintf(DEBUG, "insert a-child %s to %s before %s\n", keyStr(node.bits[:], node.prefixlen), keyStr(parent.bits[:], parent.prefixlen), keyStr(node.a.bits[:], node.a.prefixlen))
				}
			} else {
				parent.b = node
				if DEBUG != nil {
					fmt.Fprintf(DEBUG, "insert b-child %s to %s before %s\n", keyStr(node.bits[:], node.prefixlen), keyStr(parent.bits[:], parent.prefixlen), keyStr(node.b.bits[:], node.b.prefixlen))
				}
			}
		} else {
			if DEBUG != nil {
				m := "b"
				if use_a {
					m = "a"
				}
				fmt.Fprintf(DEBUG, "root=%s (uses %s as %s-child)\n", keyStr(node.bits[:], node.prefixlen), keyStr(key, ln), m)
			}
			t.btrienode160 = node
		}
	}

	return
}

func New160() *Trie160 {
	return &Trie160{new(tree160)}
}

func (rt *Trie160) Get(ip []byte, mask byte) (bool, []byte, byte, unsafe.Pointer) {
	u32 := iptou(ip, mask)
	exact, node, ct := rt.findBestMatch(u32, mask)

	if node != nil && node.dummy == 0 {
		// dummy node means "no match"
		return exact, utoip(node.bits[:], node.prefixlen), node.prefixlen, node.data
	}

	if ct != nil {
		// accept container as the answer if it's present
		return false, utoip(ct.bits[:], ct.prefixlen), ct.prefixlen, ct.data
	}
	return false, nil, 0, nil

}

func (rt *Trie160) Append(ip []byte, mask byte, value unsafe.Pointer) (bool, *Node160) {
	u32 := iptou(ip, mask)
	set, olval := rt.addRoute(u32, mask, value, false)
	return set, (*Node160)(olval)
}

func (rt *Trie160) Set(ip []byte, mask byte, value unsafe.Pointer) (bool, *Node160) {
	u32 := iptou(ip, mask)
	set, olval := rt.addRoute(u32, mask, value, true)
	return set, (*Node160)(olval)
}
