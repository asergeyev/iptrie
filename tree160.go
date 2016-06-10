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

func hasBit8(k []byte, b byte) bool {
	return (k[(b-1)/8] >> (7 - ((b - 1) % 8)) & 0x1) != 0
}

func keyStr(b []byte, ln byte) string {
	if ln <= 32 {
		// assume IPv4 for now
		kval := mkuint32(b, ln)
		return fmt.Sprintf("%d.%d.%d.%d/%d", byte(kval>>24), byte(kval>>16), byte(kval>>8), byte(kval), ln)
	} else {
		return "ipv6"
	}
}

// Command below marks beginning of template for auto-generated code.
// DO NOT REMOVE IT!

//go:generate go run ./tree_generate.go -o tree_auto.go

type Trie160 struct {
	node  *Node160
	nodes []Node160
}

type Node160 struct {
	prefixlen byte
	a, b      *Node160
	bits      [MAXBITS / 32]uint32
	data      unsafe.Pointer
	dummy     byte
}

// sweep goes thru whole subtree calling f. Could be used for cleanup,
// e.g.  tree.sweep(0, func(_ int, n *node) { n.a, n.b, n.data = nil, nil, nil })
func (node *Node160) Sweep(f func(*Node160)) {
	// reverse order
	if node.a != nil {
		node.a.Sweep(f)
	}
	if node.b != nil {
		node.b.Sweep(f)
	}
	f(node)
}

func (node *Node160) Drill(f func(*Node160)) {
	f(node)
	if node.b != nil {
		node.b.Drill(f)
	}
	if node.a != nil {
		node.a.Drill(f)
	}
}

func (node *Node160) DrillN(f func(*Node160)) {
	stack := []*Node160{node}
	for len(stack) > 0 {
		xn := len(stack) - 1
		f(stack[xn])
		if node.b != nil {
			stack[xn] = node.b
			if node.a != nil {
				stack = append(stack, node.a)
			}
		} else if node.a != nil {
			stack[xn] = node.a
		} else {
			stack = stack[:xn]
		}
	}
}

func (t *Trie160) Root() *Node160 {
	return t.node
}

func (node *Node160) Bits() byte {
	return node.prefixlen
}

func (node *Node160) IP() []byte {
	words := int(node.prefixlen+31) / 32
	s := make([]byte, 4*words)
	for i := 0; i < words; i++ {
		u32, start := node.bits[i], i*4
		s[start], s[start+1], s[start+2], s[start+3] = byte(u32>>24), byte(u32>>16), byte(u32>>8), byte(u32)
	}
	return s
}

// match returns true if key/ln is valid child of node or node itself
func (node *Node160) match(key []byte, ln byte) bool {
	if ln < node.prefixlen {
		return false
	}

	if npl := node.prefixlen; npl != 0 {
		mask := uint32(0xffffffff)
		if npl%32 != 0 {
			mask = ^(mask >> (npl % 32))
		}
		if npl <= 32 {
			return node.bits[0]&mask == mkuint32(key, ln)&mask
		}

		m := (npl - 1) / 32
		if m > 0 {
			for s := m - 1; s > 0; s-- {
				if node.bits[s] != mkuint32(key[s*4:], ln-s*8) {
					return false
				}
			}
			if node.bits[0] != mkuint32(key[0:], ln) {
				return false
			}
		}
		if node.bits[m]&mask != mkuint32(key[m*4:], ln-m*8)&mask {
			return false
		}
	}
	return true
}

func (node *Node160) bitsMatched(key []uint32, ln byte) byte {
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

func (t *Trie160) newnode(bits []byte, prefixlen, dummy byte) *Node160 {
	if len(t.nodes) == 0 {
		t.nodes = make([]Node160, 20) // 20 nodes at once to prepare
	}

	idx := len(t.nodes) - 1
	node := &(t.nodes[idx])
	t.nodes = t.nodes[:idx]

	node.prefixlen, node.dummy = prefixlen, dummy

	end := (prefixlen + 31) / 32
	for pos := byte(0); pos < end; pos++ {
		node.bits[pos] = mkuint32(bits[pos*4:], prefixlen)
		prefixlen -= 32
	}
	return node
}

func (node *Node160) findBestMatch(key []byte, ln byte) (bool, *Node160, *Node160) {
	var (
		exact   bool
		cparent *Node160
		parent  *Node160
	)
	for node != nil && node.match(key, ln) {
		if parent != nil && parent.dummy == 0 {
			cparent = parent
		}
		if DEBUG != nil {
			if node.dummy != 0 {
				fmt.Fprintf(DEBUG, "dummy %s for %s\n", keyStr(node.IP(), node.prefixlen), keyStr(key, ln))
			} else {
				fmt.Fprintf(DEBUG, "found %s for %s\n", keyStr(node.IP(), node.prefixlen), keyStr(key, ln))
			}
		}
		parent = node
		if node.prefixlen == ln {
			exact = true
			break
		}
		if hasBit8(key, parent.prefixlen+1) {
			node = node.a
		} else {
			node = node.b
		}
	}
	return exact, parent, cparent
}

func (node *Node160) delChildNode(key []byte, ln byte) bool {
	var parent *Node160
	for node != nil && node.match(key, ln) {
		parent = node
		if hasBit8(key, parent.prefixlen+1) {
			node = node.a
			if node.prefixlen == ln {
				if node.a == nil && node.b == nil {
					parent.a = nil
				} else if node.b == nil {
					// right branch has right side child, trim
					parent.a = node.a
				} else {
					node.data = nil
					node.dummy = 1
				}
				return true
			}
		} else {
			node = node.b
			if node.prefixlen == ln {
				if node.a == nil && node.b == nil {
					parent.b = nil
				} else if node.a == nil {
					// left branch has left side child, trim
					parent.b = node.b
				} else {
					node.data = nil
					node.dummy = 1
				}
				return true
			}
		}
	}
	return false
}

func (t *Trie160) addToNode(node *Node160, key []byte, ln byte, value unsafe.Pointer, replace bool) (set bool, newnode *Node160) {
	if ln > MAXBITS {
		panic("Unable to add prefix longer than MAXBITS")
	}

	set = true
	if t.node == nil {
		// just starting a tree
		if DEBUG != nil {
			fmt.Fprintf(DEBUG, "root=%s (no subtree)\n", keyStr(key, ln))
		}
		t.node = t.newnode(key[:(ln+7)/8], ln, 0)
		t.node.data = value
		newnode = t.node
		return
	}
	var (
		exact bool
		down  *Node160
	)
	if exact, node, _ = node.findBestMatch(key, ln); exact {
		if node.dummy != 0 {
			node.Assign(value)
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
	newnode = t.newnode(key, ln, 0)
	newnode.data = value
	if node != nil {
		if hasBit8(key, node.prefixlen+1) {
			if node.a == nil {
				node.a = newnode
				if DEBUG != nil {
					fmt.Fprintf(DEBUG, "a-child %s for %s\n", keyStr(key, ln), keyStr(node.IP(), node.prefixlen))
				}
				return set, newnode
			}
			// newnode fits between node and node.a
			down = node.a
		} else {
			if node.b == nil {
				node.b = newnode
				if DEBUG != nil {
					fmt.Fprintf(DEBUG, "b-child %s for %s\n", keyStr(key, ln), keyStr(node.IP(), node.prefixlen))
				}
				return set, newnode
			}
			// newnode fits between node and node.b
			down = node.b
		}
	} else {
		// newnode goes in front of root node
		down = t.node
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
					fmt.Fprintf(DEBUG, "insert a-child %s to %s before %s\n", keyStr(key, ln), keyStr(parent.IP(), parent.prefixlen), keyStr(down.IP(), down.prefixlen))
				}
				parent.a = newnode
			} else {
				if DEBUG != nil {
					fmt.Fprintf(DEBUG, "insert b-child %s to %s before %s\n", keyStr(key, ln), keyStr(parent.IP(), parent.prefixlen), keyStr(down.IP(), down.prefixlen))
				}
				parent.b = newnode
			}
		} else {
			if DEBUG != nil {
				m := "b"
				if hasBit(newnode.bits[:], 1) {
					m = "a"
				}
				fmt.Fprintf(DEBUG, "root=%s (uses %s as %s-child)\n", keyStr(key, ln), keyStr(down.IP(), down.prefixlen), m)
			}
			t.node = newnode
		}
	} else {
		// down and newnode should have new dummy parent under parent
		node = t.newnode(key[:(ln+7)/8], matched, 1)
		use_a := hasBit(down.bits[:], matched+1)
		if use_a == hasBit(newnode.bits[:], matched+1) {
			panic("tangled branches while creating new intermediate parent")
		}
		if use_a {
			node.a = down
			node.b = newnode
			if DEBUG != nil {
				fmt.Fprintf(DEBUG, "created a-dummy %s with %s and %s\n", keyStr(node.IP(), node.prefixlen), keyStr(down.IP(), down.prefixlen), keyStr(key, ln))
			}
		} else {
			node.b = down
			node.a = newnode
			if DEBUG != nil {
				fmt.Fprintf(DEBUG, "created b-dummy %s with %s and %s\n", keyStr(node.IP(), node.prefixlen), keyStr(key, ln), keyStr(down.IP(), down.prefixlen))
			}
		}

		//insert b-child 1.2.3.0/25 to 1.2.3.0/24 before 1.2.3.0/29
		if parent != nil {
			if hasBit(node.bits[:], parent.prefixlen+1) {
				parent.a = node
				if DEBUG != nil {
					fmt.Fprintf(DEBUG, "insert a-child %s to %s before %s\n", keyStr(node.IP(), node.prefixlen), keyStr(parent.IP(), parent.prefixlen), keyStr(node.a.IP(), node.a.prefixlen))
				}
			} else {
				parent.b = node
				if DEBUG != nil {
					fmt.Fprintf(DEBUG, "insert b-child %s to %s before %s\n", keyStr(node.IP(), node.prefixlen), keyStr(parent.IP(), parent.prefixlen), keyStr(node.b.IP(), node.b.prefixlen))
				}
			}
		} else {
			if DEBUG != nil {
				m := "b"
				if use_a {
					m = "a"
				}
				fmt.Fprintf(DEBUG, "root=%s (uses %s as %s-child)\n", keyStr(node.IP(), node.prefixlen), keyStr(key, ln), m)
			}
			t.node = node
		}
	}

	return
}

func (rt *Trie160) Get(ip []byte, mask byte) (bool, []byte, byte, unsafe.Pointer) {
	exact, node, ct := rt.node.findBestMatch(ip, mask)

	if node != nil && node.dummy == 0 {
		// dummy=1 means "no match", we will instead look at valid container
		return exact, node.IP(), node.prefixlen, node.data
	}

	if ct != nil {
		// accept container as the answer if it's present
		return false, ct.IP(), ct.prefixlen, ct.data
	}
	return false, nil, 0, nil

}

func (rt *Trie160) Append(ip []byte, mask byte, value unsafe.Pointer) (bool, *Node160) {
	set, olval := rt.addToNode(rt.node, ip, mask, value, false)
	return set, olval
}

func (rt *Trie160) Set(ip []byte, mask byte, value unsafe.Pointer) (bool, *Node160) {
	set, olval := rt.addToNode(rt.node, ip, mask, value, true)
	return set, olval
}

func (rt *Trie160) GetNode(ip []byte, mask byte) (bool, *Node160) {
	exact, node, ct := rt.node.findBestMatch(ip, mask)
	if exact {
		return node.IsDummy(), node // if node is a dummy it needs to look like "just added"
	}
	if node != nil {
		_, node = rt.addToNode(node, ip, mask, nil, false)
	} else {
		if ct != nil {
			_, node = rt.addToNode(ct, ip, mask, nil, false)
		} else {
			_, node = rt.addToNode(rt.node, ip, mask, nil, false)
		}
	}
	return true, node

}

func (n *Node160) Data() unsafe.Pointer {
	return n.data
}

func (n *Node160) IsDummy() bool {
	return n.dummy != 0
}

func (n *Node160) Assign(value unsafe.Pointer) {
	n.data = value
	n.dummy = 0
}
