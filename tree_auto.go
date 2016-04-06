// *** AUTOGENERATED BY "go generate" ***

package iptrie

import (
	"fmt"
	"unsafe"
)

type tree32 struct {
	*btrienode32
}

type btrienode32 struct {
	a, b      *btrienode32
	data      unsafe.Pointer
	bits      [MAXBITS / 32]uint32
	prefixlen byte
	dummy     byte
}

// sweep goes thru whole subtree calling f. Could be used for cleanup,
// e.g.  tree.sweep(func(n *node) { n.a, n.b, n.data = nil, nil, nil })
func (node *btrienode32) sweep(f func(*btrienode32)) {
	if node.a != nil {
		f(node.a)
	}
	if node.b != nil {
		f(node.b)
	}
	f(node)
}

func (node *btrienode32) match(key []uint32, ln byte) bool {
	if ln <= 0 {
		return true
	}
	var i, m byte = 0, (ln - 1) / 32
	for i = 0; i <= m; i++ {
		if i < m { // match whole word, not close to end yet
			if node.bits[i] != key[i] {
				return false
			}
		} else {
			var mask uint32 = ^(0xffffffff >> (ln % 32))
			if (node.bits[i] & mask) != (key[i] & mask) {
				return false
			}
		}
	}
	return true
}

func (node *btrienode32) bitsMatched(key []uint32, ln byte) byte {
	maxlen := node.prefixlen
	if ln > maxlen {
		maxlen = ln
	}
	var plen byte
	for n, word := range node.bits {
		var mask, trymask uint32
		for mask != 0xffffffff && plen < maxlen {
			trymask = (mask >> 1) | 0x80000000 // move 1 and set 32nd bit to 1
			if (word & trymask) != (key[n] & trymask) {
				break
			}
			mask = trymask
			plen++
		}
		if mask != 0xffffffff || plen >= maxlen {
			break
		}
	}
	return plen
}

func (t *tree32) findBestMatch(key []uint32, ln byte, container **btrienode32) (bool, *btrienode32) {
	var (
		exact  bool
		parent *btrienode32
		pstack = make([]*btrienode32, 0, MAXBITS)
		node   = t.btrienode32
	)
	for node != nil && node.prefixlen <= ln && node.match(key, node.prefixlen) {
		pstack = append(pstack, node)
		parent = node
		if DEBUG != nil {
			fmt.Fprintf(DEBUG, "found %s for %s\n", keyStr(parent.bits[:], parent.prefixlen), keyStr(key, ln))
		}
		if parent.prefixlen == ln {
			exact = true
			break
		}
		if hasBit(key, parent.prefixlen+1) {
			node = node.a
		} else {
			node = node.b
		}
	}
	if container != nil {
		for ln := len(pstack) - 1; ln >= 0; pstack, ln = pstack[:ln], ln-1 {
			if pstack[ln].dummy != 1 {
				*container = pstack[ln]
			}
		}
	}
	return exact, parent
}

func (t *tree32) addRoute(key []uint32, ln byte, value unsafe.Pointer, replace bool) (set bool, oldval unsafe.Pointer) {
	if ln > MAXBITS {
		panic("Unable to add prefix longer than MAXBITS")
	}
	set = true
	if t.btrienode32 == nil {
		// just starting a tree
		if DEBUG != nil {
			fmt.Fprintf(DEBUG, "root=%s (no subtree)\n", keyStr(key, ln))
		}
		t.btrienode32 = &btrienode32{data: value, prefixlen: ln}
		copy(t.btrienode32.bits[:], key[:(ln+31)/32])
		return
	}
	var (
		exact bool
		node  *btrienode32
		down  *btrienode32
	)
	if exact, node = t.findBestMatch(key, ln, nil); exact {
		if node.dummy != 0 {
			node.dummy = 0
			node.data = value
			if DEBUG != nil {
				fmt.Fprintf(DEBUG, "setting empty child's %v/%d value\n", key, ln)
			}
		} else {
			oldval = node.data
			if replace {
				node.data = value
			} else {
				set = false // this is only time we don't set
			}
			if DEBUG != nil {
				fmt.Fprintf(DEBUG, "hit previously set %v/%d node\n", key, ln)
			}
		}
		return
	}
	newnode := &btrienode32{data: value, prefixlen: ln}
	copy(newnode.bits[:], key[:(ln+31)/32])
	if node != nil {
		if hasBit(key, node.prefixlen+1) {
			if node.a == nil {
				node.a = newnode
				if DEBUG != nil {
					fmt.Fprintf(DEBUG, "a-child %s for %s\n", keyStr(key, ln), keyStr(node.bits[:], node.prefixlen))
				}
				return
			}
			// newnode fits between node and node.a
			down = node.a
		} else {
			if node.b == nil {
				node.b = newnode
				if DEBUG != nil {
					fmt.Fprintf(DEBUG, "b-child %s for %s\n", keyStr(key, ln), keyStr(node.bits[:], node.prefixlen))
				}
				return
			}
			// newnode fits between node and node.b
			down = node.b
		}
	} else {
		// newnode goes in front of root node
		down = t.btrienode32
	}

	parent := node
	if parent != nil && parent.prefixlen >= ln {
		panic("parent's prefix could not be larger than key len")
	}

	matched := down.bitsMatched(key, ln)
	if matched > ln {
		matched = ln
	}

	if matched == ln { // matched >=ln to remove that if above
		// down matches key fully, so new branch would start from here
		var plen byte = 1
		if parent != nil {
			// also make sure we're not messed up branch direction
			plen = parent.prefixlen + 1
		}
		use_a := hasBit(newnode.bits[:], plen)
		if use_a != hasBit(down.bits[:], plen) {
			panic("something is wrong with branch that we intend to append to")
		}
		if use_a {
			newnode.a = down
		} else {
			newnode.b = down
		}
		if parent != nil {
			if hasBit(newnode.bits[:], plen) {
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
				if use_a {
					m = "a"
				}
				fmt.Fprintf(DEBUG, "root=%s (uses %s as %s-child)\n", keyStr(key, ln), keyStr(down.bits[:], down.prefixlen), m)
			}
			t.btrienode32 = newnode
		}
	} else {
		// down and newnode should have new empty parent
		node = &btrienode32{dummy: 1, prefixlen: matched}
		copy(node.bits[:], key[:(ln+31)/32])
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
			if hasBit(newnode.bits[:], parent.prefixlen+1) {
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
			t.btrienode32 = node
		}
	}
	return
}

type tree64 struct {
	*btrienode64
}

type btrienode64 struct {
	a, b      *btrienode64
	data      unsafe.Pointer
	bits      [MAXBITS / 32]uint32
	prefixlen byte
	dummy     byte
}

// sweep goes thru whole subtree calling f. Could be used for cleanup,
// e.g.  tree.sweep(func(n *node) { n.a, n.b, n.data = nil, nil, nil })
func (node *btrienode64) sweep(f func(*btrienode64)) {
	if node.a != nil {
		f(node.a)
	}
	if node.b != nil {
		f(node.b)
	}
	f(node)
}

func (node *btrienode64) match(key []uint32, ln byte) bool {
	if ln <= 0 {
		return true
	}
	var i, m byte = 0, (ln - 1) / 32
	for i = 0; i <= m; i++ {
		if i < m { // match whole word, not close to end yet
			if node.bits[i] != key[i] {
				return false
			}
		} else {
			var mask uint32 = ^(0xffffffff >> (ln % 32))
			if (node.bits[i] & mask) != (key[i] & mask) {
				return false
			}
		}
	}
	return true
}

func (node *btrienode64) bitsMatched(key []uint32, ln byte) byte {
	maxlen := node.prefixlen
	if ln > maxlen {
		maxlen = ln
	}
	var plen byte
	for n, word := range node.bits {
		var mask, trymask uint32
		for mask != 0xffffffff && plen < maxlen {
			trymask = (mask >> 1) | 0x80000000 // move 1 and set 32nd bit to 1
			if (word & trymask) != (key[n] & trymask) {
				break
			}
			mask = trymask
			plen++
		}
		if mask != 0xffffffff || plen >= maxlen {
			break
		}
	}
	return plen
}

func (t *tree64) findBestMatch(key []uint32, ln byte, container **btrienode64) (bool, *btrienode64) {
	var (
		exact  bool
		parent *btrienode64
		pstack = make([]*btrienode64, 0, MAXBITS)
		node   = t.btrienode64
	)
	for node != nil && node.prefixlen <= ln && node.match(key, node.prefixlen) {
		pstack = append(pstack, node)
		parent = node
		if DEBUG != nil {
			fmt.Fprintf(DEBUG, "found %s for %s\n", keyStr(parent.bits[:], parent.prefixlen), keyStr(key, ln))
		}
		if parent.prefixlen == ln {
			exact = true
			break
		}
		if hasBit(key, parent.prefixlen+1) {
			node = node.a
		} else {
			node = node.b
		}
	}
	if container != nil {
		for ln := len(pstack) - 1; ln >= 0; pstack, ln = pstack[:ln], ln-1 {
			if pstack[ln].dummy != 1 {
				*container = pstack[ln]
			}
		}
	}
	return exact, parent
}

func (t *tree64) addRoute(key []uint32, ln byte, value unsafe.Pointer, replace bool) (set bool, oldval unsafe.Pointer) {
	if ln > MAXBITS {
		panic("Unable to add prefix longer than MAXBITS")
	}
	set = true
	if t.btrienode64 == nil {
		// just starting a tree
		if DEBUG != nil {
			fmt.Fprintf(DEBUG, "root=%s (no subtree)\n", keyStr(key, ln))
		}
		t.btrienode64 = &btrienode64{data: value, prefixlen: ln}
		copy(t.btrienode64.bits[:], key[:(ln+31)/32])
		return
	}
	var (
		exact bool
		node  *btrienode64
		down  *btrienode64
	)
	if exact, node = t.findBestMatch(key, ln, nil); exact {
		if node.dummy != 0 {
			node.dummy = 0
			node.data = value
			if DEBUG != nil {
				fmt.Fprintf(DEBUG, "setting empty child's %v/%d value\n", key, ln)
			}
		} else {
			oldval = node.data
			if replace {
				node.data = value
			} else {
				set = false // this is only time we don't set
			}
			if DEBUG != nil {
				fmt.Fprintf(DEBUG, "hit previously set %v/%d node\n", key, ln)
			}
		}
		return
	}
	newnode := &btrienode64{data: value, prefixlen: ln}
	copy(newnode.bits[:], key[:(ln+31)/32])
	if node != nil {
		if hasBit(key, node.prefixlen+1) {
			if node.a == nil {
				node.a = newnode
				if DEBUG != nil {
					fmt.Fprintf(DEBUG, "a-child %s for %s\n", keyStr(key, ln), keyStr(node.bits[:], node.prefixlen))
				}
				return
			}
			// newnode fits between node and node.a
			down = node.a
		} else {
			if node.b == nil {
				node.b = newnode
				if DEBUG != nil {
					fmt.Fprintf(DEBUG, "b-child %s for %s\n", keyStr(key, ln), keyStr(node.bits[:], node.prefixlen))
				}
				return
			}
			// newnode fits between node and node.b
			down = node.b
		}
	} else {
		// newnode goes in front of root node
		down = t.btrienode64
	}

	parent := node
	if parent != nil && parent.prefixlen >= ln {
		panic("parent's prefix could not be larger than key len")
	}

	matched := down.bitsMatched(key, ln)
	if matched > ln {
		matched = ln
	}

	if matched == ln { // matched >=ln to remove that if above
		// down matches key fully, so new branch would start from here
		var plen byte = 1
		if parent != nil {
			// also make sure we're not messed up branch direction
			plen = parent.prefixlen + 1
		}
		use_a := hasBit(newnode.bits[:], plen)
		if use_a != hasBit(down.bits[:], plen) {
			panic("something is wrong with branch that we intend to append to")
		}
		if use_a {
			newnode.a = down
		} else {
			newnode.b = down
		}
		if parent != nil {
			if hasBit(newnode.bits[:], plen) {
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
				if use_a {
					m = "a"
				}
				fmt.Fprintf(DEBUG, "root=%s (uses %s as %s-child)\n", keyStr(key, ln), keyStr(down.bits[:], down.prefixlen), m)
			}
			t.btrienode64 = newnode
		}
	} else {
		// down and newnode should have new empty parent
		node = &btrienode64{dummy: 1, prefixlen: matched}
		copy(node.bits[:], key[:(ln+31)/32])
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
			if hasBit(newnode.bits[:], parent.prefixlen+1) {
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
			t.btrienode64 = node
		}
	}
	return
}

type tree128 struct {
	*btrienode128
}

type btrienode128 struct {
	a, b      *btrienode128
	data      unsafe.Pointer
	bits      [MAXBITS / 32]uint32
	prefixlen byte
	dummy     byte
}

// sweep goes thru whole subtree calling f. Could be used for cleanup,
// e.g.  tree.sweep(func(n *node) { n.a, n.b, n.data = nil, nil, nil })
func (node *btrienode128) sweep(f func(*btrienode128)) {
	if node.a != nil {
		f(node.a)
	}
	if node.b != nil {
		f(node.b)
	}
	f(node)
}

func (node *btrienode128) match(key []uint32, ln byte) bool {
	if ln <= 0 {
		return true
	}
	var i, m byte = 0, (ln - 1) / 32
	for i = 0; i <= m; i++ {
		if i < m { // match whole word, not close to end yet
			if node.bits[i] != key[i] {
				return false
			}
		} else {
			var mask uint32 = ^(0xffffffff >> (ln % 32))
			if (node.bits[i] & mask) != (key[i] & mask) {
				return false
			}
		}
	}
	return true
}

func (node *btrienode128) bitsMatched(key []uint32, ln byte) byte {
	maxlen := node.prefixlen
	if ln > maxlen {
		maxlen = ln
	}
	var plen byte
	for n, word := range node.bits {
		var mask, trymask uint32
		for mask != 0xffffffff && plen < maxlen {
			trymask = (mask >> 1) | 0x80000000 // move 1 and set 32nd bit to 1
			if (word & trymask) != (key[n] & trymask) {
				break
			}
			mask = trymask
			plen++
		}
		if mask != 0xffffffff || plen >= maxlen {
			break
		}
	}
	return plen
}

func (t *tree128) findBestMatch(key []uint32, ln byte, container **btrienode128) (bool, *btrienode128) {
	var (
		exact  bool
		parent *btrienode128
		pstack = make([]*btrienode128, 0, MAXBITS)
		node   = t.btrienode128
	)
	for node != nil && node.prefixlen <= ln && node.match(key, node.prefixlen) {
		pstack = append(pstack, node)
		parent = node
		if DEBUG != nil {
			fmt.Fprintf(DEBUG, "found %s for %s\n", keyStr(parent.bits[:], parent.prefixlen), keyStr(key, ln))
		}
		if parent.prefixlen == ln {
			exact = true
			break
		}
		if hasBit(key, parent.prefixlen+1) {
			node = node.a
		} else {
			node = node.b
		}
	}
	if container != nil {
		for ln := len(pstack) - 1; ln >= 0; pstack, ln = pstack[:ln], ln-1 {
			if pstack[ln].dummy != 1 {
				*container = pstack[ln]
			}
		}
	}
	return exact, parent
}

func (t *tree128) addRoute(key []uint32, ln byte, value unsafe.Pointer, replace bool) (set bool, oldval unsafe.Pointer) {
	if ln > MAXBITS {
		panic("Unable to add prefix longer than MAXBITS")
	}
	set = true
	if t.btrienode128 == nil {
		// just starting a tree
		if DEBUG != nil {
			fmt.Fprintf(DEBUG, "root=%s (no subtree)\n", keyStr(key, ln))
		}
		t.btrienode128 = &btrienode128{data: value, prefixlen: ln}
		copy(t.btrienode128.bits[:], key[:(ln+31)/32])
		return
	}
	var (
		exact bool
		node  *btrienode128
		down  *btrienode128
	)
	if exact, node = t.findBestMatch(key, ln, nil); exact {
		if node.dummy != 0 {
			node.dummy = 0
			node.data = value
			if DEBUG != nil {
				fmt.Fprintf(DEBUG, "setting empty child's %v/%d value\n", key, ln)
			}
		} else {
			oldval = node.data
			if replace {
				node.data = value
			} else {
				set = false // this is only time we don't set
			}
			if DEBUG != nil {
				fmt.Fprintf(DEBUG, "hit previously set %v/%d node\n", key, ln)
			}
		}
		return
	}
	newnode := &btrienode128{data: value, prefixlen: ln}
	copy(newnode.bits[:], key[:(ln+31)/32])
	if node != nil {
		if hasBit(key, node.prefixlen+1) {
			if node.a == nil {
				node.a = newnode
				if DEBUG != nil {
					fmt.Fprintf(DEBUG, "a-child %s for %s\n", keyStr(key, ln), keyStr(node.bits[:], node.prefixlen))
				}
				return
			}
			// newnode fits between node and node.a
			down = node.a
		} else {
			if node.b == nil {
				node.b = newnode
				if DEBUG != nil {
					fmt.Fprintf(DEBUG, "b-child %s for %s\n", keyStr(key, ln), keyStr(node.bits[:], node.prefixlen))
				}
				return
			}
			// newnode fits between node and node.b
			down = node.b
		}
	} else {
		// newnode goes in front of root node
		down = t.btrienode128
	}

	parent := node
	if parent != nil && parent.prefixlen >= ln {
		panic("parent's prefix could not be larger than key len")
	}

	matched := down.bitsMatched(key, ln)
	if matched > ln {
		matched = ln
	}

	if matched == ln { // matched >=ln to remove that if above
		// down matches key fully, so new branch would start from here
		var plen byte = 1
		if parent != nil {
			// also make sure we're not messed up branch direction
			plen = parent.prefixlen + 1
		}
		use_a := hasBit(newnode.bits[:], plen)
		if use_a != hasBit(down.bits[:], plen) {
			panic("something is wrong with branch that we intend to append to")
		}
		if use_a {
			newnode.a = down
		} else {
			newnode.b = down
		}
		if parent != nil {
			if hasBit(newnode.bits[:], plen) {
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
				if use_a {
					m = "a"
				}
				fmt.Fprintf(DEBUG, "root=%s (uses %s as %s-child)\n", keyStr(key, ln), keyStr(down.bits[:], down.prefixlen), m)
			}
			t.btrienode128 = newnode
		}
	} else {
		// down and newnode should have new empty parent
		node = &btrienode128{dummy: 1, prefixlen: matched}
		copy(node.bits[:], key[:(ln+31)/32])
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
			if hasBit(newnode.bits[:], parent.prefixlen+1) {
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
			t.btrienode128 = node
		}
	}
	return
}
