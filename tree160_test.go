package iptrie

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"strings"
	"testing"
	"unsafe"
)

type testCaseElement struct {
	key    []byte
	ln     byte
	repl   bool
	result string
}

var testCases = [][]testCaseElement{
	{
		{[]byte{1, 2, 3, 0}, 24, true, "root=1.2.3.0/24 (no subtree)\\n"},
		{[]byte{1, 2, 3, 0}, 29, true, "found 1.2.3.0/24 for 1.2.3.0/29\\nb-child 1.2.3.0/29 for 1.2.3.0/24\\n"},
		{[]byte{1, 2, 0, 0}, 16, true, "root=1.2.0.0/16 (uses 1.2.3.0/24 as b-child)\\n"},
		{[]byte{1, 2, 3, 0}, 26, true, "found 1.2.0.0/16 for 1.2.3.0/26\\nfound 1.2.3.0/24 for 1.2.3.0/26\\ninsert b-child 1.2.3.0/26 to 1.2.3.0/24 before 1.2.3.0/29\\n"},
		{[]byte{1, 2, 4, 0}, 26, true, "found 1.2.0.0/16 for 1.2.4.0/26\\ncreated b-dummy 1.2.0.0/21 with 1.2.4.0/26 and 1.2.3.0/24\\ninsert b-child 1.2.0.0/21 to 1.2.0.0/16 before 1.2.3.0/24\\n"},
		{[]byte{1, 3, 0, 0}, 16, true, "created b-dummy 1.2.0.0/15 with 1.3.0.0/16 and 1.2.0.0/16\\nroot=1.2.0.0/15 (uses 1.3.0.0/16 as b-child)\\n"},
		{[]byte{1, 3, 0, 0}, 22, true, "dummy 1.2.0.0/15 for 1.3.0.0/22\\nfound 1.3.0.0/16 for 1.3.0.0/22\\nb-child 1.3.0.0/22 for 1.3.0.0/16\\n"},
		{[]byte{1, 3, 2, 0}, 24, true, "dummy 1.2.0.0/15 for 1.3.2.0/24\\nfound 1.3.0.0/16 for 1.3.2.0/24\\nfound 1.3.0.0/22 for 1.3.2.0/24\\na-child 1.3.2.0/24 for 1.3.0.0/22\\n"},
		{[]byte{1, 3, 4, 0}, 23, true, "dummy 1.2.0.0/15 for 1.3.4.0/23\\nfound 1.3.0.0/16 for 1.3.4.0/23\\ncreated b-dummy 1.3.0.0/21 with 1.3.4.0/23 and 1.3.0.0/22\\ninsert b-child 1.3.0.0/21 to 1.3.0.0/16 before 1.3.0.0/22\\n"},
		{[]byte{1, 3, 4, 128}, 25, true, "dummy 1.2.0.0/15 for 1.3.4.128/25\\nfound 1.3.0.0/16 for 1.3.4.128/25\\ndummy 1.3.0.0/21 for 1.3.4.128/25\\nfound 1.3.4.0/23 for 1.3.4.128/25\\nb-child 1.3.4.128/25 for 1.3.4.0/23\\n"},
	},
}

func TestTransforms(t *testing.T) {
	for _, testcase := range testCases {
		for _, s := range testcase {
			n := new(Node160)
			n.prefixlen = s.ln
			n.bits[0] = mkuint32(s.key, s.ln) // mask already entered correctly in tests above, no need to trim bits
			if want := binary.BigEndian.Uint32(s.key); n.bits[0] != want {
				t.Errorf("Expected %d as uint32 representation of %v/%d, got %d", want, s.key, s.ln, n.bits[0])
			}
			if got := n.IP(); !bytes.Equal(s.key, got) {
				t.Errorf("Expected %v and got %v converting IP back to bytes (mask=%d)", s.key, got, s.ln)
			}
		}
	}
}

func TestTreeAppend(t *testing.T) {
	var ptrs [100]uint64
	for i := range ptrs {
		ptrs[i] = uint64(i + 100)
	}
	T := new(Trie160)
	for _, testcase := range testCases {
		buf := bytes.NewBuffer(nil)
		DEBUG = buf
		for i, s := range testcase {
			T.addToNode(T.node, s.key, s.ln, unsafe.Pointer(&(ptrs[i])), s.repl)
			got := strings.Replace(buf.String(), "\n", "\\n", -1)
			if got != s.result {
				t.Error(got, "!=", s.result)
				fmt.Fprintln(os.Stderr, buf.String(), "\n")
			}
			buf.Reset()
		}
		DEBUG = nil
	}
	// should find exact and not-exact matches
	for _, testcase := range testCases {
		for i, s := range testcase {
			exact, match, _ := T.node.findBestMatch(s.key, s.ln)
			if !exact {
				t.Errorf("Incorrect match found for exact search, got %v key while looking for %v", match, s)
			}
			if match.data == nil {
				t.Errorf("Incorrect pointer found for exact search of %v/%d, got %v key while looking for %v", s.key, s.ln, match.data, unsafe.Pointer(uintptr(i+100)))
			} else if *(*uint64)(match.data) != ptrs[i] {
				t.Errorf("Incorrect value found for exact search of %v/%d, got %v key while looking for %v", s.key, s.ln, match.data, unsafe.Pointer(uintptr(i+100)))
			}
			exact, match, _ = T.node.findBestMatch(s.key, s.ln+1)
			if exact || match.prefixlen != s.ln {
				t.Errorf("Incorrect match found for not-exact search, got %v key while looking for %v", match, s)
			}
		}
	}
}

func TestNodeMatch(t *testing.T) {
	b := &Node160{
		bits:      [5]uint32{0x7f000000}, // 127.0.0.0/16
		prefixlen: 16,
	}
	for i := byte(0); i <= 32; i++ {
		// everyone inside 127.0.0.0/16 formed as 127.0.1.1/xx should match
		if i < 16 {
			if b.match([]byte{127, 0, 1, 1}, i) {
				t.Error("127.0.0.0/16 shoud not match to 127.0.0.1/xx when xx  is", i)
			}
		} else {
			if !b.match([]byte{127, 0, 1, 1}, i) {
				t.Error("127.0.0.0/16 does not match to 127.0.1.1/xx when xx  is", i)
			}
		}
	}

	if b.match([]byte{127, 1, 0, 0}, 16) {
		t.Error("127.0.0.0/16 shoud not match to 127.1.0.0/16")
	}

}

func TestNodeMatchLong(t *testing.T) {
	b := &Node160{
		bits:      [5]uint32{0x7f000000}, // 7f00::
		prefixlen: 48,
	}
	for i := byte(0); i <= 48; i++ {
		if b.match([]byte{127, 0, 1, 1, 0}, i) {
			t.Error("7f00:/48 shoud not match to 7f11/xx when xx is", i)
		}
	}

	if !b.match([]byte{127, 0, 0, 0, 0, 0}, 48) {
		t.Error("7f00:/48 should match 7f00:/48")
	}

}
