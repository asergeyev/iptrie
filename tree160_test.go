package iptrie

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"testing"
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
		{[]byte{1, 2, 4, 0}, 26, true, "found 1.2.0.0/16 for 1.2.4.0/26\\ncreated b-dummy 1.2.4.0/21 with 1.2.4.0/26 and 1.2.3.0/24\\ninsert b-child 1.2.4.0/21 to 1.2.0.0/16 before 1.2.3.0/24\\n"},
		{[]byte{1, 3, 0, 0}, 16, true, "created b-dummy 1.3.0.0/15 with 1.3.0.0/16 and 1.2.0.0/16\\nroot=1.3.0.0/15 (uses 1.3.0.0/16 as b-child)\\n"},
	},
}

func TestTreeAppend(t *testing.T) {
	T := new(tree160)
	for _, testcase := range testCases {
		buf := bytes.NewBuffer(nil)
		DEBUG = buf
		for _, s := range testcase {
			T.addRoute(iptou(s.key, s.ln), s.ln, nil, s.repl)
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
		for _, s := range testcase {
			exact, match, _ := T.findBestMatch(iptou(s.key, s.ln), s.ln)
			if !exact {
				t.Errorf("Incorrect match found for exact search, got %v key while looking for %v", match, s)
			}
			exact, match, _ = T.findBestMatch(iptou(s.key, s.ln), s.ln+1)
			if exact || match.prefixlen != s.ln {
				t.Errorf("Incorrect match found for not-exact search, got %v key while looking for %v", match, s)
			}
		}
	}
}

func TestNodeMatch(t *testing.T) {
	b := &btrienode160{
		bits:      [5]uint32{0x7f000000}, // 127.0.0.0/16
		prefixlen: 16,
	}
	for i := byte(0); i <= 32; i++ {
		// everyone inside 127.0.0.0/16 formed as 127.0.1.1/xx should match
		if i < 16 {
			if b.match([]uint32{0x7f000101}, i) {
				t.Error("127.0.0.0/16 shoud not match to 127.0.0.1/xx when xx  is", i)
			}
		} else {
			if !b.match([]uint32{0x7f000101}, i) {
				t.Error("127.0.0.0/16 does not match to 127.0.1.1/xx when xx  is", i)
			}
		}
	}

	if b.match([]uint32{0x7f010000}, 16) {
		t.Error("127.0.0.0/16 shoud not match to 127.1.0.0/16")
	}

}
