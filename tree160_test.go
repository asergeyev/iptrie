package iptrie

import (
	"bytes"
	"strings"
	"testing"
)

type testCaseElement struct {
	key    []byte
	ln     byte
	repl   bool
	result string
}

func (s *testCaseElement) getKey() []uint32 {
	key := make([]uint32, 0, (len(s.key)+3)/4)
	for i := 0; i < len(s.key); i += 4 {
		switch len(s.key) - i {
		case 1:
			key = append(key, uint32(s.key[i])<<24)
		case 2:
			key = append(key, uint32(s.key[i])<<24|uint32(s.key[i+1])<<16)
		case 3:
			key = append(key, uint32(s.key[i])<<24|uint32(s.key[i+1])<<16|uint32(s.key[i+2])<<8)
		default:
			key = append(key, uint32(s.key[i])<<24|uint32(s.key[i+1])<<16|uint32(s.key[i+2])<<8|uint32(s.key[i+3]))
		}
	}
	return key
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
			T.addRoute(s.getKey(), s.ln, nil, s.repl)
			got := strings.Replace(buf.String(), "\n", "\\n", -1)
			if got != s.result {
				t.Error(got, "!=", s.result)
			}
			buf.Reset()
		}
		DEBUG = nil
	}
	// should find exact and not-exact matches
	for _, testcase := range testCases {
		for _, s := range testcase {
			exact, match, _ := T.findBestMatch(s.getKey(), s.ln)
			if !exact {
				t.Errorf("Incorrect match found for exact search, got %v key while looking for %v", match, s.getKey())
			}
			exact, match, _ = T.findBestMatch(s.getKey(), s.ln+1)
			if exact || match.prefixlen != s.ln {
				t.Errorf("Incorrect match found for not-exact search, got %v key while looking for %v", match, s.getKey())
			}
		}
	}
}
