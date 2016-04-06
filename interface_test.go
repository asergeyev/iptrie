package iptrie

import (
	"bytes"
	"testing"
)

// TODO: needs real test

func TestTrieInterface(t *testing.T) {
	var T = NewTrie()
	a, _ := T.AppendIp4([]byte{1, 2, 3, 4}, 24, nil)
	if !a {
		t.Error("Unable to insert!")
	}
	b, _ := T.AppendIp4([]byte{1, 2, 3, 0}, 24, nil)
	if b {
		t.Error("Should not be possible to replace with append!")
	}
	a, ip, ln, _ := T.GetIp4([]byte{1, 2, 3, 5}, 24)
	if !a {
		t.Error("Unable to find previously inserted value!")
	}
	if ln != 24 || !bytes.Equal(ip, []byte{1, 2, 3, 0}) {
		t.Errorf("Expected to find 1.2.3/24 but got: %v/%d", ip, ln)
	}
}
