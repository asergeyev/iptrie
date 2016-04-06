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
	exact, ip, ln, _ := T.GetIp4([]byte{1, 2, 3, 5}, 32)
	if exact || ln != 24 || !bytes.Equal(ip, []byte{1, 2, 3, 0}) {
		t.Errorf("Expected to find 1.2.3/24 but got: %v/%d", ip, ln)
	}
}

func TestTrieBestMatch(t *testing.T) {
	var insert = [][5]byte{
		{1, 0, 0, 0, 8},
		{1, 2, 0, 0, 16},
		{1, 2, 0, 0, 24},
		{1, 2, 1, 0, 24},
		{1, 2, 2, 0, 24},
		{1, 2, 3, 0, 24},
		{1, 2, 4, 0, 24},
	}

	var T = NewTrie()
	for _, tst := range insert {
		T.AppendIp4(tst[:4], tst[4], nil)
	}

	exact, ip, ln, _ := T.GetIp4([]byte{1, 2, 3, 5}, 32)
	if exact || ln != 24 || !bytes.Equal(ip, []byte{1, 2, 3, 0}) {
		t.Errorf("Expected to find 1.2.3/24 false but got: %v/%d %t", ip, ln, exact)
	}

	exact, ip, ln, _ = T.GetIp4([]byte{1, 2, 5, 5}, 32)
	if exact || ln != 16 || !bytes.Equal(ip, []byte{1, 2, 0, 0}) {
		t.Errorf("Expected to find 1.2/16 but got: %v/%d", ip, ln)
	}

	exact, ip, ln, _ = T.GetIp4([]byte{1, 3, 5, 5}, 32)
	if exact || ln != 8 || !bytes.Equal(ip, []byte{1, 0, 0, 0}) {
		t.Errorf("Expected to find 1/8 but got: %v/%d", ip, ln)
	}

	// Check exact matches
	// buf := bytes.NewBuffer(nil)
	// DEBUG = buf
	// defer func() { fmt.Fprintln(os.Stderr, buf.String()); DEBUG = nil }()
	exact, ip, ln, _ = T.GetIp4([]byte{1, 2, 3, 0}, 24)
	if !exact || ln != 24 || !bytes.Equal(ip, []byte{1, 2, 3, 0}) {
		t.Errorf("Expected to find 1.2.3/24 but got: %v/%d", ip, ln)
	}

	// Check 2 levels up
	exact, ip, ln, _ = T.GetIp4([]byte{1, 2, 0, 0}, 23)
	if exact || ln != 16 || !bytes.Equal(ip, []byte{1, 2, 0, 0}) {
		t.Errorf("Expected to find 1.2.0/16 but got: %v/%d", ip, ln)
	}
}
