package iptrie

import (
	"bytes"
	"math/rand"
	"testing"
	"time"
	"unsafe"
)

func TestTrieInterface(t *testing.T) {
	var T = New32()
	a, _ := T.Append([]byte{1, 2, 3, 4}, 24, nil)
	if !a {
		t.Error("Unable to insert!")
	}
	b, _ := T.Append([]byte{1, 2, 3, 0}, 24, nil)
	if b {
		t.Error("Should not be possible to replace with append!")
	}
	exact, ip, ln, _ := T.Get([]byte{1, 2, 3, 5}, 32)
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

	var T = New32()
	for _, tst := range insert {
		T.Append(tst[:4], tst[4], nil)
	}

	exact, ip, ln, _ := T.Get([]byte{1, 2, 3, 5}, 32)
	if exact || ln != 24 || !bytes.Equal(ip, []byte{1, 2, 3, 0}) {
		t.Errorf("Expected to find 1.2.3/24 false but got: %v/%d %t", ip, ln, exact)
	}

	exact, ip, ln, _ = T.Get([]byte{1, 2, 5, 5}, 32)
	if exact || ln != 16 || !bytes.Equal(ip, []byte{1, 2, 0, 0}) {
		t.Errorf("Expected to find 1.2/16 but got: %v/%d", ip, ln)
	}

	exact, ip, ln, _ = T.Get([]byte{1, 3, 5, 5}, 32)
	if exact || ln != 8 || !bytes.Equal(ip, []byte{1, 0, 0, 0}) {
		t.Errorf("Expected to find 1/8 but got: %v/%d", ip, ln)
	}

	// Check exact matches
	// buf := bytes.NewBuffer(nil)
	// DEBUG = buf
	// defer func() { fmt.Fprintln(os.Stderr, buf.String()); DEBUG = nil }()
	exact, ip, ln, _ = T.Get([]byte{1, 2, 3, 0}, 24)
	if !exact || ln != 24 || !bytes.Equal(ip, []byte{1, 2, 3, 0}) {
		t.Errorf("Expected to find 1.2.3/24 but got: %v/%d", ip, ln)
	}

	// Check 2 levels up
	exact, ip, ln, _ = T.Get([]byte{1, 2, 0, 0}, 23)
	if exact || ln != 16 || !bytes.Equal(ip, []byte{1, 2, 0, 0}) {
		t.Errorf("Expected to find 1.2.0/16 but got: %v/%d", ip, ln)
	}

	// Check 0.0.0.0
	exact, ip, ln, _ = T.Get([]byte{0, 0, 0, 0}, 0)
	if exact {
		t.Errorf("Found 0/0 before it was added. Got: %v/%d", ip, ln)
	}

	T.Append([]byte{0, 0, 0, 0}, 0, nil)
	exact, ip, ln, _ = T.Get([]byte{0, 0, 0, 0}, 0)
	if !exact {
		t.Errorf("Expected to find 0.0.0/16 but got: %v/%d", ip, ln)
	}

	exact, ip, ln, _ = T.Get([]byte{100, 200, 0, 0}, 16)
	if exact || ln != 0 || len(ip) > 0 {
		t.Errorf("Expected to find 0.0.0/16 but got: %v/%d", ip, ln)
	}

}

func BenchmarkAppends(b *testing.B) {
	b.StopTimer()
	var addrs = make([][]byte, 0, b.N)
	var mask = make([]byte, 0, b.N)
	rand.Seed(int64(time.Now().Nanosecond()))
	for i := 0; i < b.N; i++ {
		u32 := rand.Uint32()
		addrs = append(addrs, []byte{byte(u32 >> 24), byte(u32 >> 16), byte(u32 >> 8), byte(u32)})
		mask = append(mask, byte((rand.Uint32()%24)+8))
	}

	b.StartTimer()
	var T = New32()
	var value = unsafe.Pointer(T) // does not matter where it points to
	for i := 0; i < b.N; i++ {
		T.Append(addrs[i], mask[i], value)
	}
}
