package iptrie

import (
	"bytes"
	"math/rand"
	"os"
	"strings"
	"testing"
	"time"
	"unsafe"
)

func TestTrieInterface(t *testing.T) {
	var T = new(Trie32)
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

func TestTrieGetNode(t *testing.T) {
	var insert = [][5]byte{
		{1, 0, 0, 0, 8},
		{1, 2, 0, 0, 16},
		{1, 2, 0, 0, 24},
		{1, 2, 1, 0, 24},
		{1, 2, 2, 0, 24},
		{1, 2, 3, 0, 24},
		{1, 2, 4, 0, 24},
	}

	var T = new(Trie32)
	for _, tst := range insert {
		ok, node := T.GetNode(tst[:4], tst[4])
		if !ok {
			t.Error("Node was not added", tst[:4], tst[4])
		}
		if node == nil {
			t.Error("Node was not added (nil)", tst[:4], tst[4])
		}
	}
}

func TestTrieGetNodeV6(t *testing.T) {
	var insert = [][]byte{
		{1, 0, 0, 0, 32},
		{1, 2, 0, 0, 3, 7, 48},
	}

	var T = new(Trie128)
	for _, tst := range insert {
		ok, node := T.GetNode(tst[:len(tst)-1], tst[len(tst)-1])
		if !ok {
			t.Error("Node was not added", tst[:len(tst)-1], tst[len(tst)-1])
		}
		if node == nil {
			t.Error("Node was not added (nil)", tst[:len(tst)-1], tst[len(tst)-1])
		}
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

	var T = new(Trie32)
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

var MAXBENCH = 1500000 // realistic expectations
var addrs32 = make([][]byte, MAXBENCH)
var mask32 = make([]byte, MAXBENCH)
var addrs128 = make([][]byte, MAXBENCH)
var mask128 = make([]byte, MAXBENCH)

func init() {
	if strings.Contains(strings.Join(os.Args, " "), "-bench") {
		rand.Seed(int64(time.Now().Nanosecond()))
		for _ = range mask32 {
			u32 := rand.Uint32()
			mask32 = append(mask32, byte((rand.Uint32()%24)+8)) // 8 to 32
			//addrs32 = append(addrs32, utoip(iptou([]byte{byte(u32 >> 24), byte(u32 >> 16), byte(u32 >> 8), byte(u32)}, mask32[i]), mask32[i]))
			addrs32 = append(addrs32, []byte{byte(u32 >> 24), byte(u32 >> 16), byte(u32 >> 8), byte(u32)})
		}
		for _ = range mask128 {
			u32 := rand.Uint32()
			mask128 = append(mask128, byte((rand.Uint32()%32)+32)) // 32 to 64
			addrs128 = append(addrs128, []byte{
				0x20, byte(u32), byte(u32 >> 24), 0,
				byte(u32 >> 16), 0, byte(u32 >> 8), 0,
				byte(u32), byte(u32 >> 24), byte(u32 >> 16), byte(u32 >> 8),
				byte(u32), byte(u32 >> 8), byte(u32), 1,
			})
		}
	}
}

func BenchmarkAppend32(b *testing.B) {
	if b.N > MAXBENCH {
		b.N = MAXBENCH
	}
	var T = new(Trie32)
	var value = unsafe.Pointer(T) // does not matter where it points to
	for i := 0; i < b.N; i++ {
		T.Append(addrs32[i], mask32[i], value)
	}
	if testing.Verbose() && b.N == MAXBENCH {
		b.StopTimer()
		ts := time.Now()
		T.Root().Drill(0, func(l int, n *Node32) {
			if n == nil {
				panic("notok")
			}
			return
		})
		b.Log("Time to drill", b.N, "is", time.Since(ts))
	}
}

func BenchmarkAppend128(b *testing.B) {
	if b.N > MAXBENCH {
		b.N = MAXBENCH
	}
	var T = new(Trie128)
	var value = unsafe.Pointer(T) // does not matter where it points to
	for i := 0; i < b.N; i++ {
		T.Append(addrs128[i], mask128[i], value)
	}
}

func BenchmarkGet32(b *testing.B) {
	if b.N > MAXBENCH {
		b.N = MAXBENCH
	}
	var T = new(Trie32)
	for i := 0; i < b.N; i++ {
		T.Append(addrs32[i], mask32[i], unsafe.Pointer(T))
	}
	if testing.Verbose() {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			ex, ip, ln, value := T.Get(addrs32[i], mask32[i])
			if !ex {
				b.Error("Not exact get!", i, addrs32[i], mask32[i], ip, ln)
			} else if value == nil {
				b.Error("Incorrect get value!")
			}
		}
	} else {
		for i := 0; i < b.N; i++ {
			T.Get(addrs32[i], mask32[i])
		}
	}
	return
}

func BenchmarkGet128(b *testing.B) {
	if b.N > MAXBENCH {
		b.N = MAXBENCH
	}
	var T = new(Trie128)
	for i := 0; i < b.N; i++ {
		T.Append(addrs128[i], mask128[i], unsafe.Pointer(T))
	}
	if testing.Verbose() {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			ex, ip, ln, value := T.Get(addrs128[i], mask128[i])
			if !ex {
				b.Error("Not exact get!", i, addrs128[i], mask128[i], ip, ln)
			} else if value == nil {
				b.Error("Incorrect get value!")
			}
		}
	} else {
		for i := 0; i < b.N; i++ {
			T.Get(addrs128[i], mask128[i])
		}
	}
	return
}
