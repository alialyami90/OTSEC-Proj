package telnet

import (
	"bytes"
	"testing"
)

// FuzzRead feeds arbitrary peer bytes, cut into chunks at the given step, and
// checks what must hold for any input: no panic, data within the limit and
// never longer than the input, and nothing written but three-byte refusals,
// each option and verb at most once.
func FuzzRead(f *testing.F) {
	f.Add([]byte("SEL-751\r\n=\xff\xfb\x01\xff\xfd\x18x\xff\xff"), uint8(3))
	f.Add([]byte{cmdIAC, cmdSB, 24, 1, cmdIAC, cmdSE, '='}, uint8(1))
	f.Add([]byte{cmdIAC, cmdIAC, cmdIAC}, uint8(2))
	f.Fuzz(func(t *testing.T, in []byte, step uint8) {
		k := int(step%16) + 1
		var chunks [][]byte
		for i := 0; i < len(in); i += k {
			chunks = append(chunks, append([]byte(nil), in[i:min(i+k, len(in))]...))
		}
		c, fc := session(t, Config{MaxReceived: 512, MaxCommands: 32}, chunks...)
		got, _ := readAll(c)
		if int64(len(got)) > 512 || len(got) > len(in) || c.Received() != int64(len(got)) {
			t.Fatalf("returned %d bytes from %d, received %d", len(got), len(in), c.Received())
		}
		w := fc.wrote.Bytes()
		if len(w)%3 != 0 {
			t.Fatalf("wrote %x", w)
		}
		seen := map[[2]byte]bool{}
		for i := 0; i < len(w); i += 3 {
			r := w[i : i+3]
			if r[0] != cmdIAC || (r[1] != cmdWONT && r[1] != cmdDONT) || seen[[2]byte{r[1], r[2]}] {
				t.Fatalf("wrote %x", w)
			}
			seen[[2]byte{r[1], r[2]}] = true
		}
		if c.Stats().Refusals*3 != len(w) || bytes.Count(w, []byte{cmdIAC}) < c.Stats().Refusals {
			t.Fatalf("stats %+v for writes %x", c.Stats(), w)
		}
	})
}
