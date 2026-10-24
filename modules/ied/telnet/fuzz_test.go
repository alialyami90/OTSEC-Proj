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

// FuzzSend checks that whatever Send accepts is written unchanged, is one
// line of printable ASCII with one line end, and was passed to Egress
// without that line end.
func FuzzSend(f *testing.F) {
	f.Add([]byte("SER\r\n"))
	f.Add([]byte("SER\r\nSER D\r\n"))
	f.Add([]byte("QUI\r"))
	f.Fuzz(func(t *testing.T, line []byte) {
		var seen []byte
		c, fc := session(t, Config{Egress: func(b []byte) error { seen = append([]byte(nil), b...); return nil }})
		if err := c.Send(line); err != nil {
			if fc.wrote.Len() != 0 {
				t.Fatalf("refused %q but wrote %q", line, fc.wrote.Bytes())
			}
			return
		}
		w := fc.wrote.Bytes()
		if !bytes.Equal(w, line) || fc.writes != 1 {
			t.Fatalf("sent %q, wrote %q in %d writes", line, w, fc.writes)
		}
		text := bytes.TrimRight(w, "\r\n")
		if !bytes.Equal(text, seen) || len(text) == 0 || len(w)-len(text) > 2 {
			t.Fatalf("wrote %q, egress saw %q", w, seen)
		}
		for _, x := range text {
			if x < 0x20 || x > 0x7e {
				t.Fatalf("wrote %q", w)
			}
		}
		if end := string(w[len(text):]); end != "\r\n" && end != "\r" && end != "\n" {
			t.Fatalf("line end %q", end)
		}
	})
}
