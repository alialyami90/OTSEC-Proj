package sel751

import (
	"bytes"
	"testing"

	"otsec.local/otsec/contracts/adapter"
)

// Each parser target checks, for any input: no panic, every span inside the
// message, and every value equal to the bytes its span names. A record span
// never holds a line end, STX or ETX (C6-A2).

const fuzzOff = 1000 // a message never starts the transcript

// framedText reports whether text could be what frame returns: a message
// never holds STX or ETX.
func framedText(text []byte) bool { return !bytes.ContainsAny(text, "\x02\x03") }

func inside(t *testing.T, m message, s adapter.Span) []byte {
	t.Helper()
	i := s.Offset - m.off
	if i < 0 || s.Length < 0 || i+s.Length > int64(len(m.text)) {
		t.Fatalf("span %+v outside a %d-byte message at %d", s, len(m.text), m.off)
	}
	return m.text[i : i+s.Length]
}

func noFraming(t *testing.T, b []byte) {
	t.Helper()
	if bytes.ContainsAny(b, "\r\n\x02\x03") {
		t.Fatalf("span bytes %q hold a line end or framing byte", b)
	}
}

func FuzzFrame(f *testing.F) {
	f.Add([]byte("ID\r\n\x02\"FID=X\",\"0000\"\r\n\x03="))
	f.Add([]byte("\x02a\x03\x02b\x03"))
	f.Fuzz(func(t *testing.T, rx []byte) {
		m, err := frame(rx, fuzzOff)
		if err != nil {
			return
		}
		if bytes.ContainsAny(m.text, "\x02\x03") {
			t.Fatalf("message %q holds STX or ETX", m.text)
		}
		i := m.off - fuzzOff
		if i < 1 || rx[i-1] != stx || int(i)+len(m.text) >= len(rx) || rx[int(i)+len(m.text)] != etx {
			t.Fatalf("message at %d is not between STX and ETX in %q", i, rx)
		}
	})
}

func FuzzParseID(f *testing.F) {
	f.Add([]byte("\"FID=SEL-751-R501-V0-Z104101-D20260910\",\"08AF\"\r\n\"CID=E754\",\"0262\"\r\n"))
	f.Add([]byte("\"FID=A\",\"0000\"\r\n\"FID=B\",\"0000\"\r\n"))
	f.Fuzz(func(t *testing.T, text []byte) {
		if !framedText(text) {
			return
		}
		m := message{text: text, off: fuzzOff}
		r, err := parseID(m)
		if err != nil {
			return
		}
		for _, fd := range r.fields {
			v := inside(t, m, fd.span)
			if string(v) != fd.value {
				t.Fatalf("%s: value %q, span bytes %q", fd.key, fd.value, v)
			}
			noFraming(t, v)
		}
	})
}

func FuzzParseSER(f *testing.F) {
	f.Add([]byte("\r\nSEL-751  Date: 10/24/2026  Time: 09:15:04.112\r\n\r\nSerial No = SIM1\r\n" +
		"FID = SEL-751-R501-V0-Z104101-D20260910     CID = E754\r\n\r\n" +
		"#    DATE       TIME           ELEMENT           STATE\r\n" +
		"1    10/24/2026 09:10:01.251   IN101             Deasserted\r\n\r\n"))
	f.Fuzz(func(t *testing.T, text []byte) {
		if !framedText(text) {
			return
		}
		m := message{text: text, off: fuzzOff}
		r, err := parseSER(m)
		if err != nil {
			return
		}
		if r.context.Length > 0 {
			inside(t, m, r.context)
		}
		for _, v := range []*serValue{r.serial, r.fid, r.cid} {
			if v != nil {
				if b := inside(t, m, v.span); string(b) != v.value {
					t.Fatalf("value %q, span bytes %q", v.value, b)
				}
			}
		}
		for _, row := range r.rows {
			b := inside(t, m, row.span)
			noFraming(t, b)
			if row.ok != (len(row.fields) == len(adapter.RecordFields["sel.ser.row"])) {
				t.Fatalf("row %q: ok %v with %d fields", b, row.ok, len(row.fields))
			}
			for _, fd := range row.fields {
				if !bytes.Contains(b, []byte(fd)) {
					t.Fatalf("field %q not in row %q", fd, b)
				}
			}
		}
	})
}

func FuzzParseSettings(f *testing.F) {
	f.Add([]byte("Port 1\r\n\r\nMAXACC  := 2\r\nLANG    := ENGLISH  FTPACC  := 1\r\n"))
	for _, l := range []string{"LANG := ENGLISH  trailing words", "xLANG := ENGLISH", "EN-LANG := ENGLISH", "TID := FEEDER  1"} {
		f.Add([]byte(l + "\r\n"))
	}
	f.Fuzz(func(t *testing.T, text []byte) {
		if !framedText(text) {
			return
		}
		m := message{text: text, off: fuzzOff}
		set, err := parseSettings(m)
		if err != nil {
			return
		}
		covered := make([]bool, len(m.text))
		for name, s := range set {
			b := inside(t, m, s.span)
			noFraming(t, b)
			if s.name != name || !bytes.HasPrefix(b, []byte(name)) || !bytes.HasSuffix(b, []byte(s.value)) || s.value == "" {
				t.Fatalf("setting %q = %q, span bytes %q", name, s.value, b)
			}
			for i := s.span.Offset - m.off; i < s.span.Offset-m.off+s.span.Length; i++ {
				covered[i] = true
			}
		}
		// A line that holds a ":=" is settings and spaces only (A6 on #85).
		for _, l := range m.lines() {
			if !bytes.Contains(l.b, []byte(":=")) {
				continue
			}
			for i, c := range l.b {
				if at := l.off - m.off + int64(i); !covered[at] && c != ' ' {
					t.Fatalf("line %q: byte %d (%q) is in no setting", l.b, i, c)
				}
			}
		}
	})
}
