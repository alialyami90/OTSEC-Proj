package receive

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"strconv"
	"testing"
	"time"
)

func newFramer(b []byte, max int) *framer {
	return &framer{r: bufio.NewReader(bytes.NewReader(b)), max: max, deadline: func(time.Time) error { return nil },
		idle: time.Second, whole: time.Second, now: time.Now}
}

// readAll returns every frame until the stream ends, and the error that
// ended it.
func readAll(f *framer) ([]*frame, error) {
	var out []*frame
	for {
		fr, err := f.next()
		if fr != nil {
			out = append(out, fr)
		}
		if err != nil {
			return out, err
		}
	}
}

// TestFramerRoundTrip: messages framed either way, mixed on one stream,
// come back exactly, including messages that hold LF (octet-counted only)
// and a trailing CR (kept: it is the message's byte, not the framing's).
func TestFramerRoundTrip(t *testing.T) {
	want := []string{"<13>a", "<13>b\nwith LF", "<13>c\r", "<13>" + string(bytes.Repeat([]byte("d"), 2000)), "x"}
	var stream []byte
	for i, m := range want {
		if i%2 == 1 {
			stream = append(stream, strconv.Itoa(len(m))+" "+m...)
		} else {
			stream = append(stream, m+"\n"...)
		}
	}
	frames, err := readAll(newFramer(stream, 2048))
	if err != io.EOF {
		t.Fatalf("ended with %v", err)
	}
	if len(frames) != len(want) {
		t.Fatalf("%d frames", len(frames))
	}
	for i, fr := range frames {
		if string(fr.msg) != want[i] || len(fr.flags) != 0 {
			t.Errorf("frame %d: %q %v", i, fr.msg, fr.flags)
		}
	}
}

func TestFramerEdges(t *testing.T) {
	cases := []struct {
		name, in string
		frames   []string
		flags    [][]string
		err      error
	}{
		{"count then eof", "12", []string{"12"}, [][]string{{"frame-truncated"}}, io.EOF},
		{"count then lf", "12\n", []string{"12"}, [][]string{{"frame-invalid"}}, io.EOF},
		{"ten-digit count", "1234567890 x\n", []string{"12345678"}, [][]string{{"frame-invalid", "frame-truncated"}}, io.EOF},
		{"zero count is a line", "0 x\n", []string{"0 x"}, [][]string{nil}, io.EOF},
		{"line at eof", "<13>x", []string{"<13>x"}, [][]string{{"frame-truncated"}}, io.EOF},
		{"count at the limit", "8 12345678", []string{"12345678"}, [][]string{nil}, io.EOF},
		{"count over the limit", "9 123456789", []string{"12345678"}, [][]string{{"frame-truncated"}}, errOversized},
		{"line at the limit", "<1234567\n", []string{"<1234567"}, [][]string{nil}, io.EOF},
		{"digits then lf are a bad count", "12345678\n", []string{"12345678"}, [][]string{{"frame-invalid"}}, io.EOF},
		{"line over the limit", "<12345678\nok\n", []string{"<1234567", "ok"}, [][]string{{"frame-truncated"}, nil}, io.EOF},
		{"empty lines", "\n\n\nok\n", []string{"ok"}, [][]string{nil}, io.EOF},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			frames, err := readAll(newFramer([]byte(c.in), 8))
			if !errors.Is(err, c.err) {
				t.Errorf("ended with %v, want %v", err, c.err)
			}
			if len(frames) != len(c.frames) {
				t.Fatalf("%d frames, want %d", len(frames), len(c.frames))
			}
			for i, fr := range frames {
				if string(fr.msg) != c.frames[i] || !equal(fr.flags, c.flags[i]) {
					t.Errorf("frame %d: %q %v", i, fr.msg, fr.flags)
				}
			}
		})
	}
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// FuzzFramer: whatever bytes arrive, the framer ends, every frame is at most
// the limit, and every byte read is in a frame, in the framing, discarded
// and counted, or an empty line.
func FuzzFramer(f *testing.F) {
	f.Add([]byte("12 <13>abcdefgh<13>x\n\n999999999 y"))
	f.Add([]byte("1\n2 a\n3 abc12x\n"))
	f.Fuzz(func(t *testing.T, in []byte) {
		if len(in) > 1<<16 {
			return
		}
		fr := newFramer(in, 2048)
		frames, err := readAll(fr)
		if err == nil {
			t.Fatal("ended without an error")
		}
		var kept int64
		for _, x := range frames {
			if len(x.msg) == 0 || len(x.msg) > 2048 {
				t.Fatalf("frame of %d bytes", len(x.msg))
			}
			kept += int64(len(x.msg))
		}
		if kept+fr.discarded > int64(len(in)) {
			t.Fatalf("%d bytes kept and %d discarded from %d", kept, fr.discarded, len(in))
		}
		if errors.Is(err, io.EOF) {
			// The whole input was read: what is not kept or discarded is
			// framing (counts, spaces, line ends) and empty lines.
			framing := int64(len(in)) - kept - fr.discarded
			if framing < fr.empty {
				t.Fatalf("%d framing bytes for %d empty lines", framing, fr.empty)
			}
		}
	})
}
