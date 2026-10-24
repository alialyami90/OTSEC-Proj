package collectorwire

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"
)

func TestFrameRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	for _, body := range []string{`{}`, `{"a":1}`, string(bytes.Repeat([]byte("x"), 4096))} {
		if err := WriteFrame(&buf, []byte(body), 4096); err != nil {
			t.Fatal(err)
		}
	}
	for _, want := range []string{`{}`, `{"a":1}`, string(bytes.Repeat([]byte("x"), 4096))} {
		got, err := ReadFrame(&buf, 4096)
		if err != nil || string(got) != want {
			t.Fatalf("got %q, %v", got, err)
		}
	}
	if _, err := ReadFrame(&buf, 4096); err != io.EOF {
		t.Fatalf("end of stream: %v, want io.EOF", err)
	}
}

func TestWriteFrameRefusesOverLimit(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteFrame(&buf, make([]byte, 11), 10); !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("got %v", err)
	}
	if err := WriteFrame(&buf, nil, 10); !errors.Is(err, ErrEmptyFrame) {
		t.Fatalf("got %v", err)
	}
	if buf.Len() != 0 {
		t.Fatalf("%d bytes written for a refused frame", buf.Len())
	}
}

// headerOnly fails the test if anything past the 4-byte header is read.
type headerOnly struct {
	t   *testing.T
	hdr []byte
}

func (h *headerOnly) Read(p []byte) (int, error) {
	if len(h.hdr) == 0 {
		h.t.Fatal("body read after an over-limit header")
	}
	n := copy(p, h.hdr)
	h.hdr = h.hdr[n:]
	return n, nil
}

func TestReadFrameRefusesOverLimitBeforeReadingBody(t *testing.T) {
	for _, n := range []uint32{11, 1 << 31, ^uint32(0)} {
		hdr := binary.BigEndian.AppendUint32(nil, n)
		if _, err := ReadFrame(&headerOnly{t: t, hdr: hdr}, 10); !errors.Is(err, ErrFrameTooLarge) {
			t.Fatalf("length %d: got %v", n, err)
		}
	}
}

func TestReadFrameShort(t *testing.T) {
	cases := map[string]struct {
		in   []byte
		want error
	}{
		"empty frame":    {[]byte{0, 0, 0, 0}, ErrEmptyFrame},
		"partial header": {[]byte{0, 0}, io.ErrUnexpectedEOF},
		"no body":        {[]byte{0, 0, 0, 5}, io.ErrUnexpectedEOF},
		"short body":     {[]byte{0, 0, 0, 5, '{', '}'}, io.ErrUnexpectedEOF},
	}
	for name, c := range cases {
		if _, err := ReadFrame(bytes.NewReader(c.in), 100); !errors.Is(err, c.want) {
			t.Errorf("%s: got %v, want %v", name, err, c.want)
		}
	}
}

// FuzzReadFrame: whatever the peer sends, a frame is never longer than the
// limit, and a frame read back from WriteFrame is the frame written.
func FuzzReadFrame(f *testing.F) {
	f.Add([]byte{0, 0, 0, 2, '{', '}'})
	f.Add([]byte{0, 0, 0, 0})
	f.Add([]byte{0xff, 0xff, 0xff, 0xff, 1})
	f.Fuzz(func(t *testing.T, in []byte) {
		const max = 64
		body, err := ReadFrame(bytes.NewReader(in), max)
		if err != nil {
			return
		}
		if len(body) == 0 || len(body) > max {
			t.Fatalf("frame of %d bytes, limit %d", len(body), max)
		}
		var buf bytes.Buffer
		if err := WriteFrame(&buf, body, max); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(buf.Bytes(), in[:4+len(body)]) {
			t.Fatal("re-encoded frame differs")
		}
	})
}
