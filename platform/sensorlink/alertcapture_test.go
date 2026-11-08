package sensorlink

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// An alert's capture built from a first sight's frames, in order, is that
// first sight's capture byte for byte, so the store keeps it once, and
// ParseCapture reads back each frame's time, bytes and wire length. Desk.
func TestAlertCaptureRoundTrip(t *testing.T) {
	o := firstSight(1, "192.0.2.10", "192.0.2.20", "")
	first, err := firstSightCapture(o)
	if err != nil {
		t.Fatal(err)
	}
	frames, err := ParseCapture(first.Bytes)
	if err != nil || len(frames) != 2 {
		t.Fatalf("%d frames, %v", len(frames), err)
	}
	for i, f := range frames {
		if hashOf(f.Data) != o.Citation.Frames[i].SHA256 || f.WireLen != o.Citation.Frames[i].WireLen || f.TS.Format("2006-01-02T15:04:05.000000Z") != o.Frames[i].TS {
			t.Errorf("frame %d: %s, wire %d, at %s", i, hashOf(f.Data), f.WireLen, f.TS)
		}
	}
	again, err := BuildCapture(frames)
	if err != nil || again.SHA256 != first.SHA256 || !bytes.Equal(again.Bytes, first.Bytes) {
		t.Fatalf("rebuilt capture differs: %v", err)
	}
	if empty, err := BuildCapture(nil); err != nil || len(empty.Bytes) != pcapHeaderBytes {
		t.Fatalf("a capture of no frames: %v", err)
	}
}

// ParseCapture refuses a capture not in the stored form, and a record that
// is cut or malformed.
func TestParseCaptureRefuses(t *testing.T) {
	first, err := firstSightCapture(firstSight(1, "192.0.2.10", "192.0.2.20", ""))
	if err != nil {
		t.Fatal(err)
	}
	b := first.Bytes
	mod := func(at int, v uint32) []byte {
		c := bytes.Clone(b)
		binary.LittleEndian.PutUint32(c[at:], v)
		return c
	}
	for name, c := range map[string][]byte{
		"magic":       mod(0, 0xa1b2c3d4),
		"snaplen":     mod(16, 65535),
		"linktype":    mod(20, 0),
		"cut header":  b[:pcapHeaderBytes+4],
		"cut frame":   b[:len(b)-1],
		"ns":          mod(pcapHeaderBytes+4, 1e9),
		"wire < len":  mod(pcapHeaderBytes+12, 1),
		"short":       b[:8],
		"len too big": mod(pcapHeaderBytes+8, 1<<20),
	} {
		if _, err := ParseCapture(c); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
