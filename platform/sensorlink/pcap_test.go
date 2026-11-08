package sensorlink

import (
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

// goldenCaptureDigest is the SHA-256 of the capture below, computed outside
// Go (Python hashlib over the hand-written hex).
const goldenCaptureDigest = "e19d389d2ff491d87fa113aa8f52cb9d75c12c5f0432d2f06314301af1d47228"

// TestCaptureGolden pins the stored capture's bytes and digest (C13 section
// 4.2, section 14 item 11), so any writer of the same frames, such as the
// alert builder or D6's checker, can check its own against them. The
// expected bytes are written out by hand from section 4.2, not produced by
// buildPcap.
func TestCaptureGolden(t *testing.T) {
	ts := func(s string) time.Time {
		v, err := time.Parse(time.RFC3339Nano, s)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	got, err := buildPcap([]pcapFrame{
		{TS: ts("2026-11-07T10:00:00.000001Z"), Data: []byte{0x01, 0x02, 0x03, 0x04}, WireLen: 4},
		{TS: ts("2026-11-07T10:00:00.120001Z"), Data: []byte{0xaa, 0xbb}, WireLen: 2},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := strings.Join([]string{
		// File header: magic a1b23c4d, 2.4, thiszone 0, sigfigs 0,
		// snaplen 2048, link type 1.
		"4d3cb2a1", "0200", "0400", "00000000", "00000000", "00080000", "01000000",
		// Record 1: 1794045600 s (0x6aeef6a0), 1000 ns, incl 4, orig 4.
		"a0f6ee6a", "e8030000", "04000000", "04000000", "01020304",
		// Record 2: 1794045600 s, 120001000 ns (0x072711e8), incl 2, orig 2.
		"a0f6ee6a", "e8112707", "02000000", "02000000", "aabb",
	}, "")
	if hex.EncodeToString(got) != want {
		t.Fatalf("capture\n got %x\nwant %s", got, want)
	}
	if d := hashOf(got); d != goldenCaptureDigest {
		t.Fatalf("digest %s, want %s", d, goldenCaptureDigest)
	}
}
