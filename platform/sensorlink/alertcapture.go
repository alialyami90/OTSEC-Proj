package sensorlink

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"otsec.local/otsec/contracts/netobs"
	c5 "otsec.local/otsec/contracts/store"
)

// CaptureFrame is one frame of a stored capture: its time, its stored
// bytes and its wire length.
type CaptureFrame struct {
	TS      time.Time
	Data    []byte
	WireLen int
}

// ParseCapture reads a capture in the stored form (C13 section 4.2), as
// buildPcap writes it, and refuses any other.
func ParseCapture(b []byte) ([]CaptureFrame, error) {
	le := binary.LittleEndian
	if len(b) < pcapHeaderBytes || le.Uint32(b) != pcapMagicNS || le.Uint16(b[4:]) != 2 || le.Uint16(b[6:]) != 4 ||
		le.Uint32(b[8:]) != 0 || le.Uint32(b[12:]) != 0 || le.Uint32(b[16:]) != netobs.MaxFrameBytes || le.Uint32(b[20:]) != linktypeEther {
		return nil, errors.New("sensorlink: not a capture in the stored form")
	}
	var out []CaptureFrame
	for p := pcapHeaderBytes; p < len(b); {
		if len(b)-p < pcapRecordBytes {
			return nil, errors.New("sensorlink: a capture record header is cut")
		}
		sec, ns, n, wire := le.Uint32(b[p:]), le.Uint32(b[p+4:]), int(le.Uint32(b[p+8:])), int(le.Uint32(b[p+12:]))
		p += pcapRecordBytes
		if ns >= 1e9 || n > netobs.MaxFrameBytes || n > len(b)-p || wire < n {
			return nil, fmt.Errorf("sensorlink: capture record %d is malformed", len(out)+1)
		}
		out = append(out, CaptureFrame{TS: time.Unix(int64(sec), int64(ns)).UTC(), Data: b[p : p+n], WireLen: wire})
		p += n
	}
	return out, nil
}

// BuildCapture writes frames, in order, in the stored form, which is the
// form of a first sight's capture, so an alert capture byte-identical to
// one is stored once (C13 section 7.1).
func BuildCapture(frames []CaptureFrame) (*c5.Capture, error) {
	pf := make([]pcapFrame, len(frames))
	for i, f := range frames {
		pf[i] = pcapFrame(f)
	}
	b, err := buildPcap(pf)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(b)
	return &c5.Capture{SHA256: hex.EncodeToString(sum[:]), Bytes: b}, nil
}
