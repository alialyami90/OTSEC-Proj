package sensorlink

import (
	"encoding/binary"
	"fmt"
	"math"
	"time"

	"otsec.local/otsec/contracts/netobs"
)

// The stored capture's form (C13 section 4.2): a classic pcap,
// little-endian, with nanosecond timestamps (magic a1b23c4d), version 2.4,
// snaplen MaxFrameBytes and LINKTYPE_ETHERNET (1). Each record carries the
// frame's own timestamp, its captured bytes and its wire length. The alert
// capture is built by the same function, so a byte-identical one is stored
// once (C13 section 7.1).
const (
	pcapMagicNS     = 0xa1b23c4d
	linktypeEther   = 1
	pcapHeaderBytes = 24
	pcapRecordBytes = 16
)

// pcapFrame is one frame to write.
type pcapFrame struct {
	TS      time.Time
	Data    []byte
	WireLen int
}

// buildPcap writes frames, in order, as one capture.
func buildPcap(frames []pcapFrame) ([]byte, error) {
	n := pcapHeaderBytes
	for _, f := range frames {
		n += pcapRecordBytes + len(f.Data)
	}
	if n > netobs.MaxCaptureBytes {
		return nil, fmt.Errorf("capture of %d bytes, above %d", n, netobs.MaxCaptureBytes)
	}
	b := make([]byte, 0, n)
	le := binary.LittleEndian
	b = le.AppendUint32(b, pcapMagicNS)
	b = le.AppendUint16(b, 2)
	b = le.AppendUint16(b, 4)
	b = le.AppendUint32(b, 0) // thiszone
	b = le.AppendUint32(b, 0) // sigfigs
	b = le.AppendUint32(b, netobs.MaxFrameBytes)
	b = le.AppendUint32(b, linktypeEther)
	for _, f := range frames {
		sec := f.TS.Unix()
		if sec < 0 || sec > 1<<32-1 {
			return nil, fmt.Errorf("frame time %s is outside the pcap range", f.TS.UTC().Format(time.RFC3339Nano))
		}
		if f.WireLen < len(f.Data) || uint64(f.WireLen) > math.MaxUint32 {
			// The uint32 would wrap and misstate the frame (D3 on #553).
			return nil, fmt.Errorf("frame wire length %d is below its %d captured bytes or above the pcap range", f.WireLen, len(f.Data))
		}
		b = le.AppendUint32(b, uint32(sec))
		b = le.AppendUint32(b, uint32(f.TS.Nanosecond()))
		b = le.AppendUint32(b, uint32(len(f.Data)))
		b = le.AppendUint32(b, uint32(f.WireLen))
		b = append(b, f.Data...)
	}
	return b, nil
}
