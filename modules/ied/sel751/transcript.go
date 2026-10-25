package sel751

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"time"

	"otsec.local/otsec/contracts/adapter"
)

// recorder builds the C2 transcript. Each reply (the bytes received between
// two sends) is one received segment, and each line sent is one sent
// segment. The secret is never handed to it: the credential slot is recorded
// as the redaction marker, and an echo of the secret is replaced before the
// reply is stored (HR-3, C-A2-3).
type recorder struct {
	t adapter.Transcript
}

func stamp(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

// add appends b as one segment, or extends the last segment when it has the
// same direction and phase, and returns where b starts.
func (r *recorder) add(dir adapter.Direction, ph adapter.Phase, b []byte, at time.Time) int64 {
	off := int64(len(r.t.Data))
	r.t.Data = append(r.t.Data, b...)
	if n := len(r.t.Segments); n > 0 {
		if last := &r.t.Segments[n-1]; last.Dir == dir && last.Phase == ph {
			last.Length += int64(len(b))
			return off
		}
	}
	r.t.Segments = append(r.t.Segments, adapter.Segment{
		Offset: off, Length: int64(len(b)), Dir: dir, Phase: ph, At: stamp(at),
	})
	return off
}

// credential records the credential slot: the marker and CR LF.
func (r *recorder) credential(at time.Time) {
	off := r.add(adapter.Sent, adapter.PhaseAuth, []byte(adapter.RedactionMarker+"\r\n"), at)
	r.t.Redactions = append(r.t.Redactions, adapter.Redaction{
		Offset: off, Length: int64(len(adapter.RedactionMarker)),
		Reason: adapter.RedactCredential, Component: "transport",
	})
}

// received records a reply, with every echo span replaced by the marker.
// echoes are half-open [start, end) offsets into rx; overlapping or
// out-of-range spans are merged or ignored, so a faulty store can only
// redact more, never less.
func (r *recorder) received(ph adapter.Phase, rx []byte, echoes [][2]int, at time.Time) int64 {
	if len(echoes) == 0 {
		return r.add(adapter.Received, ph, rx, at)
	}
	sort.Slice(echoes, func(i, j int) bool { return echoes[i][0] < echoes[j][0] })
	var b bytes.Buffer
	var marks []int64 // offsets in b where a marker starts
	pos := 0
	for _, e := range echoes {
		s, end := max(e[0], pos), min(e[1], len(rx))
		if s >= end {
			continue // empty, out of range, or inside the previous echo
		}
		b.Write(rx[pos:s])
		marks = append(marks, int64(b.Len()))
		b.WriteString(adapter.RedactionMarker)
		pos = end
	}
	b.Write(rx[pos:])
	off := r.add(adapter.Received, ph, b.Bytes(), at)
	for _, m := range marks {
		r.t.Redactions = append(r.t.Redactions, adapter.Redaction{
			Offset: off + m, Length: int64(len(adapter.RedactionMarker)),
			Reason: adapter.RedactEcho, Component: "transport",
		})
	}
	return off
}

func (r *recorder) transcript() adapter.Transcript {
	t := r.t
	if t.Data == nil {
		t.Data = []byte{}
	}
	if t.Segments == nil {
		t.Segments = []adapter.Segment{}
	}
	if t.Redactions == nil {
		t.Redactions = []adapter.Redaction{}
	}
	sum := sha256.Sum256(t.Data)
	t.SHA256 = hex.EncodeToString(sum[:])
	return t
}
