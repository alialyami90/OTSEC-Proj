package sensorlink

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"

	"otsec.local/otsec/contracts/netobs"
)

// The cursor's stored form (docs/phase4/D5-sensor-node.md section 1.4;
// C13 CH-18): "sp2" and 117 fields after it, space-separated, every
// decimal and every time (Unix nanoseconds) at most 20 digits, the digest
// at most 71 characters, and "-" for an absent field. In order:
//
//	the position: generation, run counter, run_id, T, G, D, the run's
//	  refused and dropped totals (8)
//	write_no, the digest, Ds, newest_seq (4)
//	the heartbeat baselines: frames_outgoing, drops_holder,
//	  frames_overlong, drops_driver, the egress mark (5)
//	W with its seq, at_utc and causes (4)
//	R, the interface count, and 8 x (packets, last rise) (18)
//	the gap held for the floor: from, to, cause at open, causes, gaps
//	  carried, mark (6)
//	M (1)
//	the span count, and 8 x (from, to, cut end, mark) (33)
//	prior: runs_skipped, records_lost, previous_end (c or u), started_by,
//	  owed mark, span count (6), and 8 x (from, to, cut end, mark) (32)
//
// This build fills the position, write_no, the digest, Ds, newest_seq, the
// heartbeat baselines (section 1.8), M (section 1.5), the spans and prior.
// W, R and the gap held for the floor are the gap model's: they are
// written "-", and a cursor that carries any of them is refused, so a
// later build's cursor is never read as this one's. Its largest is 2,026 bytes (section 1.4), within
// MaxLinkCursorBytes by construction.
const (
	cursorFormTag    = "sp2"
	cursorFields     = 118
	cursorAbsent     = "-"
	cursorSpanFields = 4
)

// The reserved fields this build writes "-": their first index and count.
var cursorReserved = [][2]int{{18, 4}, {22, 18}, {40, 6}}

// The egress mark (section 1.8): whether the run's baseline heartbeat
// carried egress_check, "-" when no baseline is held.
const (
	EgressCarried = "1"
	EgressOmitted = "0"
)

var cursorDecimal = regexp.MustCompile(`^(0|[1-9][0-9]{0,19})$`)

// cursorDigest is the digest's one form, C13's config_digest: 71
// characters. An absent digest is "-", never empty (D3's N1, D6's N2 on
// #742).
var cursorDigest = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// cursorEncodeFault is a test seam: nil in the node.
var cursorEncodeFault func(*Cursor) error

// encodeCursor is the cursor's stored form. It fails only for a time that
// Unix nanoseconds cannot hold (before 1970 or after 2262), which closes
// the connection position-not-saved, and never above MaxLinkCursorBytes.
func encodeCursor(c *Cursor) ([]byte, error) {
	if cursorEncodeFault != nil {
		if err := cursorEncodeFault(c); err != nil {
			return nil, err
		}
	}
	f := make([]string, 0, cursorFields)
	dec := func(v uint64) { f = append(f, strconv.FormatUint(v, 10)) }
	f = append(f, cursorFormTag)
	dec(c.Generation)
	dec(c.RunCounter)
	f = append(f, c.RunID)
	for _, v := range []uint64{c.Taken, c.G, c.D, c.Refused, c.Dropped} {
		dec(v)
	}
	digest := c.Digest
	if digest == "" {
		digest = cursorAbsent
	}
	dec(c.WriteNo)
	f = append(f, digest)
	dec(c.Ds)
	dec(c.NewestSeq)
	for _, v := range []*uint64{c.FramesOutgoing, c.DropsHolder, c.FramesOverlong, c.DropsDriver} {
		if v == nil {
			f = append(f, cursorAbsent)
		} else {
			dec(*v)
		}
	}
	switch c.Egress {
	case "":
		f = append(f, cursorAbsent)
	case EgressCarried, EgressOmitted:
		f = append(f, c.Egress)
	default:
		return nil, fmt.Errorf("sensorlink: the egress mark %q cannot be saved", c.Egress)
	}
	for range 4 + 18 + 6 { // W, R, the gap held: the gap model's
		f = append(f, cursorAbsent)
	}
	if c.M.IsZero() {
		f = append(f, cursorAbsent)
	} else {
		n, err := mNano(c.M)
		if err != nil {
			return nil, err
		}
		f = append(f, strconv.FormatInt(n, 10))
	}
	var err error
	if f, err = appendSpans(f, c.Spans); err != nil {
		return nil, err
	}
	if p := c.Prior; p == nil {
		for range 6 + netobs.MaxLostSpans*cursorSpanFields {
			f = append(f, cursorAbsent)
		}
	} else {
		end, ok := map[string]string{"clean": "c", "unclean": "u"}[p.PreviousEnd]
		if !ok || !validStartedBy(p.StartedBy) {
			return nil, fmt.Errorf("sensorlink: prior %q, %q cannot be saved", p.PreviousEnd, p.StartedBy)
		}
		dec(p.RunsSkipped)
		dec(p.RecordsLost)
		f = append(f, end, p.StartedBy, mark01(p.Owed))
		if f, err = appendSpans(f, p.Spans); err != nil {
			return nil, err
		}
	}
	// What the decoder refuses is refused here too, so a cursor saved is
	// one the next start reads (D6's N2 on #742).
	if !netobs.ValidUUID(c.RunID) || (c.Digest != "" && !cursorDigest.MatchString(c.Digest)) || len(f) != cursorFields {
		return nil, fmt.Errorf("sensorlink: a cursor of run %q cannot be saved", c.RunID)
	}
	b := []byte(strings.Join(f, " "))
	if err := checkCursorBytes(b); err != nil {
		return nil, err
	}
	return b, nil
}

// appendSpans is the span count and 8 slots, those past the count "-".
func appendSpans(f []string, spans []HeldSpan) ([]string, error) {
	if len(spans) > netobs.MaxLostSpans {
		return nil, fmt.Errorf("sensorlink: %d spans, above %d", len(spans), netobs.MaxLostSpans)
	}
	f = append(f, strconv.Itoa(len(spans)))
	for i := range netobs.MaxLostSpans {
		if i >= len(spans) {
			f = append(f, cursorAbsent, cursorAbsent, cursorAbsent, cursorAbsent)
			continue
		}
		s := spans[i]
		var t [3]int64
		for j, v := range []string{s.FromUTC, s.ToUTC, s.CutUTC} {
			n, err := unixNano(v)
			if err != nil {
				return nil, err
			}
			t[j] = n
			f = append(f, strconv.FormatInt(n, 10))
		}
		if !spanOrdered(t) {
			return nil, fmt.Errorf("sensorlink: a span from %s to %s cut at %s cannot be saved", s.FromUTC, s.ToUTC, s.CutUTC)
		}
		m := 0
		if s.Owed {
			m |= 1
		}
		if s.Marked {
			m |= 2
		}
		f = append(f, strconv.Itoa(m))
	}
	return f, nil
}

func unixNano(s string) (int64, error) {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil || t.Before(time.Unix(0, 0)) || t.After(time.Unix(0, math.MaxInt64)) {
		return 0, fmt.Errorf("sensorlink: the time %q cannot be saved in Unix nanoseconds", s)
	}
	return t.UnixNano(), nil
}

// mNoClamp: the control of M's clamp, a node that writes M unclamped and
// fails the save past the field's range. False in the node.
var mNoClamp bool

// mNano is M in Unix nanoseconds, clamped to the field's range, 1970 to
// 2262 (D1's ruling on D3's B2 on #748, option (a)): a later M is written
// as the largest, an earlier one as 0. The floor in memory is not
// clamped, so a floor past 2262 still refuses every tie, and after a
// start an M of 2262 does.
func mNano(m time.Time) (int64, error) {
	switch {
	case mNoClamp:
		return unixNano(canonUTC(m))
	case m.Before(time.Unix(0, 0)):
		return 0, nil
	case m.After(time.Unix(0, math.MaxInt64)):
		return math.MaxInt64, nil
	}
	return m.UnixNano(), nil
}

// spanOrdered is CH-40's from at or before to, and a cut end never past
// to (cutEnd); a cut end before from is a window cut to nothing (D3's N1
// on #742).
func spanOrdered(t [3]int64) bool { return t[0] <= t[1] && t[2] <= t[1] }

func mark01(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

// validStartedBy is C13's four values of prior.started_by.
func validStartedBy(s string) bool {
	switch s {
	case "agent", "capture", "engine", "enrolment":
		return true
	}
	return false
}

var errCursorForm = errors.New("sensorlink: the cursor is not section 1.4's form")

// decodeCursor reads the stored form strictly: any other form, a field out
// of its range, or a field this build does not fill, is refused, and the
// intake closes state-unread (CH-18).
func decodeCursor(b []byte) (*Cursor, error) {
	if len(b) > MaxLinkCursorBytes || bytes.ContainsAny(b, "\t\r\n") {
		return nil, errCursorForm
	}
	f := strings.Split(string(b), " ")
	if len(f) != cursorFields || f[0] != cursorFormTag {
		return nil, errCursorForm
	}
	for _, r := range cursorReserved {
		for i := r[0]; i < r[0]+r[1]; i++ {
			if f[i] != cursorAbsent {
				return nil, fmt.Errorf("%w: field %d is filled, which this build does not read", errCursorForm, i)
			}
		}
	}
	bad := false
	dec := func(i int) uint64 {
		if !cursorDecimal.MatchString(f[i]) {
			bad = true
			return 0
		}
		v, err := strconv.ParseUint(f[i], 10, 64)
		bad = bad || err != nil
		return v
	}
	c := &Cursor{Generation: dec(1), RunCounter: dec(2), RunID: f[3], Taken: dec(4), G: dec(5), D: dec(6),
		Refused: dec(7), Dropped: dec(8), WriteNo: dec(9), Ds: dec(11), NewestSeq: dec(12)}
	for i, p := range []**uint64{&c.FramesOutgoing, &c.DropsHolder, &c.FramesOverlong, &c.DropsDriver} {
		if f[13+i] != cursorAbsent {
			v := dec(13 + i)
			*p = &v
		}
	}
	switch f[17] {
	case cursorAbsent:
	case EgressCarried, EgressOmitted:
		c.Egress = f[17]
	default:
		bad = true
	}
	if f[10] != cursorAbsent {
		c.Digest = f[10]
		bad = bad || !cursorDigest.MatchString(c.Digest)
	}
	if f[46] != cursorAbsent {
		if !cursorDecimal.MatchString(f[46]) {
			return nil, errCursorForm
		}
		n, err := strconv.ParseInt(f[46], 10, 64)
		if err != nil {
			return nil, errCursorForm
		}
		c.M = time.Unix(0, n).UTC()
	}
	if bad || !netobs.ValidUUID(c.RunID) {
		return nil, errCursorForm
	}
	var err error
	if c.Spans, err = readSpans(f, 47); err != nil {
		return nil, err
	}
	if f[80] != cursorAbsent || !allAbsent(f[81:86]) {
		end, ok := map[string]string{"c": "clean", "u": "unclean"}[f[82]]
		owed, ok2 := map[string]bool{"0": false, "1": true}[f[84]]
		p := &HeldPrior{RunsSkipped: dec(80), RecordsLost: dec(81), PreviousEnd: end, StartedBy: f[83], Owed: owed}
		if bad || !ok || !ok2 || !validStartedBy(p.StartedBy) {
			return nil, errCursorForm
		}
		if p.Spans, err = readSpans(f, 85); err != nil {
			return nil, err
		}
		c.Prior = p
	} else if !allAbsent(f[86:]) {
		return nil, errCursorForm
	}
	return c, nil
}

// readSpans reads the span count at i and its 8 slots.
func readSpans(f []string, i int) ([]HeldSpan, error) {
	n, err := strconv.Atoi(f[i])
	if err != nil || n < 0 || n > netobs.MaxLostSpans || f[i] != strconv.Itoa(n) {
		return nil, errCursorForm
	}
	var out []HeldSpan // nil when none, as admit gives, so a repeat is the same Owed byte for byte
	for k := range netobs.MaxLostSpans {
		s := f[i+1+k*cursorSpanFields : i+1+(k+1)*cursorSpanFields]
		if k >= n {
			if !allAbsent(s) {
				return nil, errCursorForm
			}
			continue
		}
		var t [3]string
		var v [3]int64
		for j := range 3 {
			if !cursorDecimal.MatchString(s[j]) {
				return nil, errCursorForm
			}
			if v[j], err = strconv.ParseInt(s[j], 10, 64); err != nil {
				return nil, errCursorForm
			}
			t[j] = canonUTC(time.Unix(0, v[j]))
		}
		if !spanOrdered(v) {
			return nil, errCursorForm
		}
		m, err := strconv.Atoi(s[3])
		if err != nil || m < 0 || m > 3 || s[3] != strconv.Itoa(m) {
			return nil, errCursorForm
		}
		out = append(out, HeldSpan{FromUTC: t[0], ToUTC: t[1], CutUTC: t[2], Owed: m&1 != 0, Marked: m&2 != 0})
	}
	return out, nil
}

func allAbsent(s []string) bool {
	for _, v := range s {
		if v != cursorAbsent {
			return false
		}
	}
	return true
}
