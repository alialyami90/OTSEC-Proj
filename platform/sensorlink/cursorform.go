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
// C13 CH-18): "sp2" and 119 fields after it, space-separated, every
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
//	G and D at W's heartbeat (2)
//
// Every field is filled: W's causes and the gap held for the floor are
// the gap model's (INT-D5 2e-2, gap.go). W's causes are the causes of the
// gap open now, as bits of gapCauses, "-" when none is open; the gap held
// for the floor is six fields, all "-" or all filled: from and to (Unix
// nanoseconds, in either order, since a step back can put the end before
// the start), the cause at the open (a token of gapCauses), the causes
// (bits), the gaps it carries (at least 1), and its mark (1
// clock_stepped, 2 from_bound, 4 covered: a covered close waiting for its
// budget, D1's ruling on #788). W and its seq and at_utc, and G and D at
// its heartbeat (D1's ruling 8 on #788), are written together or not at
// all; the interface count is "-" when none is held, and its slots past
// the count "-". Its largest is 2,068 bytes as section 1.4 counts it,
// within MaxLinkCursorBytes by construction.
const (
	cursorFormTag    = "sp2"
	cursorFields     = 120
	cursorAbsent     = "-"
	cursorSpanFields = 4
)

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
	f = appendWatch(f, c)
	f = appendHeld(f, c.Held)
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
	if c.W.IsZero() {
		f = append(f, cursorAbsent, cursorAbsent)
	} else {
		dec(c.WG)
		dec(c.WD)
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
	if !readWatch(f, c) || !readHeld(f, c) {
		return nil, errCursorForm
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
	} else if !allAbsent(f[86:118]) {
		return nil, errCursorForm
	}
	// G and D at W's heartbeat, with W or not at all.
	switch {
	case allAbsent(f[118:120]) && c.W.IsZero():
	case c.W.IsZero() || !cursorDecimal.MatchString(f[118]) || !cursorDecimal.MatchString(f[119]):
		return nil, errCursorForm
	default:
		c.WG, c.WD = dec(118), dec(119)
		if bad {
			return nil, errCursorForm
		}
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

// appendWatch is W, its seq, its at_utc and its causes, R,
// the interface count and its 8 slots (fields 18 to 39). Every time is
// clamped to the field's range, as M is, so a sensor time out of it never
// stops a save.
func appendWatch(f []string, c *Cursor) []string {
	tm := func(t time.Time) string {
		if t.IsZero() {
			return cursorAbsent
		}
		return strconv.FormatInt(clampNano(t), 10)
	}
	if c.W.IsZero() {
		f = append(f, cursorAbsent, cursorAbsent, cursorAbsent)
	} else {
		f = append(f, tm(c.W), strconv.FormatUint(c.WSeq, 10), strconv.FormatInt(clampNano(c.WAtUTC), 10))
	}
	if c.Causes == 0 {
		f = append(f, cursorAbsent)
	} else {
		f = append(f, strconv.FormatUint(uint64(c.Causes), 10))
	}
	f = append(f, tm(c.R))
	if len(c.Ifaces) == 0 {
		f = append(f, cursorAbsent)
	} else {
		f = append(f, strconv.Itoa(len(c.Ifaces)))
	}
	for i := range netobs.MaxInterfaces {
		if i >= len(c.Ifaces) {
			f = append(f, cursorAbsent, cursorAbsent)
			continue
		}
		f = append(f, strconv.FormatUint(c.Ifaces[i].Packets, 10), strconv.FormatInt(clampNano(c.Ifaces[i].RiseUTC), 10))
	}
	return f
}

// readWatch reads fields 18 to 39 into c, false for any other form.
func readWatch(f []string, c *Cursor) bool {
	ok := true
	tm := func(i int) time.Time {
		if !cursorDecimal.MatchString(f[i]) {
			ok = false
			return time.Time{}
		}
		n, err := strconv.ParseInt(f[i], 10, 64)
		ok = ok && err == nil
		return time.Unix(0, n).UTC()
	}
	switch {
	case allAbsent(f[18:21]):
	case f[18] == cursorAbsent || f[19] == cursorAbsent || f[20] == cursorAbsent:
		return false
	default:
		c.W, c.WAtUTC = tm(18), tm(20)
		if !cursorDecimal.MatchString(f[19]) {
			return false
		}
		v, err := strconv.ParseUint(f[19], 10, 64)
		ok = ok && err == nil
		c.WSeq = v
	}
	if f[21] != cursorAbsent {
		v, good := causeBits(f[21])
		ok = ok && good
		c.Causes = v
	}
	if f[22] != cursorAbsent {
		c.R = tm(22)
	}
	n := 0
	if f[23] != cursorAbsent {
		var err error
		n, err = strconv.Atoi(f[23])
		if err != nil || n < 1 || n > netobs.MaxInterfaces || f[23] != strconv.Itoa(n) {
			return false
		}
	}
	for k := range netobs.MaxInterfaces {
		s := f[24+2*k : 26+2*k]
		if k >= n {
			ok = ok && allAbsent(s)
			continue
		}
		if !cursorDecimal.MatchString(s[0]) {
			return false
		}
		p, err := strconv.ParseUint(s[0], 10, 64)
		ok = ok && err == nil
		c.Ifaces = append(c.Ifaces, IfaceMark{Packets: p, RiseUTC: tm(25 + 2*k)})
	}
	return ok
}

// clampNano is t in Unix nanoseconds, clamped to 1970 to 2262 as M is.
func clampNano(t time.Time) int64 {
	switch {
	case t.Before(time.Unix(0, 0)):
		return 0
	case t.After(time.Unix(0, math.MaxInt64)):
		return math.MaxInt64
	}
	return t.UnixNano()
}

// appendHeld is the gap held for the floor (fields 40 to 45). The cause at
// its open is one character, its place in gapCauses, as section 1.4 gives
// it (D6's N5 on #781).
func appendHeld(f []string, g *HeldGap) []string {
	if g == nil {
		return append(f, cursorAbsent, cursorAbsent, cursorAbsent, cursorAbsent, cursorAbsent, cursorAbsent)
	}
	m := 0
	if g.Stepped {
		m |= 1
	}
	if g.Bound {
		m |= 2
	}
	if g.Covered {
		m |= 4
	}
	return append(f, strconv.FormatInt(clampNano(g.From), 10), strconv.FormatInt(clampNano(g.To), 10), causeCode(g.Cause),
		strconv.FormatUint(uint64(g.Causes), 10), strconv.FormatUint(g.Gaps, 10), strconv.Itoa(m))
}

// readHeld reads fields 40 to 45 into c, false for any other form.
func readHeld(f []string, c *Cursor) bool {
	s := f[40:46]
	if allAbsent(s) {
		return true
	}
	var t [2]time.Time
	for i := range 2 {
		if !cursorDecimal.MatchString(s[i]) {
			return false
		}
		n, err := strconv.ParseInt(s[i], 10, 64)
		if err != nil {
			return false
		}
		t[i] = time.Unix(0, n).UTC()
	}
	bits, ok := causeBits(s[3])
	cause, ok2 := causeOfCode(s[2])
	if !ok || !ok2 || !cursorDecimal.MatchString(s[4]) {
		return false
	}
	n, err := strconv.ParseUint(s[4], 10, 64)
	m, err2 := strconv.Atoi(s[5])
	if err != nil || n == 0 || err2 != nil || m < 0 || m > 7 || s[5] != strconv.Itoa(m) {
		return false
	}
	c.Held = &HeldGap{From: t[0], To: t[1], Cause: cause, Causes: bits, Gaps: n, Stepped: m&1 != 0, Bound: m&2 != 0, Covered: m&4 != 0}
	return true
}

// causeCode is cause's one-character code, its place in gapCauses.
func causeCode(cause string) string {
	for i, c := range gapCauses {
		if c == cause {
			return strconv.Itoa(i)
		}
	}
	return cursorAbsent // never a cause the model holds; read back as a bad form
}

// causeOfCode reads a cause's one-character code.
func causeOfCode(s string) (string, bool) {
	if len(s) != 1 || s[0] < '0' || int(s[0]-'0') >= len(gapCauses) {
		return "", false
	}
	return gapCauses[s[0]-'0'], true
}

// causeBits reads a set of causes, 1 to the full set.
func causeBits(s string) (uint16, bool) {
	if !cursorDecimal.MatchString(s) {
		return 0, false
	}
	v, err := strconv.ParseUint(s, 10, 16)
	if err != nil || v == 0 || v >= 1<<len(gapCauses) {
		return 0, false
	}
	return uint16(v), true
}
