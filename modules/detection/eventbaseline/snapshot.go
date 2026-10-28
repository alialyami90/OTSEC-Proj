package eventbaseline

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"slices"
	"sort"
	"time"

	"otsec.local/otsec/contracts/baseline"
	"otsec.local/otsec/contracts/event"
)

// MaxSnapshotBytes bounds a snapshot of either half. A snapshot above it is
// not made: Snapshot returns ErrSnapshotTooLarge and the caller keeps the
// previous one (and says so, because a restart then replays from that
// point or relearns). The package documentation, "Snapshot and Restore",
// gives the sizes this is chosen against.
const MaxSnapshotBytes = 8 << 20

// snapshotLimit is MaxSnapshotBytes; the tests lower it to reach the refusal
// without building 8 MiB of state.
var snapshotLimit = MaxSnapshotBytes

// snapshotVersion is the format. A snapshot of another version is refused
// (ErrSnapshotVersion), never read as best as it can be.
const snapshotVersion = 1

var snapshotMagic = [4]byte{'O', 'T', 'E', 'B'}

const (
	kindLearner  = 'L'
	kindDetector = 'D'
)

// Errors of Snapshot and the Restore functions. A restore that returns any
// of them returns no learner or detector: there is no partial state.
var (
	// ErrSnapshot: the bytes are not a snapshot this package can restore:
	// cut short, changed (the checksum), not of the half asked for, or not
	// consistent with themselves. ErrSnapshotVersion and ErrSnapshotMismatch
	// are refinements of it.
	ErrSnapshot = errors.New("eventbaseline: snapshot cannot be restored")
	// ErrSnapshotVersion: a format version, or a learner version, this
	// package does not read.
	ErrSnapshotVersion = fmt.Errorf("%w: unknown version", ErrSnapshot)
	// ErrSnapshotMismatch: the snapshot was made for another configuration
	// (other parameters, node, asset, baseline or activation time) than the
	// one it is being restored into.
	ErrSnapshotMismatch = fmt.Errorf("%w: made for another configuration", ErrSnapshot)
	// ErrSnapshotTooLarge: the state does not fit MaxSnapshotBytes.
	ErrSnapshotTooLarge = errors.New("eventbaseline: state does not fit MaxSnapshotBytes")
)

// snapW writes the format: unsigned and signed varints, and strings as a
// length and the bytes.
type snapW struct{ b []byte }

func (e *snapW) u(v uint64) { e.b = binary.AppendUvarint(e.b, v) }
func (e *snapW) i(v int64)  { e.b = binary.AppendVarint(e.b, v) }
func (e *snapW) s(v string) { e.u(uint64(len(v))); e.b = append(e.b, v...) }
func (e *snapW) bool(v bool) {
	if v {
		e.b = append(e.b, 1)
	} else {
		e.b = append(e.b, 0)
	}
}

// big is true once the state is known not to fit.
func (e *snapW) big() bool { return len(e.b) > snapshotLimit }

// seal puts the header before body and the checksum after it.
func seal(kind byte, parts ...[]byte) ([]byte, error) {
	h := append([]byte{}, snapshotMagic[:]...)
	h = binary.AppendUvarint(h, snapshotVersion)
	h = append(h, kind)
	n := len(h) + sha256.Size
	for _, p := range parts {
		n += len(p)
	}
	if n > snapshotLimit {
		return nil, fmt.Errorf("%w: %d bytes, above %d", ErrSnapshotTooLarge, n, snapshotLimit)
	}
	out := make([]byte, 0, n)
	out = append(out, h...)
	for _, p := range parts {
		out = append(out, p...)
	}
	sum := sha256.Sum256(out)
	return append(out, sum[:]...), nil
}

// snapR reads the format. The first fault sticks in err and every later read
// returns zero, so a decoder checks err where a value is used.
type snapR struct {
	b   []byte
	err error
}

func (d *snapR) fail(format string, a ...any) {
	if d.err == nil {
		d.err = fmt.Errorf("%w: "+format, append([]any{ErrSnapshot}, a...)...)
	}
}

func (d *snapR) u() uint64 {
	if d.err != nil {
		return 0
	}
	v, n := binary.Uvarint(d.b)
	if n <= 0 || n != uvarintLen(v) {
		d.fail("a number is cut short, too large or not in its shortest form")
		return 0
	}
	d.b = d.b[n:]
	return v
}

// uvarintLen is the bytes of v in the shortest form, the only one a snapshot
// holds, so that a snapshot has one encoding and Restore then Snapshot gives
// the bytes back.
func uvarintLen(v uint64) int { return len(binary.AppendUvarint(nil, v)) }

func (d *snapR) i() int64 {
	if d.err != nil {
		return 0
	}
	v, n := binary.Varint(d.b)
	if n <= 0 || n != uvarintLen(uint64(v<<1)^uint64(v>>63)) {
		d.fail("a number is cut short, too large or not in its shortest form")
		return 0
	}
	d.b = d.b[n:]
	return v
}

// nonNeg reads a count that is not negative.
func (d *snapR) nonNeg(what string) int64 {
	v := d.i()
	if v < 0 {
		d.fail("%s is %d", what, v)
		return 0
	}
	return v
}

func (d *snapR) bool() bool {
	if d.err != nil {
		return false
	}
	if len(d.b) == 0 || d.b[0] > 1 {
		d.fail("a flag is cut short or not 0 or 1")
		return false
	}
	v := d.b[0] == 1
	d.b = d.b[1:]
	return v
}

func (d *snapR) s(max int) string {
	n := d.u()
	if d.err != nil {
		return ""
	}
	if n > uint64(max) || n > uint64(len(d.b)) {
		d.fail("a string of %d bytes (at most %d, %d left)", n, max, len(d.b))
		return ""
	}
	v := string(d.b[:n])
	d.b = d.b[n:]
	return v
}

// n reads the number of elements of a list. Every element takes at least one
// byte, so a count above what is left is a fault, and nothing larger than
// the snapshot is ever allocated.
func (d *snapR) n(what string, max int) int {
	v := d.u()
	if d.err != nil {
		return 0
	}
	if v > uint64(max) || v > uint64(len(d.b)) {
		d.fail("%s: %d entries (at most %d, %d bytes left)", what, v, max, len(d.b))
		return 0
	}
	return int(v)
}

func (d *snapR) done() {
	if d.err == nil && len(d.b) != 0 {
		d.fail("%d bytes after the end", len(d.b))
	}
}

// open checks the header and the checksum of a snapshot of kind and returns
// a decoder at its body. The format version is read before the checksum,
// because another version may place the checksum elsewhere.
func open(snap []byte, kind byte) (*snapR, error) {
	if len(snap) > snapshotLimit {
		return nil, fmt.Errorf("%w: %d bytes, above %d", ErrSnapshot, len(snap), snapshotLimit)
	}
	if len(snap) < len(snapshotMagic)+2+sha256.Size || !bytes.Equal(snap[:len(snapshotMagic)], snapshotMagic[:]) {
		return nil, fmt.Errorf("%w: not a snapshot", ErrSnapshot)
	}
	v, n := binary.Uvarint(snap[len(snapshotMagic):])
	if n <= 0 {
		return nil, fmt.Errorf("%w: the version is cut short", ErrSnapshot)
	}
	if v != snapshotVersion {
		return nil, fmt.Errorf("%w: format version %d, this package reads %d", ErrSnapshotVersion, v, snapshotVersion)
	}
	body, sum := snap[:len(snap)-sha256.Size], snap[len(snap)-sha256.Size:]
	if got := sha256.Sum256(body); !bytes.Equal(got[:], sum) {
		return nil, fmt.Errorf("%w: the checksum does not match", ErrSnapshot)
	}
	d := &snapR{b: body[len(snapshotMagic)+n:]}
	if len(d.b) == 0 || d.b[0] != kind {
		return nil, fmt.Errorf("%w: it is a snapshot of the other half", ErrSnapshot)
	}
	d.b = d.b[1:]
	return d, nil
}

// match reads a string the snapshot holds for something the caller also
// states, and refuses the restore if they differ.
func (d *snapR) match(what, want string, max int) {
	if got := d.s(max); d.err == nil && got != want {
		d.err = fmt.Errorf("%w: %s differs", ErrSnapshotMismatch, what)
	}
}

type keyed struct {
	s string
	k baseline.Key
}

func sortedKeys[V any](m map[baseline.Key]V) []keyed {
	out := make([]keyed, 0, len(m))
	for k := range m {
		out = append(out, keyed{k.String(), k})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].s < out[j].s })
	return out
}

// readKey reads a key, which must come after prev in the canonical order,
// so no key appears twice.
func (d *snapR) key(prev string) (baseline.Key, string) {
	s := d.s(1024)
	if d.err != nil {
		return baseline.Key{}, ""
	}
	k, err := baseline.ParseKey(s)
	if err != nil {
		d.fail("%v", err)
		return baseline.Key{}, ""
	}
	if s <= prev {
		d.fail("key %q is not after %q: keys are in order, once each", s, prev)
	}
	return k, s
}

const maxText = 1024

// ---- Learner ----

func learnerIdentity(c LearnerConfig) (params []byte, err error) {
	return json.Marshal(c.Params)
}

// Snapshot is the learner's whole state as bytes: the same state gives the
// same bytes, and RestoreLearner of them gives a learner whose every later
// call gives what this one's would. It does not change the learner. A state
// above MaxSnapshotBytes is refused (ErrSnapshotTooLarge).
func (l *Learner) Snapshot() ([]byte, error) {
	params, err := learnerIdentity(l.cfg)
	if err != nil {
		return nil, err
	}
	var e snapW
	e.s(string(l.cfg.Node))
	e.s(l.cfg.AssetID)
	e.u(uint64(l.cfg.Version))
	e.s(l.cfg.Previous)
	e.i(int64(l.cfg.MaxBytes))
	e.s(LearnerName)
	e.s(LearnerVersion)
	e.s(string(params))

	e.bool(l.started)
	e.i(l.startNS)
	e.i(l.lastNS)
	e.i(l.events)
	e.i(l.full)
	e.i(l.typeOnly)
	e.i(l.notCnt)
	e.bool(l.overflowSaturated)

	why := make([]string, 0, len(l.excluded))
	for w := range l.excluded {
		why = append(why, string(w))
	}
	slices.Sort(why)
	e.u(uint64(len(why)))
	for _, w := range why {
		e.s(w)
		e.i(l.excluded[baseline.Exclusion(w)])
	}

	e.u(uint64(len(l.gaps)))
	for _, g := range l.gaps {
		e.s(g.FromUTC)
		e.s(g.ToUTC)
		e.s(g.Reason)
	}

	ov := sortedKeys(l.overflow)
	e.u(uint64(len(ov)))
	for _, k := range ov {
		e.s(k.s)
	}

	ts := sortedKeys(l.types)
	e.u(uint64(len(ts)))
	for _, k := range ts {
		ty := l.types[k.k]
		e.s(k.s)
		e.s(ty.text)
		e.i(ty.count)
		e.i(ty.full)
		for _, h := range ty.hours {
			e.i(h)
		}
		e.i(ty.first)
		e.i(ty.last)
		e.i(ty.maxWin)
		e.i(ty.bucket)
		e.i(ty.inBucket)
		e.i(ty.maxBucket)
		e.i(ty.gapMin)
		e.i(ty.gapMax)
		e.bool(ty.notPeriodic)
		e.bool(ty.haveFull)
		e.i(ty.lastFullNS)
		// The window is non-decreasing: the first stamp, then the steps.
		e.u(uint64(len(ty.win)))
		var prev int64
		for j, t := range ty.win {
			if j == 0 {
				e.i(t)
			} else {
				e.u(uint64(t - prev))
			}
			prev = t
		}
		if !ty.notPeriodic {
			gs := make([]int64, 0, len(ty.gaps))
			for g := range ty.gaps {
				gs = append(gs, g)
			}
			slices.Sort(gs)
			e.u(uint64(len(gs)))
			for _, g := range gs {
				e.i(g)
				e.i(ty.gaps[g])
			}
		}
		if e.big() {
			return nil, fmt.Errorf("%w: past %d bytes at the type %s", ErrSnapshotTooLarge, snapshotLimit, k.s)
		}
	}
	return seal(kindLearner, e.b)
}

// RestoreLearner builds the learner a snapshot was taken of. c is the
// configuration the learner is to run with; it must be the one the snapshot
// was made with (node, asset, version, previous, byte cap and every
// parameter), or the restore is refused with ErrSnapshotMismatch: a learner
// resumed under other parameters would record a baseline that is neither.
// The snapshot is checked whole before anything is returned, and any fault
// returns no learner.
func RestoreLearner(c LearnerConfig, snap []byte) (*Learner, error) {
	l, err := NewLearner(c)
	if err != nil {
		return nil, err
	}
	params, err := learnerIdentity(c)
	if err != nil {
		return nil, err
	}
	d, err := open(snap, kindLearner)
	if err != nil {
		return nil, err
	}
	d.match("the node", string(c.Node), 256)
	d.match("the asset", c.AssetID, 256)
	if v := d.u(); d.err == nil && v != uint64(c.Version) {
		d.err = fmt.Errorf("%w: the baseline version differs", ErrSnapshotMismatch)
	}
	d.match("the previous baseline", c.Previous, 256)
	if v := d.i(); d.err == nil && v != int64(c.MaxBytes) {
		d.err = fmt.Errorf("%w: the byte cap differs", ErrSnapshotMismatch)
	}
	if name := d.s(256); d.err == nil && name != LearnerName {
		d.err = fmt.Errorf("%w: learner %q, this is %q", ErrSnapshotVersion, name, LearnerName)
	}
	if v := d.s(256); d.err == nil && v != LearnerVersion {
		d.err = fmt.Errorf("%w: learner version %q, this is %q", ErrSnapshotVersion, v, LearnerVersion)
	}
	d.match("the parameters", string(params), 64<<10)

	l.started = d.bool()
	l.startNS, l.lastNS = d.i(), d.i()
	l.events, l.full = d.nonNeg("events"), d.nonNeg("full")
	l.typeOnly, l.notCnt = d.nonNeg("type_only"), d.nonNeg("not_counted")
	l.overflowSaturated = d.bool()
	if d.err == nil {
		switch {
		case l.events != l.full+l.typeOnly+l.notCnt:
			d.fail("%d events, but %d full, %d type-only and %d not counted", l.events, l.full, l.typeOnly, l.notCnt)
		case l.started != (l.events > 0):
			d.fail("started is %v with %d events", l.started, l.events)
		case l.started && l.lastNS < l.startNS:
			d.fail("the last event is before the first")
		}
	}

	prev := ""
	for n := d.n("excluded", 64); n > 0 && d.err == nil; n-- {
		w := d.s(64)
		if d.err == nil && (w == "" || w <= prev) {
			d.fail("exclusion %q is empty or out of order", w)
		}
		prev = w
		if cnt := d.nonNeg("an exclusion count"); d.err == nil && cnt > 0 {
			l.excluded[baseline.Exclusion(w)] = cnt
		} else if d.err == nil {
			d.fail("exclusion %q has no events", w)
		}
	}

	for n := d.n("gaps", snapshotLimit); n > 0 && d.err == nil; n-- {
		g := baseline.Gap{FromUTC: d.s(64), ToUTC: d.s(64), Reason: d.s(1024)}
		for _, s := range []string{g.FromUTC, g.ToUTC} {
			if _, err := time.Parse(time.RFC3339Nano, s); d.err == nil && err != nil {
				d.fail("gap time %q: %v", s, err)
			}
		}
		l.gaps = append(l.gaps, g)
	}

	prev = ""
	for n := d.n("overflow", baseline.MaxTypesCeiling); n > 0 && d.err == nil; n-- {
		k, s := d.key(prev)
		prev = s
		if d.err == nil {
			l.overflow[k] = struct{}{}
		}
	}

	prev = ""
	nTypes := d.n("types", baseline.MaxTypesCeiling)
	for ; nTypes > 0 && d.err == nil; nTypes-- {
		k, s := d.key(prev)
		prev = s
		ty := &learnt{key: k, text: d.s(maxText)}
		ty.count, ty.full = d.nonNeg("count"), d.nonNeg("full")
		var hours int64
		for h := range ty.hours {
			ty.hours[h] = d.nonNeg("an hour count")
			hours += ty.hours[h]
		}
		ty.first, ty.last = d.i(), d.i()
		ty.maxWin, ty.bucket, ty.inBucket, ty.maxBucket = d.nonNeg("max_per_window"), d.i(), d.nonNeg("in_bucket"), d.nonNeg("max_per_bucket")
		ty.gapMin, ty.gapMax = d.i(), d.i()
		ty.notPeriodic, ty.haveFull = d.bool(), d.bool()
		ty.lastFullNS = d.i()
		for j, nw := 0, d.n("window", windowCap); j < nw && d.err == nil; j++ {
			if j == 0 {
				ty.win = append(make([]int64, 0, nw), d.i())
				continue
			}
			step := d.u()
			at := ty.win[j-1] + int64(step)
			if d.err == nil && (step > math.MaxInt64 || at < ty.win[j-1]) {
				d.fail("a window step overflows")
			}
			ty.win = append(ty.win, at)
		}
		var gapSum int64
		if !ty.notPeriodic {
			ty.gaps = map[int64]int64{}
			var lo, hi, last int64
			ng := d.n("gaps", gapCap)
			for j := 0; j < ng && d.err == nil; j++ {
				g, c := d.i(), d.nonNeg("a gap count")
				if d.err == nil && (c == 0 || (j > 0 && g <= last)) {
					d.fail("gap %d is empty or out of order", g)
				}
				if j == 0 {
					lo = g
				}
				hi, last = g, g
				ty.gaps[g] = c
				gapSum += c
			}
			if d.err == nil && ng > 0 && (ty.gapMin != lo || ty.gapMax != hi) {
				d.fail("a type's smallest and largest gaps do not match its gaps")
			}
		}
		if d.err != nil {
			break
		}
		switch {
		case ty.count < ty.full, hours != ty.full:
			d.fail("type %s: count %d, full %d, hours %d", s, ty.count, ty.full, hours)
		case ty.haveFull != (ty.full > 0), (len(ty.win) > 0) != (ty.full > 0):
			d.fail("type %s: have_full is %v and the window holds %d, with %d full", s, ty.haveFull, len(ty.win), ty.full)
		case ty.first < l.startNS || ty.last > l.lastNS || ty.first > ty.last:
			d.fail("type %s: first and last are outside the period", s)
		case int64(len(ty.win)) > ty.maxWin, ty.maxWin > ty.full, ty.inBucket > ty.maxBucket, ty.maxBucket > ty.full:
			d.fail("type %s: the window or the bucket exceeds its maximum", s)
		case !ty.notPeriodic && ty.full > 0 && gapSum != ty.full-1:
			d.fail("type %s: %d gaps for %d full occurrences", s, gapSum, ty.full)
		case ty.haveFull && (ty.lastFullNS > ty.last || ty.lastFullNS < ty.first):
			d.fail("type %s: the last full occurrence is outside the type's range", s)
		}
		if len(ty.win) > 0 && ty.win[len(ty.win)-1] != ty.lastFullNS {
			d.fail("type %s: the window does not end at the last full occurrence", s)
		}
		l.types[k] = ty
	}
	d.done()
	if d.err == nil {
		var counted int64
		for _, ty := range l.types {
			counted += ty.count
		}
		switch {
		case counted > l.full+l.typeOnly, counted != l.full+l.typeOnly && len(l.types) < baseline.MaxTypesCeiling:
			d.fail("the types count %d events, the learner %d full and %d type-only", counted, l.full, l.typeOnly)
		case len(l.overflow) > 0 && len(l.types) < baseline.MaxTypesCeiling:
			d.fail("types were left out with only %d held", len(l.types))
		case l.overflowSaturated && len(l.overflow) < baseline.MaxTypesCeiling:
			d.fail("the left-out count is saturated at %d", len(l.overflow))
		}
	}
	if d.err != nil {
		return nil, d.err
	}
	return l, nil
}

// ---- Detector ----

// idTable gives each (node, stream) pair a number, in the order the pairs are
// first written, so an event ID is written as that number and its seq.
type idTable struct {
	at    map[[2]string]int
	pairs [][2]string
}

func (t *idTable) ref(e *snapW, id event.EventID) {
	k := [2]string{string(id.NodeID), string(id.Stream)}
	i, ok := t.at[k]
	if !ok {
		if t.at == nil {
			t.at = map[[2]string]int{}
		}
		i = len(t.pairs)
		t.at[k] = i
		t.pairs = append(t.pairs, k)
	}
	e.u(uint64(i))
	e.u(id.Seq)
}

func (t *idTable) refs(e *snapW, ids []event.EventID) {
	e.u(uint64(len(ids)))
	for _, id := range ids {
		t.ref(e, id)
	}
}

// Snapshot is the detector's whole state as bytes, bound to the baseline it
// watches (by its hash) and to its activation time. The same state gives the
// same bytes, and RestoreDetector of them gives a detector whose every later
// call gives what this one's would. It does not change the detector. A state
// above MaxSnapshotBytes is refused (ErrSnapshotTooLarge).
func (d *Detector) Snapshot() ([]byte, error) {
	var tab idTable
	var body, head snapW

	body.i(d.lastNS)
	body.bool(d.holdOpen)
	body.i(d.holdFrom)
	body.i(d.raised)
	body.i(d.held)

	ns := sortedKeys(d.newSeen)
	body.u(uint64(len(ns)))
	for _, k := range ns {
		body.s(k.s)
	}

	for i := range d.b.Types {
		w := d.types[d.b.Types[i].Key]
		body.u(uint64(len(w.recent)))
		for j, s := range w.recent {
			if j == 0 {
				body.i(s.ns)
			} else {
				body.u(uint64(s.ns - w.recent[j-1].ns))
			}
			tab.ref(&body, s.id)
		}
		body.i(w.bucket)
		body.i(w.inBucket)
		tab.refs(&body, w.ids)
		body.i(w.last)
		body.bool(w.absent)
		tab.refs(&body, w.notCounted)
		body.i(w.notCountedTotal)
		if body.big() {
			return nil, fmt.Errorf("%w: past %d bytes at the type %s", ErrSnapshotTooLarge, snapshotLimit, w.t.Key)
		}
	}

	type rp struct {
		s string
		p pair
	}
	ps := make([]rp, 0, len(d.pairs))
	for p := range d.pairs {
		ps = append(ps, rp{string(p.rule) + "\x00" + p.key.String(), p})
	}
	sort.Slice(ps, func(i, j int) bool { return ps[i].s < ps[j].s })
	body.u(uint64(len(ps)))
	for _, x := range ps {
		pd := d.pairs[x.p]
		body.s(string(x.p.rule))
		body.s(x.p.key.String())
		body.i(pd.lastAlarm)
		body.bool(pd.raisedOnce)
		body.i(pd.total)
		tab.refs(&body, pd.ids)
		if body.big() {
			return nil, fmt.Errorf("%w: past %d bytes in the held breaks", ErrSnapshotTooLarge, snapshotLimit)
		}
	}

	head.s(d.hash)
	head.s(d.b.AssetID)
	head.i(d.activeNS)
	head.u(uint64(len(d.b.Types)))
	head.u(uint64(len(tab.pairs)))
	for _, p := range tab.pairs {
		head.s(p[0])
		head.s(p[1])
	}
	return seal(kindDetector, head.b, body.b)
}

var knownRules = []baseline.Rule{baseline.RuleNewType, baseline.RuleRepeats, baseline.RuleRate, baseline.RuleTime, baseline.RuleAbsence}

// RestoreDetector builds the detector a snapshot was taken of. c is the
// configuration the detector runs with; its baseline hash, asset, number of
// types and activation time must be those the snapshot was made with, or the
// restore is refused with ErrSnapshotMismatch. The snapshot is checked whole
// before anything is returned, and any fault returns no detector.
func RestoreDetector(c DetectorConfig, snap []byte) (*Detector, error) {
	det, err := NewDetector(c)
	if err != nil {
		return nil, err
	}
	d, err := open(snap, kindDetector)
	if err != nil {
		return nil, err
	}
	d.match("the baseline hash", c.Hash, 256)
	d.match("the asset", c.Baseline.AssetID, 256)
	if v := d.i(); d.err == nil && v != c.ActiveFrom.UnixNano() {
		d.err = fmt.Errorf("%w: the activation time differs", ErrSnapshotMismatch)
	}
	if v := d.u(); d.err == nil && v != uint64(len(c.Baseline.Types)) {
		d.err = fmt.Errorf("%w: the baseline has %d types, the snapshot %d", ErrSnapshotMismatch, len(c.Baseline.Types), v)
	}
	var ids [][2]string
	for n := d.n("event ID table", snapshotLimit); n > 0 && d.err == nil; n-- {
		ids = append(ids, [2]string{d.s(256), d.s(256)})
	}
	idRef := func() event.EventID {
		i, seq := d.u(), d.u()
		if d.err != nil {
			return event.EventID{}
		}
		if i >= uint64(len(ids)) {
			d.fail("an event ID names stream %d of %d", i, len(ids))
			return event.EventID{}
		}
		id := event.EventID{NodeID: event.NodeID(ids[i][0]), Stream: event.Stream(ids[i][1]), Seq: seq}
		if !id.NodeID.Valid() || !id.Stream.Valid() || seq == 0 {
			d.fail("%q is not an event ID", id.String())
		}
		return id
	}
	idList := func(what string, max int) []event.EventID {
		var out []event.EventID
		for n := d.n(what, max); n > 0 && d.err == nil; n-- {
			out = append(out, idRef())
		}
		return out
	}

	p := det.p
	det.lastNS = d.i()
	det.holdOpen = d.bool()
	det.holdFrom, det.raised, det.held = d.i(), d.nonNeg("raised"), d.nonNeg("held")
	if d.err == nil {
		switch {
		case det.lastNS < det.activeNS:
			d.fail("the detector's time is before its activation")
		case !det.holdOpen && (det.raised != 0 || det.held != 0):
			d.fail("alarms counted with no hold open")
		case det.holdOpen && (det.raised > p.MaxAlarmsPerHold || det.holdFrom > det.lastNS):
			d.fail("the open hold is inconsistent")
		}
	}

	prev := ""
	for n := d.n("new types seen", baseline.MaxTypesCeiling*4); n > 0 && d.err == nil; n-- {
		k, s := d.key(prev)
		prev = s
		if d.err == nil {
			if _, known := det.types[k]; known {
				d.fail("%s is a type of the baseline, listed as a new one", s)
			}
			det.newSeen[k] = struct{}{}
		}
	}

	for i := range c.Baseline.Types {
		if d.err != nil {
			break
		}
		w := det.types[c.Baseline.Types[i].Key]
		w.recent = nil
		for j, n := 0, d.n("recent", int(p.RepeatsN)+1); j < n && d.err == nil; j++ {
			var ns int64
			if j == 0 {
				ns = d.i()
			} else {
				step := d.u()
				ns = w.recent[j-1].ns + int64(step)
				if d.err == nil && (step > math.MaxInt64 || ns < w.recent[j-1].ns) {
					d.fail("a step between recent occurrences overflows")
				}
			}
			w.recent = append(w.recent, stamp{ns, idRef()})
		}
		w.bucket, w.inBucket = d.i(), d.nonNeg("in_bucket")
		w.ids = idList("bucket events", baseline.MaxEventIDs)
		w.last = d.i()
		w.absent = d.bool()
		w.notCounted = idList("not counted", baseline.MaxEventIDs)
		w.notCountedTotal = d.nonNeg("not_counted_total")
		switch {
		case d.err != nil:
		case w.absent && w.t.Periodic == nil, int64(len(w.ids)) > w.inBucket, w.notCountedTotal < int64(len(w.notCounted)):
			d.fail("type %s: inconsistent counts", w.t.Key)
		}
	}

	var last [2]string
	for n := d.n("pairs", snapshotLimit); n > 0 && d.err == nil; n-- {
		rule := baseline.Rule(d.s(32))
		k, s := d.key("")
		if d.err == nil && !slices.Contains(knownRules, rule) {
			d.fail("%q is not a rule", rule)
		}
		if cur := [2]string{string(rule), s}; d.err == nil && last != ([2]string{}) && (cur[0] < last[0] || (cur[0] == last[0] && cur[1] <= last[1])) {
			d.fail("pairs are out of order")
		} else {
			last = cur
		}
		pd := &pending{lastAlarm: d.i(), raisedOnce: d.bool(), total: d.nonNeg("total")}
		pd.ids = idList("held events", baseline.MaxEventIDs)
		if d.err == nil && pd.total < int64(len(pd.ids)) {
			d.fail("a pair holds %d events but counts %d", len(pd.ids), pd.total)
		}
		if d.err == nil {
			det.pairs[pair{rule, k}] = pd
		}
	}
	d.done()
	if d.err != nil {
		return nil, d.err
	}
	return det, nil
}
