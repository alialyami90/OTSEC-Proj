package node

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
	"time"

	"otsec.local/otsec/contracts/event"
	"otsec.local/otsec/contracts/netobs"
	c5 "otsec.local/otsec/contracts/store"
	"otsec.local/otsec/platform/store"
)

// The durable counts of refused stored observations (C4 0.6 step 2, S2-bc;
// docs/phase4/D5-refusal-alarms-options.md section 2.4, option B, and
// section 5; docs/phase4/D4-c4-0.6-proposal.md sections 2.1 to 2.3 and 4).
// The counts by reason are written as one detector.observation-refused
// event before the detector checkpoint that follows a change, carrying
// that checkpoint's Through as through. While an event is owed no
// checkpoint is stored, up to RefusedCountsWait; past it the checkpoint is
// stored without it and AlarmRefusedCountsUnwritten is raised. A start
// reads the newest event back: a replay counts a refusal only above its
// through (the seq rule), and an event whose through U is above the
// restored checkpoint's Through T marks the counts not exact over T+1 to U
// in the unsure detail, durably, until the counts begin again.

// AlarmRefusedCountsUnwritten: the owed counts event was not written within
// RefusedCountsWait, so the detector's checkpoint was stored without it.
// Raised at the first forced checkpoint, again at most once an hour while
// the event is still owed, and at the stop while it is.
const AlarmRefusedCountsUnwritten = "network-refused-counts-unwritten"

// RefusedCountsWait bounds how long an owed counts event holds back the
// detector's checkpoint, from when it first became owed (section 2.4).
// RefusedCountsPerHour is the counts event's own budget, outside the pool
// (section 5).
const (
	RefusedCountsWait    = time.Hour
	RefusedCountsPerHour = 4
)

// refusedCountsScan is how far back a start reads platform/health for the
// newest counts event, as for the drop counts.
const refusedCountsScan = sensorDropScanRecords

// refusedReason is one reason's count since since, and the lowest and
// highest seq it counted.
type refusedReason struct{ n, first, last uint64 }

// refusedRange is the seq range a to b; the zero range is none.
type refusedRange struct{ a, b uint64 }

func (s refusedRange) set() bool { return s.b != 0 }

func (s refusedRange) String() string { return fmt.Sprintf("%d-%d", s.a, s.b) }

// union is the one range from the lower start to the higher end.
func (s refusedRange) union(o refusedRange) refusedRange {
	switch {
	case !s.set():
		return o
	case !o.set():
		return s
	}
	return refusedRange{min(s.a, o.a), max(s.b, o.b)}
}

// refusedCounts is the detector's durable counts and what is owed of them.
// It lives in memory, and nothing of it is kept across a restart but the
// events written: an owed event is built when it is written (C4 0.6
// section 2.3).
type refusedCounts struct {
	since time.Time
	// by are the counts now, and written those of the newest counts event.
	by, written map[string]refusedReason
	// through is U, the newest counts event's through: a refusal at or
	// below it is in that event, and the next event is written no lower.
	through uint64
	// unsure is the lasting not-exact mark, and why its cause for status.
	unsure refusedRange
	why    string
	// owing: an event is owed since owedAt (the monotonic clock); pending
	// are the seqs counted since the last event, and forced says a
	// checkpoint was stored past RefusedCountsWait while it is owed.
	owing   bool
	owedAt  time.Duration
	pending refusedRange
	forced  bool
	// cause is why the owed event was last held; raisedAt the last raise
	// of AlarmRefusedCountsUnwritten, failRaised that store-commit-failed
	// is raised for this owed event, and lastWrite the last write, when
	// hasWritten.
	cause      string
	raisedAt   time.Duration
	raised     bool
	failRaised bool
	lastWrite  time.Duration
	hasWritten bool
}

// countsOwed reports whether the counts changed since the newest event.
func (rc *refusedCounts) countsOwed() bool { return !maps.Equal(rc.by, rc.written) }

func (rc *refusedCounts) owe(now time.Duration) {
	if !rc.owing {
		rc.owing, rc.owedAt = true, now
	}
}

// count counts a refusal of reason at seq.
func (rc *refusedCounts) count(reason string, seq uint64, now time.Duration) {
	c := rc.by[reason]
	if c.n == 0 {
		c.first = seq
	}
	c.n++
	c.last = seq
	rc.by[reason] = c
	if !rc.pending.set() {
		rc.pending.a = seq
	}
	rc.pending.b = seq
	rc.owe(now)
}

// room reports whether the budget allows a write now: no sooner than
// time.Hour/RefusedCountsPerHour after the last, so a held checkpoint waits
// at most that long for the budget (section 5; D3's B1 on #779).
func (rc *refusedCounts) room(now time.Duration) bool {
	return !rc.hasWritten || now-rc.lastWrite >= time.Hour/RefusedCountsPerHour
}

// wrote notes the event written at through.
func (rc *refusedCounts) wrote(now time.Duration, through uint64) {
	rc.written, rc.through, rc.lastWrite, rc.hasWritten = maps.Clone(rc.by), through, now, true
	rc.owing, rc.pending, rc.forced, rc.raised, rc.failRaised = false, refusedRange{}, false, false, false
}

// details are the counts event's details at through (C4-0.6-1).
func (rc *refusedCounts) details(stream c5.StreamID, through uint64) map[string]string {
	d := map[string]string{"stream": string(stream), "since": rc.since.Format(time.RFC3339Nano), "through": strconv.FormatUint(through, 10),
		"netobs": netobs.SelfIdentifier()}
	var sum uint64
	for r, c := range rc.by {
		sum += c.n
		d["reason."+r], d["first_seq."+r], d["last_seq."+r] = strconv.FormatUint(c.n, 10), strconv.FormatUint(c.first, 10), strconv.FormatUint(c.last, 10)
	}
	d["count"] = strconv.FormatUint(sum, 10)
	if rc.unsure.set() {
		d["unsure"] = rc.unsure.String()
	}
	return d
}

// shown is the range status shows as not exact, and its causes: the mark,
// and past RefusedCountsWait the seqs counted and not yet in an event.
func (rc *refusedCounts) shown() (refusedRange, string) {
	rg, why := rc.unsure, rc.why
	if rc.forced && rc.pending.set() {
		rg = rg.union(rc.pending)
		w := fmt.Sprintf("seqs %s counted since the last counts event were not written to the health stream within RefusedCountsWait (%s)", rc.pending, rc.cause)
		if why != "" {
			w = why + "; and " + w
		}
		why = w
	}
	return rg, why
}

// unwritten is AlarmRefusedCountsUnwritten's text. An event owed for the
// mark alone has its own form; one owed for counts names one range, with
// the mark's when it is set, and then reads "not exact".
func (rc *refusedCounts) unwritten() string {
	if !rc.countsOwed() {
		return fmt.Sprintf("the mark that the counts of refused observations may be wrong for seqs %s was not written to the health stream within RefusedCountsWait (%s), so the detector's checkpoint was stored without it. Status shows the counts as not exact until it is written. A restart before then shows them as exact, or as not exact only above the stored checkpoint, and this alarm is then the only record of that range.",
			rc.unsure, rc.cause)
	}
	rg, how := rc.pending, "a lower bound"
	if rc.unsure.set() {
		rg, how = rg.union(rc.unsure), "not exact"
	}
	return fmt.Sprintf("the counts of refused observations at seqs %s were not written to the health stream within RefusedCountsWait (%s), so the detector's checkpoint was stored without them. Status shows the counts as %s until they are written. A restart before then shows them as exact, and this alarm is then the only record of that range.",
		rg, rc.cause, how)
}

// refusedWrite is the counts event's write. A test swaps it to fail.
var refusedWrite = (*Runtime).sensorHealth

// refusedCountsReady writes the owed counts event, if any, before the
// detector's checkpoint, and reports whether the checkpoint may be stored:
// no checkpoint passes an unwritten count. The event is written only at a
// Through at or above the newest event's through, and within its budget and
// the platform ceiling. Held past RefusedCountsWait from when it became
// owed, the checkpoint is stored without it and the alarm raised.
func (r *Runtime) refusedCountsReady(ctx context.Context, nd *netDetector) bool {
	rc := &nd.rc
	if !rc.owing {
		return true
	}
	now, through := r.opt.Mono(), nd.d.Through()
	switch {
	case through < rc.through:
		rc.cause = fmt.Sprintf("replay below %d", rc.through)
	case !rc.room(now):
		rc.cause = fmt.Sprintf("its budget of %d an hour", RefusedCountsPerHour)
	default:
		_, err := refusedWrite(r, ctx, event.Health{Type: event.HealthObservationRefused, Details: rc.details(nd.obs, through)})
		if err == nil {
			rc.wrote(now, through)
			return true
		}
		if errors.Is(err, errPastCeiling) {
			rc.cause = "the platform class's ceiling"
		} else {
			rc.cause = "its write failed: " + err.Error()
			if !rc.failRaised {
				rc.failRaised = true
				var db c5.DatabaseID
				if d := r.dbFor(HealthStream); d != nil {
					db = d.spec.ID
				}
				r.opt.Status.Alarm(db, c5.Alarm{Code: c5.AlarmCommitFailed, At: r.opt.Now(), Stream: HealthStream,
					Detail: "health event " + event.HealthObservationRefused + " for " + string(nd.obs) + ": " + err.Error()})
			}
		}
	}
	if !rc.forced && now-rc.owedAt < RefusedCountsWait {
		return false
	}
	rc.forced = true
	if !rc.raised || now-rc.raisedAt >= time.Hour {
		r.raiseUnwritten(nd, now)
	}
	return true
}

func (r *Runtime) raiseUnwritten(nd *netDetector, now time.Duration) {
	nd.rc.raised, nd.rc.raisedAt = true, now
	r.opt.Status.Alarm(NetworkDB, c5.Alarm{Code: AlarmRefusedCountsUnwritten, At: r.opt.Now(), Stream: nd.obs, Detail: nd.rc.unwritten()})
}

// refusedAtStop raises AlarmRefusedCountsUnwritten at the stop, with the
// range as of then, while a forced checkpoint left the event owed, unless
// the stop's own step just raised it.
func (r *Runtime) refusedAtStop(nd *netDetector) {
	if now := r.opt.Mono(); nd != nil && nd.rc.owing && nd.rc.forced && !(nd.rc.raised && nd.rc.raisedAt == now) {
		r.raiseUnwritten(nd, now)
	}
}

// restoreRefused is the start's read of the counts. Without a restored
// checkpoint, or with no counts event for the stream within the scan, the
// counts begin again, since now with through 0. Otherwise they go on from
// the newest event: its unsure is carried, and when its through U is above
// the restored Through T, T+1 to U is marked, widening a carried range; a
// set or widened range owes an event. A failed read fails the start, so the
// next tick tries again.
func (r *Runtime) restoreRefused(ctx context.Context, nd *netDetector) error {
	rc := &nd.rc
	*rc = refusedCounts{since: r.opt.Now().UTC(), by: map[string]refusedReason{}, written: map[string]refusedReason{}}
	if !nd.restored {
		return nil
	}
	var ev *refusedEvent
	if err := r.newestHealth(ctx, refusedCountsScan, func(b []byte) bool {
		var ok bool
		ev, ok = parseRefusedEvent(b, nd.obs)
		return ok
	}); err != nil {
		return err
	}
	if ev == nil || ev.by == nil {
		return nil // none, or one this build cannot read: begin again
	}
	rc.since, rc.through, rc.by, rc.written, rc.unsure = ev.since, ev.through, ev.by, maps.Clone(ev.by), ev.unsure
	if rc.unsure.set() {
		rc.why = "carried from an earlier start"
	}
	t := nd.d.Through()
	if ev.through <= t {
		return nil
	}
	cause := "a crash or a build change"
	if ev.schema != event.Identifier || ev.netobs != netobs.SelfIdentifier() {
		cause = "a build change"
	}
	w := rc.unsure.union(refusedRange{t + 1, ev.through})
	if w == rc.unsure {
		return nil // inside the carried range
	}
	why := fmt.Sprintf("the newest counts event's through %d is above the restored checkpoint's %d (%s)", ev.through, t, cause)
	if rc.unsure.set() {
		why = "carried from an earlier start and widened: " + why
	}
	rc.unsure, rc.why = w, why
	rc.owe(r.opt.Mono())
	return nil
}

// refusedEvent is what a start reads of a counts event. by is nil when the
// event is one this build cannot read back.
type refusedEvent struct {
	schema, netobs string
	since          time.Time
	through        uint64
	unsure         refusedRange
	by             map[string]refusedReason
}

// parseRefusedEvent reads a detector.observation-refused event for stream,
// its type and stream pinned; anything else is not one. One whose details
// do not read, or that holds a reason this build does not know, as a later
// minor's may, comes back with by nil.
func parseRefusedEvent(b []byte, stream c5.StreamID) (*refusedEvent, bool) {
	if !strings.Contains(string(b), `"`+event.HealthObservationRefused+`"`) {
		return nil, false
	}
	var e struct {
		Schema string        `json:"schema"`
		Health *event.Health `json:"health"`
	}
	if json.Unmarshal(b, &e) != nil || e.Health == nil || e.Health.Type != event.HealthObservationRefused || e.Health.Details["stream"] != string(stream) {
		return nil, false
	}
	d, ev := e.Health.Details, &refusedEvent{schema: e.Schema, netobs: e.Health.Details["netobs"]}
	num := func(k string) (uint64, bool) {
		n, err := strconv.ParseUint(d[k], 10, 64)
		return n, err == nil && n > 0
	}
	var err error
	ev.since, err = time.Parse(time.RFC3339Nano, d["since"])
	through, ok := num("through")
	if err != nil || !ok {
		return ev, true
	}
	ev.through = through
	if v, ok := d["unsure"]; ok {
		as, bs, _ := strings.Cut(v, "-")
		a, aOK := strconv.ParseUint(as, 10, 64)
		z, zOK := strconv.ParseUint(bs, 10, 64)
		if aOK != nil || zOK != nil || a == 0 || a > z {
			return ev, true
		}
		ev.unsure = refusedRange{a, z}
	}
	by := map[string]refusedReason{}
	for k := range d {
		r, isReason := strings.CutPrefix(k, "reason.")
		if !isReason {
			continue
		}
		n, ok1 := num(k)
		first, ok2 := num("first_seq." + r)
		last, ok3 := num("last_seq." + r)
		if !slices.Contains(event.ObservationRefusedReasons, r) || !ok1 || !ok2 || !ok3 {
			return ev, true
		}
		by[r] = refusedReason{n, first, last}
	}
	ev.by = by
	return ev, true
}

// readHealthPage is newestHealth's read of a page. A test swaps it to fail
// the start's scan.
var readHealthPage = (*store.DB).Read

// newestHealth reads platform/health newest first, at most scan records
// back, and stops at the first record match takes. A failed read returns
// its error.
func (r *Runtime) newestHealth(ctx context.Context, scan int, match func([]byte) bool) error {
	db := r.Store(HealthStream)
	if db == nil {
		return errors.New("the health stream's database is not open")
	}
	last, err := db.LastCommitted(ctx, HealthStream)
	if err != nil {
		return err
	}
	first, err := db.FirstRetained(ctx, HealthStream)
	if err != nil || first == 0 {
		return err
	}
	const page = 500
	for hi, read := last, 0; hi >= first && read < scan; {
		lo := first - 1
		if hi-lo > page {
			lo = hi - page
		}
		got, err := readHealthPage(db, ctx, HealthStream, lo, int(hi-lo))
		if err != nil {
			return err
		}
		read += len(got)
		for i := len(got) - 1; i >= 0; i-- {
			if match(got[i].Event) {
				return nil
			}
		}
		hi = lo
	}
	return nil
}
