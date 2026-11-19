package sensorlink

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"otsec.local/otsec/contracts/event"
	"otsec.local/otsec/contracts/netobs"
)

// This file is the sensor's health events on the node (CH-45;
// docs/phase4/D5-sensor-node.md section 1.9 item 5 and section 1.8): the
// writer of what the cursor owes (a run loss, a lost gap), the pool, the
// sensor.counters builder, the heartbeat baselines' alarms, and what of it
// sensorrun.json keeps (runfile.go). Not wired (F-027's gate): nothing
// outside the tests makes a Health.

// The alarms this file raises, beside conn.go's.
const (
	AlarmTransmitted  = "sensor-transmitted"
	AlarmEgressAbsent = "sensor-egress-absent"
	AlarmStateUnread  = "sensor-state-unread"
	// AlarmStateNotDurable: a write of sensorrun.json failed; raised once
	// a failing stretch, status and the OS log only (section 1.9 item 5).
	AlarmStateNotDurable = "sensor-state-not-durable"
)

// DetailRunsFolded is sensor.counters' fold count (C4-0.5-1).
const DetailRunsFolded = "runs_folded"

// HealthSink writes one sensor health event to the node's health stream,
// building the C4 event at the write with the writing binary's
// event.Identifier (E4-7), under the platform class's ceiling. An error is
// an event not written: it stays held or owed. It is called with Health's
// lock held, so it must not call back into the Health or a Link's raise
// (D3's N2 on #747).
type HealthSink interface {
	WriteHealth(ctx context.Context, typ string, details map[string]string) error
}

// ErrHealthHeld: an owed event waits for its budget or the pool; its mark
// stays in the cursor, and it is tried again.
var ErrHealthHeld = errors.New("sensorlink: an owed health event waits for its budget")

// maxWritten bounds the keys of owed events written in this process.
const maxWritten = 1024

// HealthConfig makes a Health.
type HealthConfig struct {
	SensorID string
	Sink     HealthSink
	// Monotonic runs the budgets and the run file's minute; Now is the
	// node's wall clock, for the times the events and the file carry.
	Monotonic func() time.Duration
	Now       func() time.Time
	// Raise shows an alarm in status and the OS log. It is called with
	// Health's lock held, so it must not call back into the Health or a
	// Link's raise (D3's N2 on #747).
	Raise func(alarm, detail string)
	// File is the node's sensorrun.json; nil keeps nothing across a start.
	File *RunFile
}

// Health is one sensor's health events. Its methods are safe for
// concurrent use.
type Health struct {
	cfg  HealthConfig
	mu   sync.Mutex
	pool *Pool
	lost window // sensor.coverage-gap with cause lost: its own budget
	// written holds the keys of owed events committed in this process, so
	// a call repeated after a partial failure, or a redial after a failed
	// save, writes each event once (D4-116 items 3.4 and 3.5). A start
	// forgets it: an event can be written twice, never not at all.
	written []string
	// The run file's part (runfile.go): sensor-transmitted's standing
	// state and latest raise; the run and the capture totals the held
	// loss counts up to, as the cursor holds them now and as the file
	// last recorded them.
	transmitted bool
	raisedAt    time.Time
	run         string
	key         string // sensor.counters' key for run, "" when not known
	totals      [3]*uint64
	fileRun     string
	fileTotals  [3]*uint64
	fileAt      time.Duration
	fileWritten bool
	dirty       bool
	// fileErr is the run file's last write error while a failing stretch
	// stands, raised once at its first failure.
	fileErr error
	// Status.
	possiblyLost []string
	runFile      string
	startCopies  uint64
}

// NewHealth makes a sensor's Health with an empty pool.
func NewHealth(cfg HealthConfig) *Health {
	h := &Health{cfg: cfg, pool: NewPool()}
	if cfg.File != nil {
		cfg.File.add(h)
	}
	return h
}

// HealthStatus is what status shows of a sensor's health events.
type HealthStatus struct {
	// HealthHeld counts the pool events made to wait (health_held).
	HealthHeld uint64
	Waiting    []HeldEvent
	// Transmitted is sensor-transmitted's standing state, and RaisedAt
	// its latest raise.
	Transmitted bool
	RaisedAt    time.Time
	// RunFile is sensor-state-unread's cause run-file, with what made the
	// file unusable (behind, lost, unreadable, not-comparable), or "";
	// PossiblyLost names the held events the file may have lost.
	RunFile      string
	PossiblyLost []string
	// StartCopies counts the owed events written at a start, each
	// possibly a second copy (section 1.4).
	StartCopies uint64
	// Saturated names each waiting sensor.counters value that a rise would
	// have carried past 2^64 - 1 (diff.<name> or runs_folded), held there
	// as a lower bound until it is written (C4-0.5-3); a sum of exactly
	// 2^64 - 1 is not named (E5-8 (a)).
	Saturated []string
	// NotDurable is the run file's failing write, "" while it writes.
	NotDurable string
}

// Status returns a copy of the sensor's health status. It waits on the
// Health's lock, which a store append or the run file's sync holds
// (section 1.14).
func (h *Health) Status() HealthStatus {
	h.mu.Lock()
	defer h.mu.Unlock()
	st := HealthStatus{HealthHeld: h.pool.Held, Waiting: h.pool.Waiting(), Transmitted: h.transmitted, RaisedAt: h.raisedAt,
		RunFile: h.runFile, PossiblyLost: slices.Clone(h.possiblyLost), StartCopies: h.startCopies}
	for _, w := range st.Waiting {
		if w.Name != EventCounters {
			continue
		}
		st.Saturated = append(st.Saturated, w.Saturated...)
	}
	if h.fileErr != nil {
		st.NotDurable = h.fileErr.Error()
	}
	return st
}

// raise shows alarm in status and makes its event due in the pool, written
// at the pool's next write. The caller holds h.mu.
func (h *Health) raise(alarm, detail string) {
	if h.cfg.Raise != nil {
		h.cfg.Raise(alarm, detail)
	}
	h.pool.Due(HeldEvent{Name: alarm, Details: map[string]string{"sensor_id": h.cfg.SensorID, "detail": detail}})
	h.dirty = true
}

// alarm makes the event of an alarm the link raised due, written at the
// pool's next write (a heartbeat's, the owed writer's, or Flush on the
// manager's tick): no store append under the link's lock (D3's N2 on
// #747).
func (h *Health) alarm(alarm, detail string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.pool.Due(HeldEvent{Name: alarm, Details: map[string]string{"sensor_id": h.cfg.SensorID, "detail": detail}})
	h.dirty = true
}

// startCopy counts n owed events written at a start, each possibly a
// second copy (section 1.4).
func (h *Health) startCopy(n uint64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.startCopies += n
}

func (h *Health) wrote(k string) bool { return slices.Contains(h.written, k) }

func (h *Health) note(k string) {
	if len(h.written) == maxWritten {
		h.written = h.written[1:]
	}
	h.written = append(h.written, k)
}

// runLossKey and gapKey are Owed's keys (D4's N4 on #732).
func runLossKey(run string) string { return EventRunLoss + " " + run }

func gapKey(run string, s HeldSpan) string {
	return strings.Join([]string{EventCoverageGap, run, s.FromUTC, s.ToUTC, s.CutUTC}, " ")
}

// declares reports whether a prior declares a loss or an unclean end, for
// which sensor.run-loss is written (CH-45).
func declares(p *HeldPrior) bool {
	return p.RunsSkipped > 0 || p.RecordsLost > 0 || p.PreviousEnd != "clean" || len(p.Spans) > 0
}

// WriteOwed is Options.Owed: it writes each event o owes that this
// process has not written, the lost gaps under their own budget and the
// run loss through the pool, and returns nil only when every one is
// written. A gap or a run loss that waits returns ErrHealthHeld; a sink
// error is returned as it is. Either way the marks stay, and a later call
// writes only what is still unwritten.
func (h *Health) WriteOwed(ctx context.Context, o Owed) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	now := h.cfg.Monotonic()
	var pending []string
	// A run loss already waiting is not made due again: one run's loss is
	// one event (D6's B5 on #747).
	if p := o.Prior; p != nil && declares(p) && !h.wrote(runLossKey(o.RunID)) && !h.pool.waiting(EventRunLoss, o.RunID) {
		h.pool.Due(HeldEvent{Name: EventRunLoss, Key: o.RunID, Details: map[string]string{
			"sensor_id": h.cfg.SensorID, "generation": strconv.FormatUint(o.Generation, 10),
			"run_counter": strconv.FormatUint(o.RunCounter, 10), "run_id": o.RunID,
			"runs_skipped": strconv.FormatUint(p.RunsSkipped, 10), "records_lost": strconv.FormatUint(p.RecordsLost, 10),
			"previous_end": p.PreviousEnd, "started_by": p.StartedBy}})
	}
	if p := o.Prior; p != nil && declares(p) {
		pending = append(pending, runLossKey(o.RunID))
	}
	var gaps []HeldSpan
	if o.Prior != nil {
		gaps = append(gaps, o.Prior.Spans...)
	}
	gaps = append(gaps, o.Spans...)
	gaps = slices.DeleteFunc(gaps, func(s HeldSpan) bool { return !s.Owed || h.wrote(gapKey(o.RunID, s)) })
	err := h.writeGaps(ctx, now, o, gaps)
	perr := h.pool.Write(ctx, now, h.emit)
	for _, s := range gaps {
		pending = append(pending, gapKey(o.RunID, s))
	}
	// Only what o owes decides: the pool's error counts while the run
	// loss is unwritten (the pass stops at its first error, and
	// sensor.counters comes after the run loss), never for another
	// waiting event alone.
	if slices.ContainsFunc(pending, func(k string) bool { return !h.wrote(k) }) && err == nil {
		err = perr
		if err == nil {
			err = ErrHealthHeld
		}
	}
	h.persist(ctx, false) // a failure is raised there; the owed events are not the file's
	return err
}

// writeGaps writes the lost gaps of gaps under their budget: each alone
// while it has room, and past it the rest merged into one record (first
// start, last cut end, their number), which merges lost gaps only (section
// 1.9 item 5). A gap's times are its stated from_utc and its cut end
// (CH-40; D6's B1 on #747).
func (h *Health) writeGaps(ctx context.Context, now time.Duration, o Owed, gaps []HeldSpan) error {
	room := h.lost.room(now, GapLostPerHour)
	for len(gaps) > 0 && room > 0 {
		batch := gaps[:1]
		if room == 1 {
			batch = gaps
		}
		d := map[string]string{"sensor_id": h.cfg.SensorID, "generation": strconv.FormatUint(o.Generation, 10),
			"run_counter": strconv.FormatUint(o.RunCounter, 10), "run_id": o.RunID, "cause": "lost", "causes": "lost",
			"state": "closed", "covered": "false", "from_utc": batch[0].FromUTC, "to_utc": batch[0].CutUTC}
		if len(batch) > 1 {
			for _, s := range batch[1:] {
				d["from_utc"], d["to_utc"] = earlierUTC(d["from_utc"], s.FromUTC), laterUTC(d["to_utc"], s.CutUTC)
			}
			d["merged"] = strconv.Itoa(len(batch))
		}
		if err := h.cfg.Sink.WriteHealth(ctx, EventCoverageGap, d); err != nil {
			return err
		}
		h.lost = append(h.lost, now)
		for _, s := range batch {
			h.note(gapKey(o.RunID, s))
		}
		gaps, room = gaps[len(batch):], room-1
	}
	return nil
}

func earlierUTC(a, b string) string {
	if parseUTC(b).Before(parseUTC(a)) {
		return b
	}
	return a
}

// emit writes one pool event, built at its write.
func (h *Health) emit(ctx context.Context, e *HeldEvent) error {
	d := maps.Clone(e.Details)
	if e.Name == EventCounters {
		// Its rises are summed already, across runs when it folds (C4
		// 0.5), and C4's closed set has no merged detail.
		d = SensorCountersDetails(h.cfg.SensorID, e.Run, e.Rises)
		if e.Folded > 0 {
			d[DetailRunsFolded] = strconv.FormatUint(e.Folded, 10)
		}
	} else if e.Merged > 1 {
		if d == nil {
			d = map[string]string{}
		}
		d["merged"] = strconv.FormatUint(e.Merged, 10)
	}
	if err := h.cfg.Sink.WriteHealth(ctx, e.Name, d); err != nil {
		return err
	}
	if e.Name == EventRunLoss {
		h.note(runLossKey(e.Key))
	}
	h.dirty = true // the file's next write removes what the event carried
	return nil
}

// Event makes a pool event due: a node-only event (CH-45's list), held as
// its facts until it is written. It returns the pool's or the run file's
// error: nil means the event is written, or waits held in the run file,
// which an event that waits writes at once (section 1.1's re-arm waits on
// that).
func (h *Health) Event(ctx context.Context, name string, details map[string]string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	d := maps.Clone(details)
	if d == nil {
		d = map[string]string{}
	}
	d["sensor_id"] = h.cfg.SensorID
	h.pool.Due(HeldEvent{Name: name, Details: d})
	h.dirty = true
	err := h.pool.Write(ctx, h.cfg.Monotonic(), h.emit)
	return errors.Join(err, h.persist(ctx, h.pool.waiting(name, "")))
}

// Flush writes what waits while the pool has room, and writes the run
// file when its counts changed and its minute has passed. The node's
// manager calls it on its tick.
func (h *Health) Flush(ctx context.Context) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	err := h.pool.Write(ctx, h.cfg.Monotonic(), h.emit)
	return errors.Join(err, h.persist(ctx, false))
}

// countersKey is sensor.counters' key: the position generation, which an
// enrolment's Began names. Runs fold within it, never across it, since a
// new, rekey or replace begins one (C4-0.5-2). startKey is the key of a
// run whose position generation a start cannot know: its rises wait on
// their own, at most one entry a start.
func countersKey(began uint64) string { return strconv.FormatUint(began, 10) }

func startKey(run string) string { return "run " + run }

// countersDue is the sensor.counters event due for run's rises under key.
func countersDue(key, run string, rises map[string]uint64) HeldEvent {
	return HeldEvent{Name: EventCounters, Key: key, Run: run, Rises: rises}
}

// counters makes sensor.counters due for run with rises, folded into the
// waiting one of the position generation key, and records the run's
// capture totals, as the cursor now holds them. A run file write that
// fails is raised in persist, and the start counts the cursor's totals
// above those the file holds (section 1.8).
func (h *Health) counters(ctx context.Context, key, run string, rises map[string]uint64, totals [3]*uint64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.run != run || h.key != key || !sameTotals(h.totals, totals) {
		h.dirty = true
	}
	h.run, h.key, h.totals = run, key, totals
	if len(rises) > 0 {
		h.pool.Due(countersDue(key, run, rises))
		h.dirty = true
	}
	_ = h.pool.Write(ctx, h.cfg.Monotonic(), h.emit)
	h.persist(ctx, false)
}

// transmit raises sensor-transmitted: the standing state and the latest
// raise are written to the run file and synced before the caller saves
// the baseline that holds the rise, and only then is the alarm shown
// (section 1.8). A write that fails returns its error: the caller keeps
// the old baseline, so the next heartbeat raises again.
func (h *Health) transmit(ctx context.Context, detail string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.transmitted, h.raisedAt, h.dirty = true, h.cfg.Now(), true
	if err := h.persist(ctx, true); err != nil {
		h.raise(AlarmTransmitted, detail+"; the raise is not durable: "+err.Error())
		return err
	}
	h.raise(AlarmTransmitted, detail)
	return nil
}

// beforeReplace writes the run file with cur's run's last capture loss and
// the totals it counts up to, before row 6's save replaces that run in the
// cursor, unless the file already holds them (section 1.4; D1's rulings
// 6850475569 and 6850665387 on #655).
func (h *Health) beforeReplace(ctx context.Context, cur *Cursor) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	t := captureTotals(cur)
	if h.fileWritten && h.fileRun == cur.RunID && sameTotals(h.fileTotals, t) {
		return nil
	}
	if h.run != cur.RunID {
		h.key = ""
	}
	h.run, h.totals, h.dirty = cur.RunID, t, true
	return h.persist(ctx, true)
}

// persist writes the run file when its state changed: now, or at most once
// a minute. The caller holds h.mu.
func (h *Health) persist(ctx context.Context, now bool) error {
	f := h.cfg.File
	if f == nil || !h.dirty {
		return nil
	}
	at := h.cfg.Monotonic()
	if !now && h.fileWritten && at-h.fileAt < time.Minute {
		return nil
	}
	f.put(h.cfg.SensorID, h.entry())
	if err := f.write(ctx); err != nil {
		if h.fileErr == nil && h.cfg.Raise != nil {
			h.cfg.Raise(AlarmStateNotDurable, fmt.Sprintf("sensor %s: sensorrun.json was not written: %v; what it holds is in memory only until a write succeeds", h.cfg.SensorID, err))
		}
		h.fileErr = err
		return err
	}
	h.fileErr = nil
	h.fileAt, h.fileWritten, h.dirty = at, true, false
	h.fileRun, h.fileTotals = h.run, h.totals
	return nil
}

// entry is what the run file keeps for the sensor: never a run loss,
// whose home is the cursor's owed mark.
func (h *Health) entry() runFileSensor {
	e := runFileSensor{}
	if h.transmitted {
		e.Transmitted = &transmitState{Standing: true, RaisedAt: canonUTC(h.raisedAt)}
	}
	for _, w := range h.pool.Waiting() {
		if w.Name != EventRunLoss {
			e.Held = append(e.Held, w)
		}
	}
	if h.run != "" {
		e.Capture = &captureState{RunID: h.run, Key: h.key, Totals: totalsMap(h.totals)}
	}
	return e
}

// The capture-loss counters (C4-0.4-2), in CaptureLossCounters' order.
func captureTotals(c *Cursor) [3]*uint64 {
	return [3]*uint64{c.DropsDriver, c.DropsHolder, c.FramesOverlong}
}

func sameTotals(a, b [3]*uint64) bool {
	for i := range a {
		if (a[i] == nil) != (b[i] == nil) || (a[i] != nil && *a[i] != *b[i]) {
			return false
		}
	}
	return true
}

func totalsMap(t [3]*uint64) map[string]uint64 {
	m := map[string]uint64{}
	for i, n := range event.CaptureLossCounters {
		if t[i] != nil {
			m[n] = *t[i]
		}
	}
	return m
}

// SensorCountersDetails builds sensor.counters' details (C4 0.4): every
// counter of C4's two lists that rose, as diff.<name>, diff.packets always,
// and capture_loss naming the capture-loss counters that rose. It reads
// only rises keyed by those lists' names, so a count kept outside
// counters (C13 0.3's frame_stage and agent counts, CH-53) is never in it
// (N-9).
func SensorCountersDetails(sensor, run string, rises map[string]uint64) map[string]string {
	d := map[string]string{"reported_by": event.SensorReported, "sensor_id": sensor, "run_id": run,
		"diff.packets": strconv.FormatUint(rises["packets"], 10)}
	for _, n := range slices.Concat(event.SensorCounters, event.SensorCounters04) {
		if v := rises[n]; v > 0 {
			d["diff."+n] = strconv.FormatUint(v, 10)
		}
	}
	var loss []string
	for _, n := range event.CaptureLossCounters {
		if rises[n] > 0 {
			loss = append(loss, n)
		}
	}
	if len(loss) > 0 {
		d[event.DetailCaptureLoss] = strings.Join(loss, " ")
	}
	return d
}

// counterValues are a heartbeat's counters by C4's names, nil where the
// heartbeat carries none (drops_driver unknown, or a 0.2 counter in a 0.1
// heartbeat).
func counterValues(k *netobs.Counters) map[string]*uint64 {
	v := func(x uint64) *uint64 { return &x }
	return map[string]*uint64{"packets": v(k.Packets), "bytes": v(k.Bytes), "drops_driver": k.DropsDriver,
		"drops_decoder": v(k.DropsDecoder), "drops_channel": v(k.DropsChannel), "decoder_errors": v(k.DecoderErrors),
		"sessions_unparsed": v(k.SessionsUnparsed), "table_evictions": v(k.TableEvictions),
		"dnp3_pending_overflows": v(k.DNP3PendingOverflows), "dnp3_seq_reused": v(k.DNP3SeqReused), "prp_discards": v(k.PRPDiscards),
		"redactions": v(k.Redactions), "logins_not_placed": v(k.LoginsNotPlaced), "drops_holder": k.DropsHolder,
		"frames_overlong": k.FramesOverlong, "frames_outgoing": k.FramesOutgoing, "prp_mismatched": k.PRPMismatched,
		"prp_table_full": k.PRPTableFull, "prp_tag_differs": k.PRPTagDiffers, "prp_wrong_lan": k.PRPWrongLAN,
		"engine_lines_refused": k.EngineLinesRefused}
}

// rise is v above base, or v itself with no base held: the one rule for
// every counter (D1's ruling 6840188059 on #645).
func rise(v, base *uint64) uint64 {
	switch {
	case v == nil:
		return 0
	case base == nil:
		return *v
	case *v > *base:
		return *v - *base
	}
	return 0
}

// start applies the run file at the node's start (RunFile.Start): e is the
// sensor's entry, nil when the file holds none; usable says whether the
// file's values for the sensor stand; held says whether its held events
// and capture totals are taken (a usable file, or one that is behind);
// cause is why it is not usable. cur is the sensor's cursor, nil when
// none. It returns the cursor's capture baselines raised to the file's
// totals for the cursor's run, nil when they did not change.
func (h *Health) start(e *runFileSensor, usable, held bool, cause string, cur *Cursor) *Cursor {
	h.mu.Lock()
	defer h.mu.Unlock()
	now := h.cfg.Now()
	if !usable {
		h.runFile = cause
		h.raise(AlarmStateUnread, fmt.Sprintf("sensor %s: cause run-file: sensorrun.json is %s; its values for the sensor read as lost", h.cfg.SensorID, cause))
		if e != nil {
			for _, w := range e.Held {
				h.possiblyLost = append(h.possiblyLost, w.Name)
			}
		}
		h.possiblyLost = append(h.possiblyLost, "held pool events")
		h.transmitted, h.raisedAt, h.dirty = true, now, true
		h.raise(AlarmTransmitted, fmt.Sprintf("sensor %s: sensorrun.json is %s, so a transmit it held may be lost; standing until an administrator clears it", h.cfg.SensorID, cause))
	} else if e != nil && e.Transmitted != nil && e.Transmitted.Standing {
		h.transmitted, h.raisedAt = true, parseUTC(e.Transmitted.RaisedAt)
		h.raise(AlarmTransmitted, fmt.Sprintf("sensor %s: standing since %s, until an administrator clears it", h.cfg.SensorID, e.Transmitted.RaisedAt))
	}
	var base [3]*uint64
	baseRun, baseKey := "", ""
	if held && e != nil {
		for _, w := range e.Held {
			h.pool.Due(w)
			h.dirty = true
		}
		if e.Capture != nil {
			baseRun, baseKey = e.Capture.RunID, e.Capture.Key
			for i, n := range event.CaptureLossCounters {
				if v, ok := e.Capture.Totals[n]; ok {
					base[i] = &v
				}
			}
			h.fileRun, h.fileTotals, h.fileWritten = baseRun, base, usable
		}
	}
	if cur == nil {
		return nil
	}
	// The cursor's capture totals above the file's for the cursor's run,
	// or above none, are a loss, at the start's time (section 1.8).
	t := captureTotals(cur)
	if baseRun != cur.RunID {
		base, baseKey = [3]*uint64{}, ""
	}
	// The run's key is the file's when it records the run; otherwise the
	// start cannot know its position generation.
	key := baseKey
	if key == "" {
		key = startKey(cur.RunID)
	}
	rises := map[string]uint64{}
	var next *Cursor
	for i, n := range event.CaptureLossCounters {
		if r := rise(t[i], base[i]); r > 0 {
			rises[n] = r
		}
		if base[i] != nil && (t[i] == nil || *base[i] > *t[i]) {
			// The file counts up to more than the cursor saved (a kill
			// between the file and the cursor): the held loss has it.
			if next == nil {
				next = cur.clone()
			}
			v := *base[i]
			*[]**uint64{&next.DropsDriver, &next.DropsHolder, &next.FramesOverlong}[i] = &v
		}
	}
	if len(rises) > 0 {
		h.pool.Due(countersDue(key, cur.RunID, rises))
		h.dirty = true
	}
	h.run, h.key, h.totals = cur.RunID, baseKey, t
	if next != nil {
		h.totals = captureTotals(next)
	}
	return next
}
