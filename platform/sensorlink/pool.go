package sensorlink

import (
	"context"
	"maps"
	"math"
	"slices"
	"strings"
	"time"
)

// The sensor's health-event budgets, for each sensor and each hour (CH-45;
// docs/phase4/D5-sensor-node.md section 1.9 item 5). An hour is the last
// hour on the node's monotonic clock, so a step of the wall clock neither
// frees nor spends a budget.
const (
	PoolPerHour     = 24
	PoolPerName     = 4
	GapLostPerHour  = 4
	GapOtherPerHour = 4
	// CountersSpacing: sensor.counters comes no sooner than 10 minutes
	// after its last.
	CountersSpacing = 10 * time.Minute
)

// The pool's events that are not alarms (CH-45).
const (
	EventCounters          = "sensor.counters"
	EventRunLoss           = "sensor.run-loss"
	EventPastBlind         = "sensor.past-blind"
	EventRedialGranted     = "sensor.redial-granted"
	EventRevocationApplied = "sensor.revocation-applied"
	// EventCoverageGap is never in the pool: its two budgets are its own.
	EventCoverageGap = "sensor.coverage-gap"
)

// poolAlarms are the alarms whose health event is in the pool (CH-45's one
// list). Every other sensor alarm is status and the OS log only.
var poolAlarms = []string{"sensor-clock-skew", "sensor-blind", "sensor-no-heartbeat", AlarmGapUndeclared, "sensor-records-late",
	AlarmRecordsLost, "sensor-buffer-filling", AlarmBufferSmall, AlarmCoverageMismatch, "sensor-pinned-by-console",
	"sensor-identity", AlarmEgressAbsent, "sensor-dial-limit", AlarmTransmitted, "sensor-link-key", AlarmStateUnread,
	"sensor-enrolment-expiring", "sensor-enrolment-expired", "network-detector-lag", "network-session-not-tied"}

// rank orders the pool's waiting events when it is spent: sensor.counters
// waits first, then sensor.run-loss, then the alarms' events, and
// sensor.redial-granted and sensor.revocation-applied last (CH-45). The
// lowest rank is written first.
func rank(name string) int {
	switch name {
	case EventRedialGranted, EventRevocationApplied:
		return 0
	case EventRunLoss:
		return 2
	case EventCounters:
		return 3
	}
	return 1
}

// HeldEvent is a pool event due and not yet written, held as its counts and
// facts, never as built event bytes (C4 0.4 section 3; E4-7): the C4 event
// is built at its write, by the writing binary. Events of one name and key
// merge: the latest facts, the rises summed, Merged counting the events it
// carries. Every sum holds at 2^64 - 1, never wraps (C4-0.5-3).
type HeldEvent struct {
	Name string `json:"name"`
	// Key keeps apart what must not merge: the run, for sensor.run-loss;
	// the position generation, for sensor.counters (countersKey); empty
	// otherwise.
	Key     string            `json:"key,omitempty"`
	Merged  uint64            `json:"merged"`
	Details map[string]string `json:"details,omitempty"`
	Rises   map[string]uint64 `json:"rises,omitempty"`
	// Run and Folded are sensor.counters' fold (C4-0.5-1, C4-0.5-2; D1's
	// ruling 6996137498 on #747): the latest run whose rises it carries,
	// and how many earlier runs' rises are in it (runs_folded).
	Run    string `json:"run,omitempty"`
	Folded uint64 `json:"runs_folded,omitempty"`
	waited bool
}

func (e *HeldEvent) id() string { return e.Name + "\x00" + e.Key }

// window is the write times within the last hour.
type window []time.Duration

func (w *window) prune(now time.Duration) {
	*w = slices.DeleteFunc(*w, func(t time.Duration) bool { return now-t >= time.Hour })
}

// room is how many more writes the window takes under limit.
func (w *window) room(now time.Duration, limit int) int {
	w.prune(now)
	return max(0, limit-len(*w))
}

// Pool is one sensor's pool of 24 an hour (CH-45): each name at most 4 an
// hour, sensor.counters no sooner than 10 minutes after its last, and,
// when it is spent, the waiting events written in rank order once room
// returns. It is not safe for concurrent use: Health guards it.
type Pool struct {
	all    window
	byName map[string]*window
	// lastCounters is the monotonic time of the last sensor.counters, and
	// counted whether one has been written.
	lastCounters time.Duration
	counted      bool
	held         map[string]*HeldEvent
	// Held counts the events made to wait (health_held).
	Held uint64
	// The rules, CH-45's in the node; a test's control changes one.
	perName int
	spacing time.Duration
	rankOf  func(string) int
}

// NewPool makes an empty pool.
func NewPool() *Pool {
	return &Pool{byName: map[string]*window{}, held: map[string]*HeldEvent{}, perName: PoolPerName, spacing: CountersSpacing, rankOf: rank}
}

// before orders the waiting events: by rank, then by name and key.
func (p *Pool) before(a, b *HeldEvent) int {
	if r := p.rankOf(a.Name) - p.rankOf(b.Name); r != 0 {
		return r
	}
	return strings.Compare(a.id(), b.id())
}

// Due adds e to the waiting events, merged into one of its name and key.
// An event that joins one already waiting has waited.
func (p *Pool) Due(e HeldEvent) {
	if e.Merged == 0 {
		e.Merged = 1
	}
	h, ok := p.held[e.id()]
	if !ok {
		c := e
		c.Details, c.Rises = maps.Clone(e.Details), maps.Clone(e.Rises)
		p.held[e.id()] = &c
		return
	}
	if h.waited {
		p.Held = satAdd(p.Held, e.Merged)
	}
	h.Merged = satAdd(h.Merged, e.Merged)
	if e.Details != nil {
		h.Details = maps.Clone(e.Details)
	}
	for k, v := range e.Rises {
		if h.Rises == nil {
			h.Rises = map[string]uint64{}
		}
		h.Rises[k] = satAdd(h.Rises[k], v)
	}
	// A run other than the latest folds in: it counts once, and run_id
	// moves to it.
	h.Folded = satAdd(h.Folded, e.Folded)
	if e.Run != h.Run {
		h.Folded, h.Run = satAdd(h.Folded, 1), e.Run
	}
}

// satAdd is a + b, held at 2^64 - 1 (C4-0.5-3).
func satAdd(a, b uint64) uint64 {
	if s := a + b; s >= a {
		return s
	}
	return math.MaxUint64
}

// waiting reports whether an event of name and key waits.
func (p *Pool) waiting(name, key string) bool {
	_, ok := p.held[(&HeldEvent{Name: name, Key: key}).id()]
	return ok
}

// fits reports whether an event of name may be written at now.
func (p *Pool) fits(name string, now time.Duration) bool {
	w := p.byName[name]
	if w == nil {
		w = &window{}
		p.byName[name] = w
	}
	if p.all.room(now, PoolPerHour) == 0 || w.room(now, p.perName) == 0 {
		return false
	}
	return name != EventCounters || !p.counted || now-p.lastCounters >= p.spacing
}

func (p *Pool) spend(name string, now time.Duration) {
	p.all = append(p.all, now)
	*p.byName[name] = append(*p.byName[name], now)
	if name == EventCounters {
		p.lastCounters, p.counted = now, true
	}
}

// Write writes the waiting events in rank order, each while the pool has
// room for it, through emit. An event emit refuses stays waiting, and the
// pass stops there. Every event left waiting is counted once as held.
// It returns emit's first error.
func (p *Pool) Write(ctx context.Context, now time.Duration, emit func(context.Context, *HeldEvent) error) error {
	order := slices.SortedFunc(maps.Values(p.held), p.before)
	var err error
	for _, e := range order {
		if err == nil && p.fits(e.Name, now) {
			if err = emit(ctx, e); err == nil {
				p.spend(e.Name, now)
				delete(p.held, e.id())
				continue
			}
		}
		if !e.waited {
			e.waited = true
			p.Held = satAdd(p.Held, e.Merged)
		}
	}
	return err
}

// Waiting returns copies of the waiting events, in rank order.
func (p *Pool) Waiting() []HeldEvent {
	var out []HeldEvent
	for _, e := range p.held {
		c := *e
		c.Details, c.Rises = maps.Clone(e.Details), maps.Clone(e.Rises)
		out = append(out, c)
	}
	slices.SortFunc(out, func(a, b HeldEvent) int { return p.before(&a, &b) })
	return out
}
