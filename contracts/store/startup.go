package store

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// Step names one startup step. Each is a separate StartupEnv or
// RecoveryStore call, so a test can make any one of them fail.
type Step string

const (
	StepPolicy            Step = "policy"
	StepLock              Step = "lock"
	StepInspect           Step = "inspect"
	StepReleaseReserve    Step = "release-reserve"
	StepReleaseLastResort Step = "release-last-resort"
	StepHeadroom          Step = "headroom"
	StepOpen              Step = "open"
	StepSettings          Step = "settings"
	StepIntegrity         Step = "integrity"
	StepPrune             Step = "prune"
	StepCompact           Step = "compact"
	StepRecreateReserves  Step = "recreate-reserves"
)

// Reserve names one of the two reserve files on the store's volume.
type Reserve string

const (
	// ReserveRecovery is released at every startup before the store is
	// opened. It must be at least twice the WAL bound (ADR-0004 item 1).
	ReserveRecovery Reserve = "recovery"
	// ReserveLastResort is released only when the recovery reserve is gone,
	// which is F-013's condition. It lets that startup free enough space to
	// open the store, so that forwarding can drain it and pruning can run.
	ReserveLastResort Reserve = "last-resort"
)

// StartupEnv is everything startup does before and around opening the store.
// None of these calls may open the database, its WAL or its -shm file.
type StartupEnv interface {
	// Lock gives this process exclusive use of the store's files and fails
	// if another process holds it. It is held for the life of the node, so
	// nothing else opens the store before recovery completes, or after.
	// Other modules and tools read through the node, never the files; the
	// files' ACL names only the node's service SID (ADR-0007 item 4).
	Lock(ctx context.Context) (unlock func(), err error)
	// StoreExists reports whether the database file exists.
	StoreExists(ctx context.Context) (bool, error)
	// ReserveExists reports whether a reserve file exists. A partial file
	// (a crash during creation) counts as existing.
	ReserveExists(ctx context.Context, r Reserve) (bool, error)
	// ReleaseReserve deletes the reserve and returns nil only once the file
	// is gone and its space is free.
	ReleaseReserve(ctx context.Context, r Reserve) error
	// FreeBytes is the free space on the store's volume.
	FreeBytes(ctx context.Context) (int64, error)
	// Open opens (or, if absent, creates) the database. A new database is
	// created with auto_vacuum=INCREMENTAL before its first table.
	Open(ctx context.Context) (RecoveryStore, error)
	// CreateReserve writes a reserve of exactly bytes, flushed, or removes
	// what it wrote and fails: a partial reserve hides a shortfall.
	CreateReserve(ctx context.Context, r Reserve, bytes int64) error
}

// RecoveryStore is an open store as startup recovery uses it. The node keeps
// using it after startup.
type RecoveryStore interface {
	CursorStore
	CommitIndex
	Pruner
	Outbox
	// CheckSettings fails unless the database runs in WAL mode at
	// synchronous=FULL with the bounded WAL settings and was created with
	// auto_vacuum=INCREMENTAL (without it pruning frees no space, E-A5-3
	// case 3). It never changes a setting on an existing store.
	CheckSettings(ctx context.Context) error
	// QuickCheck runs a structural check of the database.
	QuickCheck(ctx context.Context) error
	// Usage is the space the database uses and its limit (the sum of its
	// class quotas).
	Usage(ctx context.Context) (used, limit int64, err error)
	// CompactStep returns up to pages free pages to the filesystem and
	// checkpoints, in one step; more is false when no free pages are left.
	CompactStep(ctx context.Context, pages int) (more bool, err error)
	Close() error
}

// StartupPolicy holds the numbers startup works with.
type StartupPolicy struct {
	Streams   []StreamID
	Consumers []Consumer
	// RecoveryReserveBytes: at least twice the WAL bound.
	RecoveryReserveBytes int64
	// LastResortReserveBytes: at least OpenHeadroomBytes.
	LastResortReserveBytes int64
	// OpenHeadroomBytes is the free space the volume must have before the
	// store is opened. F-013: an open that rebuilds the -shm needs a 32 KiB
	// region and failed with 28,672 bytes free. The floor is 64 KiB, two
	// regions; the proposal is the WAL bound plus 64 KiB.
	OpenHeadroomBytes int64
	// PruneStepEvents is the size of one prune transaction (proposal: 50).
	PruneStepEvents int
	// CompactStepPages is the size of one compaction step (proposal: 32).
	CompactStepPages int
	// PruneTarget: startup prunes confirmed events while usage is above
	// this fraction of the limit (proposal: 0.8).
	PruneTarget float64
	// Now is the clock; nil means time.Now.
	Now func() time.Time
}

// MinOpenHeadroom is the smallest OpenHeadroomBytes allowed.
const MinOpenHeadroom = 64 << 10

// Validate checks the policy.
func (p StartupPolicy) Validate() error {
	switch {
	case len(p.Streams) == 0:
		return errf(CodeInvalid, nil, "startup policy names no streams")
	case p.OpenHeadroomBytes < MinOpenHeadroom:
		return errf(CodeInvalid, nil, "open headroom %d below %d", p.OpenHeadroomBytes, MinOpenHeadroom)
	case p.LastResortReserveBytes < p.OpenHeadroomBytes:
		return errf(CodeInvalid, nil, "last-resort reserve %d below open headroom %d", p.LastResortReserveBytes, p.OpenHeadroomBytes)
	case p.RecoveryReserveBytes <= 0:
		return errf(CodeInvalid, nil, "recovery reserve must be positive")
	case p.PruneStepEvents < 1 || p.PruneStepEvents > 1000:
		return errf(CodeInvalid, nil, "prune step %d not in [1, 1000]", p.PruneStepEvents)
	case p.CompactStepPages < 1 || p.CompactStepPages > 1024:
		return errf(CodeInvalid, nil, "compact step %d not in [1, 1024]", p.CompactStepPages)
	case !(p.PruneTarget > 0 && p.PruneTarget < 1):
		return errf(CodeInvalid, nil, "prune target %v not in (0,1)", p.PruneTarget)
	}
	for _, c := range p.Consumers {
		if err := c.Validate(); err != nil {
			return err
		}
	}
	return nil
}

// Mode is how the node may run after startup.
type Mode string

const (
	// ModeCollecting: recovery completed and both reserves are in place.
	// Collectors may start.
	ModeCollecting Mode = "collecting"
	// ModeDrainOnly: the store is open and readable, so forwarding can run
	// and advance cursors, but collectors must not start. Reached when a
	// reserve could not be re-created, or pruning or compaction failed. The
	// node retries steps 6 to 8 while draining and may start collectors once
	// both reserves exist.
	ModeDrainOnly Mode = "drain-only"
	// ModeBlocked: the store was not opened, because the volume lacks the
	// open headroom. The node keeps the lock, raises AlarmOpenBlocked, and
	// retries startup when space is freed outside the store; it never opens
	// the store below the headroom.
	ModeBlocked Mode = "blocked"
	// ModeFailed: a step failed and startup stopped. Report.Err says which.
	ModeFailed Mode = "failed"
)

// StepResult is the outcome of one step.
type StepResult struct {
	Step Step
	Err  error
	Note string
}

// Report is the result of RunStartup.
type Report struct {
	Mode   Mode
	Steps  []StepResult
	Alarms []Alarm
	// Store is the open store in ModeCollecting and ModeDrainOnly, else nil.
	Store RecoveryStore
	// Unlock releases the store lock. It is set whenever the lock was
	// taken, whatever the mode; the node calls it at shutdown.
	Unlock func()
	// Err is set in ModeFailed.
	Err error
}

// RunStartup runs startup recovery in the order ADR-0004 item 8 and F-013
// require:
//
//  1. take the store lock;
//  2. inspect, without opening: does the store exist, which reserves exist;
//  3. release the recovery reserve; a failed release stops startup. If the
//     store exists and the recovery reserve does not (the last run could not
//     re-create it), release the last-resort reserve instead;
//  4. check the volume has the open headroom; if not, stop in ModeBlocked
//     without opening the store;
//  5. open the store; check its settings and structure;
//  6. prune confirmed events in small steps while usage is above the
//     target, recomputing the boundary from persisted cursors before every
//     step (R-A5-5);
//  7. return freed pages to the filesystem in small steps;
//  8. re-create any released or missing reserve, last-resort first.
//
// The node collects only if every step passed and both reserves are back in
// place. A failure in steps 6 to 8 leaves the store open in drain-only mode.
//
// The first open happens at step 5 and nothing before it touches the
// database files.
func RunStartup(ctx context.Context, env StartupEnv, p StartupPolicy) Report {
	s := &startup{env: env, p: p, r: &Report{}}
	s.run(ctx)
	return *s.r
}

type startup struct {
	env StartupEnv
	p   StartupPolicy
	r   *Report
	now time.Time
	cap Mode
}

func (s *startup) ok(step Step, note string) {
	s.r.Steps = append(s.r.Steps, StepResult{Step: step, Note: note})
}

func (s *startup) alarm(code AlarmCode, step Step, detail string) {
	s.r.Alarms = append(s.r.Alarms, Alarm{Code: code, At: s.now, Step: step, Detail: detail})
}

// fail records a failed step and stops startup in ModeFailed.
func (s *startup) fail(step Step, code AlarmCode, err error) {
	s.r.Steps = append(s.r.Steps, StepResult{Step: step, Err: err})
	s.alarm(code, step, err.Error())
	s.r.Mode = ModeFailed
	s.r.Err = errf(CodeStartupFailed, err, "step %s", step)
	if s.r.Store != nil {
		s.r.Store.Close()
		s.r.Store = nil
	}
}

// degrade records a failed step that leaves the store usable for draining.
func (s *startup) degrade(step Step, code AlarmCode, err error) {
	s.r.Steps = append(s.r.Steps, StepResult{Step: step, Err: err})
	s.alarm(code, step, err.Error())
	s.cap = ModeDrainOnly
}

func (s *startup) run(ctx context.Context) {
	s.now = time.Now()
	if s.p.Now != nil {
		s.now = s.p.Now()
	}
	if err := s.p.Validate(); err != nil {
		s.fail(StepPolicy, AlarmSettingsInvalid, err)
		return
	}
	s.cap = ModeCollecting

	unlock, err := s.env.Lock(ctx)
	if err != nil {
		s.fail(StepLock, AlarmLockFailed, err)
		return
	}
	s.r.Unlock = unlock
	s.ok(StepLock, "")
	s.fromInspect(ctx)
}

// fromInspect runs steps 2 to 8 with the lock already held.
func (s *startup) fromInspect(ctx context.Context) {
	exists, err := s.env.StoreExists(ctx)
	if err != nil {
		s.fail(StepInspect, AlarmOpenBlocked, err)
		return
	}
	hasRecovery, err := s.env.ReserveExists(ctx, ReserveRecovery)
	if err != nil {
		s.fail(StepInspect, AlarmOpenBlocked, err)
		return
	}
	hasLast, err := s.env.ReserveExists(ctx, ReserveLastResort)
	if err != nil {
		s.fail(StepInspect, AlarmOpenBlocked, err)
		return
	}
	s.ok(StepInspect, fmt.Sprintf("store=%t recovery=%t last-resort=%t", exists, hasRecovery, hasLast))

	switch {
	case hasRecovery:
		if err := s.env.ReleaseReserve(ctx, ReserveRecovery); err != nil {
			s.fail(StepReleaseReserve, AlarmReserveReleaseFailed, err)
			return
		}
		s.ok(StepReleaseReserve, "")
	case !exists:
		s.ok(StepReleaseReserve, "new store, no reserve to release")
	default:
		// F-013's condition: the store exists and the last run could not
		// re-create its recovery reserve, so the disk may be full.
		s.alarm(AlarmReserveMissing, StepReleaseReserve, "recovery reserve missing on an existing store")
		if hasLast {
			if err := s.env.ReleaseReserve(ctx, ReserveLastResort); err != nil {
				s.fail(StepReleaseLastResort, AlarmReserveReleaseFailed, err)
				return
			}
			s.ok(StepReleaseLastResort, "")
		} else {
			s.alarm(AlarmReserveMissing, StepReleaseLastResort, "last-resort reserve missing on an existing store")
		}
	}

	free, err := s.env.FreeBytes(ctx)
	if err != nil {
		s.fail(StepHeadroom, AlarmOpenBlocked, err)
		return
	}
	if free < s.p.OpenHeadroomBytes {
		err := fmt.Errorf("%d bytes free, %d needed to open the store", free, s.p.OpenHeadroomBytes)
		s.r.Steps = append(s.r.Steps, StepResult{Step: StepHeadroom, Err: err})
		s.alarm(AlarmOpenBlocked, StepHeadroom, err.Error())
		s.r.Mode = ModeBlocked
		return
	}
	s.ok(StepHeadroom, fmt.Sprintf("%d bytes free", free))

	st, err := s.env.Open(ctx)
	if err != nil {
		s.fail(StepOpen, AlarmOpenFailed, err)
		return
	}
	s.r.Store = st
	s.ok(StepOpen, "")
	if err := st.CheckSettings(ctx); err != nil {
		s.fail(StepSettings, AlarmSettingsInvalid, err)
		return
	}
	s.ok(StepSettings, "")
	if err := st.QuickCheck(ctx); err != nil {
		s.fail(StepIntegrity, AlarmIntegrityFailed, err)
		return
	}
	s.ok(StepIntegrity, "")
	s.recover(ctx, st)
}

// recover runs steps 6 to 8 on an open, checked store and sets the mode.
func (s *startup) recover(ctx context.Context, st RecoveryStore) {
	if n, err := s.prune(ctx, st); err != nil {
		s.degrade(StepPrune, AlarmPruneFailed, err)
	} else {
		s.ok(StepPrune, fmt.Sprintf("%d events pruned", n))
		if err := s.compact(ctx, st); err != nil {
			s.degrade(StepCompact, AlarmCompactFailed, err)
		} else {
			s.ok(StepCompact, "")
		}
	}

	recreated := true
	for _, r := range []struct {
		which Reserve
		bytes int64
	}{{ReserveLastResort, s.p.LastResortReserveBytes}, {ReserveRecovery, s.p.RecoveryReserveBytes}} {
		has, err := s.env.ReserveExists(ctx, r.which)
		if err == nil && has {
			continue
		}
		if err == nil {
			err = s.env.CreateReserve(ctx, r.which, r.bytes)
		}
		if err != nil {
			s.degrade(StepRecreateReserves, AlarmReserveRecreateFailed, fmt.Errorf("%s reserve: %w", r.which, err))
			recreated = false
			break
		}
	}
	if recreated {
		s.ok(StepRecreateReserves, "")
	}

	s.r.Mode = s.cap
	if s.cap == ModeDrainOnly {
		s.alarm(AlarmDrainOnly, "", "store open for forwarding and pruning only; no new events accepted")
	}
}

// Resume is how a node leaves ModeBlocked or ModeDrainOnly without a restart.
// prev is the Report the node is running under; the lock it holds is kept.
//
//   - From ModeBlocked, Resume re-runs steps 2 to 8. The node calls it when
//     the volume's free space has changed (proposal: checked every 60 s),
//     and it leaves ModeBlocked only when free space reaches the open
//     headroom. It never opens the store below it.
//   - From ModeDrainOnly, Resume re-runs steps 6 to 8 on the open store. The
//     node calls it after forwarding has saved a cursor (proposal: at most
//     every 60 s). It returns ModeCollecting only when pruning and compaction
//     succeed and both reserves exist again.
//   - From any other mode it returns prev unchanged: ModeCollecting needs
//     nothing, and ModeFailed needs a restart.
//
// Every Report whose Mode differs from prev's is a ModeChange the node
// reports as a health event and an audit record (ModeChangeOf).
func Resume(ctx context.Context, env StartupEnv, p StartupPolicy, prev Report) Report {
	if prev.Mode != ModeBlocked && prev.Mode != ModeDrainOnly {
		return prev
	}
	s := &startup{env: env, p: p, r: &Report{Unlock: prev.Unlock}, cap: ModeCollecting}
	s.now = time.Now()
	if p.Now != nil {
		s.now = p.Now()
	}
	if err := p.Validate(); err != nil {
		s.fail(StepPolicy, AlarmSettingsInvalid, err)
		return *s.r
	}
	if prev.Mode == ModeBlocked {
		s.fromInspect(ctx)
		return *s.r
	}
	s.r.Store = prev.Store
	s.recover(ctx, prev.Store)
	return *s.r
}

// AcceptsEvents reports whether a node in mode m may accept new events: start
// collectors, poll SER, and accept Syslog. Only ModeCollecting does. In every
// other mode the collector stops pulling from devices, so records stay in
// the device's own buffer; if the buffer wraps meanwhile, the loss shows at
// the next collection as a C4 ser.gap event, not as silence. Syslog
// listeners refuse new data (stream) or drop and count it (datagram).
func (m Mode) AcceptsEvents() bool { return m == ModeCollecting }

// ModeChange is a change of the store's mode. The node emits it as a C4
// platform health event (store.mode-changed) and as an audit record.
// TODO(C8): the audit record shape.
type ModeChange struct {
	From, To Mode
	At       time.Time
	// Alarms are the alarms of the run that changed the mode; they say why.
	Alarms []Alarm
}

// ModeChangeOf returns the change from prev to next, and false if the mode
// did not change.
func ModeChangeOf(prev, next Report, at time.Time) (ModeChange, bool) {
	if prev.Mode == next.Mode {
		return ModeChange{}, false
	}
	return ModeChange{From: prev.Mode, To: next.Mode, At: at, Alarms: next.Alarms}, true
}

// prune runs prune passes, one step per stream per pass, while usage is
// above the target and a pass still deletes something. The boundary is
// recomputed from persisted cursors before every step.
func (s *startup) prune(ctx context.Context, st RecoveryStore) (int, error) {
	total := 0
	for {
		used, limit, err := st.Usage(ctx)
		if err != nil {
			return total, err
		}
		if float64(used) <= s.p.PruneTarget*float64(limit) {
			return total, nil
		}
		pass := 0
		for _, stream := range s.p.Streams {
			b, err := ComputeBoundary(ctx, st, st, s.p.Consumers, stream, s.now)
			if errors.Is(err, &Error{Code: CodeNoConsumers}) {
				continue // nothing confirms this stream; none of it is prunable
			}
			if err != nil {
				return total, err
			}
			n, err := st.PruneStep(ctx, b, s.p.PruneStepEvents)
			if err != nil {
				return total, err
			}
			pass += n
		}
		total += pass
		if pass == 0 {
			return total, nil
		}
	}
}

func (s *startup) compact(ctx context.Context, st RecoveryStore) error {
	for {
		more, err := st.CompactStep(ctx, s.p.CompactStepPages)
		if err != nil || !more {
			return err
		}
	}
}
