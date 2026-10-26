package node

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"time"

	"otsec.local/otsec/contracts/adapter"
	"otsec.local/otsec/contracts/asset"
	"otsec.local/otsec/contracts/audit"
	"otsec.local/otsec/contracts/authz"
	c5 "otsec.local/otsec/contracts/store"
	"otsec.local/otsec/modules/security/collectorclient"
	"otsec.local/otsec/modules/security/collectorwire"
	"otsec.local/otsec/platform/store/protect"
)

// The node keeps its own copy of the C1 suspensions its runs' outcome codes
// set (adapter.Code.Suspends), so a collector that lost its state on a
// reinstall cannot resume a suspended asset (A1, after A3's C8 0.2 draft).
// The audit stream is the record: each suspension is an asset.suspend
// record and each clear an asset.suspension_clear record. The file in the
// store directory is a checkpoint of that record, so a start does not read
// the whole stream.
const (
	// AlarmAssetSuspended: an outcome code suspended the asset. Its runs
	// are not sent until an administrator clears the suspension.
	AlarmAssetSuspended = "asset-suspended"
	// AlarmSuspensionNotDurable: a suspension or a clear was not written to
	// the audit stream or to the checkpoint. While a suspension is not in
	// the audit stream, every run on the node stops, level 0 included,
	// because the chain is the record (D2-15).
	AlarmSuspensionNotDurable = "asset-suspension-not-durable"
	// AlarmSuspensionsUnknown: the suspensions could not be read or
	// rebuilt, so every run on the node stops, level 0 included.
	AlarmSuspensionsUnknown = "asset-suspensions-unknown"
	// AlarmSuspensionsRebuilt: the suspensions are rebuilt after the audit
	// database, which was not open at start, opened on a retry (C5 0.2,
	// P3-A5). It ends AlarmSuspensionsUnknown, and runs go again.
	AlarmSuspensionsRebuilt = "asset-suspensions-rebuilt"
	// AlarmSuspensionClearRefused: clear-suspension.json was refused,
	// names no current suspension, or names one not yet in the audit
	// stream, which it clears only once it is. Nothing was cleared.
	AlarmSuspensionClearRefused = "asset-suspension-clear-refused"
	// AlarmSuspensionCleared: an administrator's clear was recorded and
	// applied; the asset's runs resume once the collector has accepted it
	// too (assetclear.go).
	AlarmSuspensionCleared = "asset-suspension-cleared"
)

// SuspensionsFileName is the checkpoint's name in the store directory.
const SuspensionsFileName = "suspensions.json"

// ClearSuspensionFileName is the file an administrator writes in admin_dir
// to clear one suspension: {"schema": ClearSuspensionSchema, "asset_id":
// ..., "ref": the invocation ID the suspension names}. It is the Phase 2
// interim; before any device-observed endpoint the clear becomes an
// admin-signed C7 request (A1).
const ClearSuspensionFileName = "clear-suspension.json"

// AdminReaders are the services that read admin_dir besides
// Administrators and SYSTEM: the node and the collector, whose service
// SIDs each hold read and traverse there and nothing more
// (winsvc.Dirs, OTSEC\config\admin). Both services pass the same list to
// protect.CheckDirFor and ReadFileFor, so a file either could have
// written is refused by both (A3 #117). On Linux, a development platform
// only, the list is not used.
func AdminReaders() []string {
	return []string{collectorwire.ServiceSID(collectorwire.NodeService), collectorwire.ServiceSID(collectorwire.CollectorService)}
}

const (
	suspensionsSchema       = "otsec.node-suspensions/0.1"
	ClearSuspensionSchema   = "otsec.clear-suspension/0.1"
	MaxClearSuspensionBytes = 4 << 10
)

type suspensionsFile struct {
	Schema string `json:"schema"`
	// ThroughSeq is the last audit seq the checkpoint reflects.
	ThroughSeq  uint64                      `json:"through_seq"`
	Suspensions map[string]asset.Suspension `json:"suspensions"`
	// Unaudited are the suspensions in Suspensions whose asset.suspend
	// record was not yet in the audit stream. A start writes them, and
	// holds the node until it has.
	Unaudited []pendingSuspension `json:"unaudited,omitempty"`
	// Collector is the collector's keys and numbering through ThroughSeq
	// (seqreset.go).
	Collector collectorState `json:"collector"`
	// CollectorClears are the clears the node has recorded that the
	// collector has not yet accepted: asset ID to the suspension's ref
	// (assetclear.go).
	CollectorClears map[string]string `json:"collector_clears,omitempty"`
	// Quarantine is every quarantine.exported record through ThroughSeq,
	// by manifest hash, with what the chain holds about its clear
	// (quarantine.go).
	Quarantine map[string]quarantineEntry `json:"quarantine,omitempty"`
}

type pendingSuspension struct {
	AssetID string `json:"asset_id"`
	Ref     string `json:"ref"`
	Code    string `json:"code"`
	// Adopted marks a suspension taken from the collector's refusal
	// (adopt.go), which its record says.
	Adopted bool `json:"adopted,omitempty"`
}

type clearSuspension struct {
	Schema  string `json:"schema"`
	AssetID string `json:"asset_id"`
	Ref     string `json:"ref"`
}

// loadSuspensions reads the checkpoint and applies every asset.suspend and
// asset.suspension_clear record after it, in chain order. A missing or
// unreadable checkpoint means the whole stream is read. An error means the
// suspensions are unknown; the caller stops every run on the node.
func (s *Scheduler) loadSuspensions(ctx context.Context) error {
	f, err := readSuspensions(s.suspensionsPath())
	switch {
	case errors.Is(err, fs.ErrNotExist):
		f = suspensionsFile{}
	case err != nil:
		s.rt.opt.Status.Raise("", AlarmSuspensionsUnknown, "suspension checkpoint unreadable, rebuilt from the audit stream: "+err.Error())
		f = suspensionsFile{}
	}
	m := f.Suspensions
	if m == nil {
		m = map[string]asset.Suspension{}
	}
	db := s.rt.Store(AuditStream)
	if db == nil {
		return errAuditNotOpen
	}
	through := c5.Seq(f.ThroughSeq)
	last, err := db.LastCommitted(ctx, AuditStream)
	if err != nil {
		return err
	}
	if through > last {
		return fmt.Errorf("the checkpoint reflects audit seq %d, but the audit stream ends at %d", through, last)
	}
	if last > through {
		first, err := db.FirstRetained(ctx, AuditStream)
		if err != nil {
			return err
		}
		if first > through+1 {
			return fmt.Errorf("audit records %d to %d were pruned, so the suspensions they hold cannot be read", through+1, first-1)
		}
	}
	var pending []unaudited
	for _, u := range f.Unaudited {
		sp, ok := m[u.AssetID]
		if !ok || sp.Ref != u.Ref {
			return fmt.Errorf("the checkpoint lists suspension %s of %s as unaudited but does not hold it", u.Ref, u.AssetID)
		}
		pending = append(pending, unaudited{u.AssetID, sp, u.Code, u.Adopted})
	}
	cc := f.CollectorClears
	if cc == nil {
		cc = map[string]string{}
	}
	quar := map[string]*quarantineEntry{}
	for h, e := range f.Quarantine {
		quar[h] = &e
	}
	s.mu.Lock()
	s.susp, s.through, s.unaudited, s.cs, s.collClear, s.quar = m, uint64(through), pending, f.Collector, cc, quar
	s.mu.Unlock()
	if err := s.fold(ctx, false); err != nil {
		return err
	}
	s.mu.Lock()
	snapshot, pending, through2, cs, cc, q := maps.Clone(s.susp), slices.Clone(s.unaudited), s.through, s.cs, maps.Clone(s.collClear), s.quarSnapshot()
	s.fileStale = true
	s.mu.Unlock()
	if err := writeCheckpoint(s.suspensionsPath(), through2, snapshot, pending, cs, cc, q); err != nil {
		// The audit stream holds every suspension; settle writes the
		// checkpoint later.
		s.rt.opt.Status.Raise("", AlarmSuspensionNotDurable, "suspension checkpoint not written; the next start reads the audit stream again: "+err.Error())
	} else {
		s.mu.Lock()
		s.fileStale = false
		s.mu.Unlock()
		s.saveCursor(ctx, through2)
	}
	s.publishSuspensions()
	return nil
}

// applySuspension applies one audit record to m, after checking it
// against C8 0.2's suspension rules (audit.VerifySuspensions) from the
// suspensions m holds in the chain: those in m but not in pending. It
// returns true when the record changed m. The node holds one suspension
// per asset, since a suspended asset never runs; a second one is an error.
func applySuspension(m map[string]asset.Suspension, pending []unaudited, rec *audit.Record) (bool, error) {
	if rec.Action != audit.ActionAssetSuspend && rec.Action != audit.ActionAssetSuspensionClear {
		return false, nil
	}
	open := make([]audit.OpenSuspension, 0, len(m))
	for id, sp := range m {
		if !slices.ContainsFunc(pending, func(u unaudited) bool { return u.assetID == id && u.sp.Ref == sp.Ref }) {
			open = append(open, audit.OpenSuspension{AssetID: id, Reason: sp.Reason, Ref: sp.Ref})
		}
	}
	if _, err := audit.VerifySuspensions(open, []*audit.Record{rec}); err != nil {
		return false, err
	}
	if rec.Action == audit.ActionAssetSuspensionClear {
		delete(m, rec.Target.AssetID)
		return true, nil
	}
	sp, assetID, err := suspensionFromRecord(rec)
	if err != nil {
		return false, err
	}
	if cur, ok := m[assetID]; ok && cur.Ref != sp.Ref {
		return false, fmt.Errorf("asset %s is suspended by %s and again by %s", assetID, cur.Ref, sp.Ref)
	}
	changed := m[assetID] != sp
	m[assetID] = sp
	return changed, nil
}

// suspensionFromRecord reads a C8 0.2 asset.suspend record: the asset in
// target, the C1 reason in suspension, the ref in correlation_id, and the
// record's time as the suspension's start.
func suspensionFromRecord(rec *audit.Record) (asset.Suspension, string, error) {
	if rec.Target == nil || rec.Target.AssetID == "" || rec.Suspension == nil || rec.CorrelationID == "" {
		return asset.Suspension{}, "", errors.New("asset.suspend without an asset, a suspension or a ref")
	}
	since, err := time.Parse(time.RFC3339Nano, rec.Time.UTC)
	if err != nil {
		return asset.Suspension{}, "", err
	}
	return asset.Suspension{Reason: rec.Suspension.Reason, Since: since.UTC().Format(time.RFC3339), Ref: rec.CorrelationID}, rec.Target.AssetID, nil
}

// suspensionRecord is the node's C8 0.2 record of a suspension or a clear.
// code is the C2 code that set a suspension; a clear carries none.
func (s *Scheduler) suspensionRecord(action audit.Action, assetID string, sp asset.Suspension, code, detail string) (c5.Record, error) {
	rec := audit.Record{Contract: audit.ContractID, NodeID: string(s.rt.cfg.NodeID), Time: s.rt.received(),
		Actor: audit.Actor{Type: authz.PrincipalNode, ID: string(s.rt.cfg.NodeID)}, Action: action, Outcome: audit.OutcomeInfo,
		Target: &audit.Target{AssetID: assetID}, CorrelationID: sp.Ref, Detail: detail,
		Suspension: &audit.Suspension{Reason: sp.Reason}}
	if action == audit.ActionAssetSuspend {
		rec.Suspension.Code = code
	}
	b, err := json.Marshal(rec)
	if err != nil {
		return c5.Record{}, err
	}
	if _, err := audit.ValidatePending(b); err != nil {
		return c5.Record{}, err
	}
	return c5.Record{Stream: AuditStream, Class: c5.ClassAudit, Event: b}, nil
}

func (s *Scheduler) commitSuspensionRecord(ctx context.Context, action audit.Action, assetID string, sp asset.Suspension, code, detail string) error {
	rec, err := s.suspensionRecord(action, assetID, sp, code, detail)
	if err != nil {
		return err
	}
	if _, log, mode := s.rt.view(s.rt.find(AuditDB)); log == nil || !mode.AcceptsEvents() {
		return fmt.Errorf("audit database is %s", s.rt.Mode(AuditDB))
	} else if _, err := log.Append(ctx, rec); err != nil {
		return err
	}
	return nil
}

// outcomeCode is the C2 code of an accepted run's outcome, read from the
// result even when the outcome was quarantined (A1: a result that fails
// validation still suspends). "" when the outcome holds no code.
func outcomeCode(resp collectorclient.Response) adapter.Code {
	switch {
	case resp.Outcome != nil:
		if resp.Outcome.Result.Error != nil {
			return resp.Outcome.Result.Error.Code
		}
	case resp.Quarantine != nil && len(resp.Quarantine.ResultJSON) > 0:
		var r struct {
			Error *struct {
				Code adapter.Code `json:"code"`
			} `json:"error"`
		}
		if json.Unmarshal(resp.Quarantine.ResultJSON, &r) == nil && r.Error != nil {
			return r.Error.Code
		}
	}
	return ""
}

// suspend holds the asset at once, then records the suspension on the
// audit stream and in the checkpoint, before the scheduler decides
// anything else.
func (s *Scheduler) suspend(ctx context.Context, assetID, ref string, code adapter.Code) {
	s.hold(ctx, assetID, ref, code, false)
}

// hold is suspend for a run's outcome, or, with adopted, for a suspension
// the collector's refusal named (adopt.go).
func (s *Scheduler) hold(ctx context.Context, assetID, ref string, code adapter.Code, adopted bool) {
	reason := code.Suspends()
	if reason == "" || ref == "" {
		return
	}
	sp := asset.Suspension{Reason: reason, Since: s.now().UTC().Format(time.RFC3339), Ref: ref}
	s.mu.Lock()
	s.susp[assetID] = sp
	s.unaudited = append(s.unaudited, unaudited{assetID, sp, string(code.Effective()), adopted})
	s.fileStale = true
	s.mu.Unlock()
	why := fmt.Sprintf("outcome code %s suspends the asset (%s)", code.Effective(), reason)
	if adopted {
		why = fmt.Sprintf("the collector holds the asset suspended by %s (%s, outcome code %s), which the node had not recorded; adopted from the collector's refusal", ref, reason, code.Effective())
	}
	s.rt.opt.Status.Raise(assetID, AlarmAssetSuspended, why+"; its runs are not sent until an administrator clears suspension "+ref)
	s.settle(ctx)
}

// unaudited is a suspension whose asset.suspend record is not yet in the
// audit stream.
type unaudited struct {
	assetID string
	sp      asset.Suspension
	code    string // the C2 code that set it
	adopted bool   // taken from the collector's refusal (adopt.go)
}

// detail is the asset.suspend record's detail.
func (u unaudited) detail() string {
	if u.adopted {
		return adoptedDetail + "; outcome code " + u.code
	}
	return "outcome code " + u.code
}

// settle writes what suspend and checkClear could not, and keeps the
// checkpoint current.
//
//   - The audit records after the checkpoint are applied first (fold), so
//     a record whose append reported an error but was committed is found
//     there and not written twice: C8 0.2 breaks the chain on a duplicate
//     suspend or a second clear.
//   - Every asset.suspend record not yet in the audit stream is written.
//     While one is missing, all collection on the node is held, every asset
//     and every operation, even if the checkpoint holds the suspension: the
//     chain is the record (A1, D2-15 at 0ef6641).
//   - The checkpoint is written when the state changed or the stream was
//     applied further. Its through_seq is the last record applied; it may
//     also hold suspensions not yet in the stream, which only holds more.
//     Then the suspension consumer's cursor moves to that seq, so pruning
//     never passes a checkpoint (pruneConsumers).
//
// The scheduler calls it before every run, so a hold lifts once the write
// succeeds.
func (s *Scheduler) settle(ctx context.Context) {
	s.settleMu.Lock()
	defer s.settleMu.Unlock()
	s.settleLocked(ctx)
}

// settleLocked is settle with settleMu held.
func (s *Scheduler) settleLocked(ctx context.Context) {
	auditErr := s.fold(ctx, true)
	if !s.foldOK(auditErr) {
		return
	}
	s.mu.Lock()
	pending := append([]unaudited{}, s.unaudited...)
	s.mu.Unlock()
	var fileErr error
	done := 0
	for _, u := range pending {
		if auditErr != nil {
			break
		}
		if auditErr = s.commitSuspensionRecord(ctx, audit.ActionAssetSuspend, u.assetID, u.sp, u.code, u.detail()); auditErr == nil {
			done++
		}
	}
	if done > 0 {
		// Apply what was just written: fold takes each written suspension
		// off the pending list and moves the checkpoint past it. An error
		// here leaves it pending, and the next settle's fold finds it in
		// the stream before writing anything.
		err := s.fold(ctx, true)
		if !s.foldOK(err) {
			return
		}
		if auditErr == nil {
			auditErr = err
		}
	}
	s.mu.Lock()
	unwritten := len(s.unaudited) > 0
	stale := s.fileStale
	through := s.through
	s.mu.Unlock()
	if stale {
		s.mu.Lock()
		snapshot, pending, cs, cc, q := maps.Clone(s.susp), slices.Clone(s.unaudited), s.cs, maps.Clone(s.collClear), s.quarSnapshot()
		s.mu.Unlock()
		if fileErr = writeCheckpoint(s.suspensionsPath(), through, snapshot, pending, cs, cc, q); fileErr == nil {
			s.mu.Lock()
			s.fileStale = s.through != through
			s.mu.Unlock()
			s.saveCursor(ctx, through)
		} else {
			s.mu.Lock()
			s.fileStale = true
			s.mu.Unlock()
		}
	}
	s.mu.Lock()
	was := s.node == AlarmSuspensionNotDurable
	switch {
	case unwritten && s.node == "":
		s.node = AlarmSuspensionNotDurable
	case !unwritten && was:
		s.node = ""
	}
	s.mu.Unlock()
	if unwritten {
		s.raiseOnceKey("suspension unaudited", "", AlarmSuspensionNotDurable, "a suspension is not in the audit stream; all collection on this node is held until it is: "+auditErr.Error())
	} else {
		s.clearQuietKey("suspension unaudited")
	}
	if fileErr != nil {
		s.raiseOnceKey("suspension checkpoint", "", AlarmSuspensionNotDurable, "suspension checkpoint not written; the audit stream holds every suspension: "+fileErr.Error())
	} else {
		s.clearQuietKey("suspension checkpoint")
	}
	if was && !unwritten {
		s.rt.opt.Status.Raise("", AlarmSuspensionNotDurable, "every suspension is in the audit stream again; collection resumes")
	}
	if len(pending) > 0 || stale {
		s.publishSuspensions()
	}
}

// fold applies the audit records after the last one applied to the node's
// suspensions, in chain order, as loadSuspensions does at start. A pending
// asset.suspend found there is written already. announce raises
// AlarmSuspensionCleared for each clear applied; a start replaying the
// tail does not. On an error the records
// from there on are applied again next time.
func (s *Scheduler) fold(ctx context.Context, announce bool) error {
	db := s.rt.Store(AuditStream)
	if db == nil {
		return errors.New("audit database not open")
	}
	last, err := db.LastCommitted(ctx, AuditStream)
	if err != nil {
		return err
	}
	s.mu.Lock()
	after := c5.Seq(s.through)
	s.mu.Unlock()
	for after < last {
		got, err := db.Read(ctx, AuditStream, after, 500)
		if err != nil {
			return err
		}
		if len(got) == 0 {
			return fmt.Errorf("audit stream ends at %d, before its last committed seq %d", after, last)
		}
		for _, st := range got {
			rec, err := audit.ParseRecord(st.Event)
			if err != nil {
				return badRecord{st.Key.Seq, err}
			}
			s.mu.Lock()
			changed, err := applySuspension(s.susp, s.unaudited, rec)
			if err == nil {
				err = applyCollector(&s.cs, rec)
			}
			accepted := false
			if err == nil {
				accepted = applyCollectorClear(s.collClear, rec)
				applyQuarantine(s.quar, rec)
			}
			if err == nil {
				if rec.Action == audit.ActionAssetSuspend {
					s.unaudited = slices.DeleteFunc(s.unaudited, func(u unaudited) bool {
						return u.assetID == rec.Target.AssetID && u.sp.Ref == rec.CorrelationID
					})
				}
				s.through, s.fileStale = uint64(st.Key.Seq), true
			}
			s.mu.Unlock()
			if err != nil {
				return badRecord{st.Key.Seq, err}
			}
			if announce && changed && rec.Action == audit.ActionAssetSuspensionClear {
				s.rt.opt.Status.Raise(rec.Target.AssetID, AlarmSuspensionCleared, "suspension "+rec.CorrelationID+" cleared by an administrator; runs resume once the collector accepts the clear")
			}
			if announce && accepted {
				s.rt.opt.Status.Raise(rec.Target.AssetID, AlarmSuspensionCleared, "the collector accepted the "+rec.Detail+"; runs resume")
			}
			after = st.Key.Seq
		}
	}
	return nil
}

// foldOK reports whether settle may go on after fold returned err. A bad
// record stops every run on the node, level 0 included.
func (s *Scheduler) foldOK(err error) bool {
	bad := badRecord{}
	if !errors.As(err, &bad) {
		return true
	}
	s.mu.Lock()
	s.node = AlarmSuspensionsUnknown
	s.mu.Unlock()
	s.raiseOnceKey("suspension record", "", AlarmSuspensionsUnknown, "suspensions cannot be rebuilt past an audit record; every run on this node is stopped: "+bad.Error())
	return false
}

// badRecord is an audit record the suspensions cannot be rebuilt past: it
// does not parse, or breaks C8 0.2's suspension rules. Unlike a read
// error, retrying does not help, so every run on the node stops.
type badRecord struct {
	seq c5.Seq
	err error
}

func (e badRecord) Error() string { return fmt.Sprintf("audit seq %d: %v", e.seq, e.err) }
func (e badRecord) Unwrap() error { return e.err }

// SuspensionConsumer is the C5 consumer that keeps the audit stream from
// being pruned past the suspension checkpoint (D2-15 at 0ef6641): a
// rebuild must find every record after through_seq.
const SuspensionConsumer c5.ConsumerID = "node-suspensions"

// pruneConsumers adds SuspensionConsumer to the audit stream's consumers.
// It is added only when the stream already has a required consumer: C5
// prunes audit only after a required consumer confirmed delivery, and the
// checkpoint must never make an unforwarded record prunable. With it, the
// boundary is the lower of the delivery cursors and the checkpoint.
func pruneConsumers(cs []c5.Consumer) []c5.Consumer {
	for _, c := range cs {
		if c.Stream == AuditStream && c.Delivery == c5.Required {
			return append(cs, c5.Consumer{ID: SuspensionConsumer, Stream: AuditStream, Delivery: c5.Required})
		}
	}
	return cs
}

// saveCursor moves SuspensionConsumer's cursor to the checkpoint's
// through_seq. A failure leaves the cursor behind, which only holds more
// of the stream.
func (s *Scheduler) saveCursor(ctx context.Context, through uint64) {
	db := s.rt.Store(AuditStream)
	if db == nil {
		return
	}
	if err := db.SaveCursor(ctx, c5.Cursor{Consumer: SuspensionConsumer, Stream: AuditStream, Through: c5.Seq(through)}); err != nil {
		s.raiseOnceKey("suspension cursor", "", AlarmSuspensionNotDurable, "suspension checkpoint cursor not saved; the audit stream is pruned less: "+err.Error())
	}
}

// checkClear applies clear-suspension.json in admin_dir, if there is one.
// It clears one suspension, only on an exact asset and ref match, and only
// once the clear is in the audit stream. A clear of a suspension whose
// asset.suspend is not yet in the stream waits: written first, the clear
// would name a suspension the chain does not hold, and C8 0.2 breaks the
// chain on it (A6 on #107). Anything else changes nothing and is raised
// once per file content.
//
// It holds settleMu throughout, so no settle folds or writes between the
// match and the clear.
func (s *Scheduler) checkClear(ctx context.Context) {
	if s.rt.cfg.AdminDir == "" {
		return
	}
	s.settleMu.Lock()
	defer s.settleMu.Unlock()
	s.mu.Lock()
	s.clearFile = nil // set again below only from a file read and decoded now
	s.mu.Unlock()
	// The directory first (A3 on #107): a file the node could have written
	// itself is no administrator's. On Linux the file check reads only the
	// mode, so a node-writable directory would let the node plant a 0400
	// file; on Windows another account could write one into it.
	if err := protect.CheckDirFor(s.rt.cfg.AdminDir, AdminReaders()); err != nil {
		s.refuseClear("dir "+err.Error(), "", "admin_dir refused, so "+ClearSuspensionFileName+" is not read: "+err.Error())
		return
	}
	path := filepath.Join(s.rt.cfg.AdminDir, ClearSuspensionFileName)
	b, err := protect.ReadFileFor(path, MaxClearSuspensionBytes, AdminReaders())
	if errors.Is(err, fs.ErrNotExist) {
		return
	}
	if err != nil {
		s.refuseClear("err "+err.Error(), "", ClearSuspensionFileName+" refused: "+err.Error())
		return
	}
	key := "file " + digest(b)
	var cl clearSuspension
	// Strict as the collector reads it (A3 #117): keys exactly as named,
	// no duplicate, nothing after the object.
	if err := collectorwire.DecodeStrict(b, &cl); err != nil || cl.Schema != ClearSuspensionSchema || cl.AssetID == "" || cl.Ref == "" {
		s.refuseClear(key, "", fmt.Sprintf("%s is not a %s object with asset_id and ref", ClearSuspensionFileName, ClearSuspensionSchema))
		return
	}
	s.mu.Lock()
	file := cl
	s.clearFile = &file
	s.mu.Unlock()
	// Match against the stream as it stands, even when the run's settle
	// could not read it: a clear whose append reported an error but was
	// committed is applied here, and not written a second time, which C8
	// 0.2 breaks the chain on.
	if err := s.fold(ctx, true); err != nil {
		if s.foldOK(err) {
			s.refuseClear("read "+key, cl.AssetID, "the audit stream could not be read, so the clear was not matched; nothing cleared: "+err.Error())
		}
		return
	}
	s.mu.Lock()
	sp, ok := s.susp[cl.AssetID]
	unwritten := slices.ContainsFunc(s.unaudited, func(u unaudited) bool { return u.assetID == cl.AssetID && u.sp.Ref == cl.Ref })
	s.mu.Unlock()
	if !ok || sp.Ref != cl.Ref {
		if !ok && s.collectorClearing(cl.AssetID, cl.Ref) {
			// The node cleared it; the file stays until the collector has
			// accepted the clear too, since it reads the same file.
			return
		}
		s.refuseClear(key, cl.AssetID, fmt.Sprintf("%s names suspension %s, which this asset does not hold; nothing cleared", ClearSuspensionFileName, cl.Ref))
		return
	}
	if unwritten {
		s.refuseClear("unaudited "+key, cl.AssetID, fmt.Sprintf("suspension %s is not yet in the audit stream; nothing cleared, and the clear waits until it is", cl.Ref))
		return
	}
	if err := s.commitSuspensionRecord(ctx, audit.ActionAssetSuspensionClear, cl.AssetID, sp, "", "cleared by "+ClearSuspensionFileName); err != nil {
		s.refuseClear("audit "+key, cl.AssetID, "clear not recorded in the audit stream, so not applied: "+err.Error())
		return
	}
	// The clear applies from the stream, as at a start: settle's fold
	// finds it and lifts the suspension. A checkpoint that still holds the
	// cleared suspension errs on the safe side.
	s.settleLocked(ctx)
}

func (s *Scheduler) refuseClear(key, assetID, detail string) {
	s.raiseOnceKey(AlarmSuspensionClearRefused+" "+key, assetID, AlarmSuspensionClearRefused, detail)
}

func (s *Scheduler) suspended(assetID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.susp[assetID]
	return ok
}

// Suspensions returns the node's current suspensions.
func (s *Scheduler) Suspensions() map[string]asset.Suspension {
	s.mu.Lock()
	defer s.mu.Unlock()
	return maps.Clone(s.susp)
}

func (s *Scheduler) publishSuspensions() {
	s.rt.opt.Status.SetSuspensions(s.Suspensions())
	s.rt.opt.Status.SetCollectorClears(s.CollectorClears())
	s.publishCollector()
}

func (s *Scheduler) suspensionsPath() string {
	return filepath.Join(s.rt.cfg.Store.Dir, SuspensionsFileName)
}

// checkpointSeq is the through_seq a checkpoint written now may claim: the
// last audit record applied to the suspensions. Records after it are
// applied again at the next start, which is harmless: applying the same
// records in the same order gives the same result.
func (s *Scheduler) checkpointSeq() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.through
}

func readSuspensions(path string) (suspensionsFile, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return suspensionsFile{}, err
	}
	var f suspensionsFile
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return suspensionsFile{}, fmt.Errorf("%s: %w", path, err)
	}
	if f.Schema != suspensionsSchema {
		return suspensionsFile{}, fmt.Errorf("%s: schema %q", path, f.Schema)
	}
	for id, sp := range f.Suspensions {
		if sp.Ref == "" || sp.Reason == "" {
			return suspensionsFile{}, fmt.Errorf("%s: suspension of %s has no reason or ref", path, id)
		}
	}
	return f, nil
}

// writeSuspensions writes a checkpoint that holds no quarantine exports.
func writeSuspensions(path string, through uint64, m map[string]asset.Suspension, pending []unaudited, cs collectorState, cc map[string]string) error {
	return writeCheckpoint(path, through, m, pending, cs, cc, nil)
}

// quarSnapshot copies the recorded exports for the checkpoint. The caller
// holds s.mu.
func (s *Scheduler) quarSnapshot() map[string]quarantineEntry {
	out := make(map[string]quarantineEntry, len(s.quar))
	for h, e := range s.quar {
		c := *e
		c.Clears = slices.Clone(e.Clears)
		out[h] = c
	}
	return out
}

// writeCheckpoint writes the checkpoint as the status file is written:
// a temporary file, flushed, then renamed.
func writeCheckpoint(path string, through uint64, m map[string]asset.Suspension, pending []unaudited, cs collectorState, cc map[string]string, q map[string]quarantineEntry) error {
	f := suspensionsFile{Schema: suspensionsSchema, ThroughSeq: through, Suspensions: m, Collector: cs, CollectorClears: cc, Quarantine: q}
	for _, u := range pending {
		f.Unaudited = append(f.Unaudited, pendingSuspension{AssetID: u.assetID, Ref: u.sp.Ref, Code: u.code, Adopted: u.adopted})
	}
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".suspensions-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(append(b, '\n')); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
