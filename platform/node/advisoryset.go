package node

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"strconv"
	"time"

	"otsec.local/otsec/contracts/adapter"
	"otsec.local/otsec/contracts/advisory"
	"otsec.local/otsec/contracts/audit"
	"otsec.local/otsec/contracts/authz"
	c5 "otsec.local/otsec/contracts/store"
	"otsec.local/otsec/modules/security/collectorwire"
	"otsec.local/otsec/platform/store/protect"
)

// The advisory set's intake (the node note, section 3; C11 1.5; D4-53). An
// administrator leaves the signed set file in admin_dir as AdvisorySetFile.
// The node reads it at most once per tick, runs C11's seven checks, and
// either refuses it, installs it, or finds it is the set in use. A set is
// stored as the envelope's exact bytes, one record on AdvisoryStream, and
// is in use only once its advisory.set_installed record is in the chain.

// R9's alarms. Each is raised once for its condition and goes to
// platform/health as well as status.
const (
	// AlarmAdvisorySetRefused: a set file failed one of C11's checks, or
	// the stored set in use no longer verifies against the anchors pinned
	// now. Raised once per file SHA-256, with the C11 code.
	AlarmAdvisorySetRefused = "advisory-set-refused"
	// AlarmAdvisorySetNoRoom: a set that passed C11's checks would leave
	// the configuration class above the item 3 ceiling, so it is not
	// installed and the set in use stays (C3 and C1 on #444). Raised once
	// per file SHA-256, with the set's ID and version, the bytes needed and
	// the bytes free. No advisory.set_refused is written: it is a storage
	// refusal, not one of C11's.
	AlarmAdvisorySetNoRoom = "advisory-set-no-room"
	// AlarmAdvisorySetUnread: the set file is there but the protected-file
	// rule refused it (owner, mode or ACL, a link, or over
	// MaxEnvelopeBytes+1 bytes), so it was not read.
	AlarmAdvisorySetUnread = "advisory-set-unread"
	// AlarmAdvisorySetNotStored: a set that passed every check could not be
	// stored, or its advisory.set_installed could not be written. A stored
	// set waits for its record, which is tried again at every tick.
	AlarmAdvisorySetNotStored = "advisory-set-not-stored"
	// AlarmApplicabilityNoSet: applicability is on and no set is in use.
	AlarmApplicabilityNoSet = "applicability-no-set"
	// AlarmAdvisorySetsOverFloor: at start, the configuration quota is below
	// the floor plus every stored set beyond the two the floor counts, each
	// at its stored size. The node still starts (C5 0.8 section 5).
	AlarmAdvisorySetsOverFloor = "advisory-sets-over-floor"
	// AlarmAdvisoryStateUnknown: the stored sets or the chain could not be
	// read, so no set is in use and no file is read until they can be.
	AlarmAdvisoryStateUnknown = "advisory-state-unknown"
)

// R9's health event types on platform/health.
const (
	HealthAdvisorySetRefused   = "advisory.set-refused"
	HealthAdvisorySetNoRoom    = "advisory.set-no-room"
	HealthApplicabilityNoSet   = "applicability.no-set"
	HealthAdvisorySetsOver     = "advisory.sets-over-floor"
	HealthAdvisorySetInstalled = "advisory.set-installed"
)

// advisoryRun is R9's set state. Only the scheduler's goroutine uses it.
type advisoryRun struct {
	anchors []advisory.Anchor
	loaded  bool
	// floor is C11's floor: the newest stored set whose
	// advisory.set_installed is in the chain. It is derived at start and
	// stored nowhere else.
	floor advisory.Floor
	// inUse is the set the matcher runs under, nil when none is.
	inUse *advisory.Verified
	since time.Time
	// pending is a stored set whose advisory.set_installed is not written
	// yet, with the floor it replaces.
	pending     *advisory.Verified
	pendingPrev uint64
	// refused holds the file hashes whose refusal is in the chain, with the
	// code; noRoom the hashes whose no-room alarm was raised.
	refused map[[32]byte]string
	noRoom  map[[32]byte]bool
	// checked holds the file hashes given a verdict under this process's
	// anchors, so a refused file is not verified again at every tick.
	checked map[[32]byte]bool
	// inUseFile is the hash of a file found to be the set in use, so it is
	// not verified again at every tick.
	inUseFile [32]byte
	stored    int
	last      *AdvisoryRefusalStatus
}

// checkAdvisorySetRecord is ConfigDocuments for a C11 envelope (C5 0.8: C11's
// strict decode, bounded at MaxEnvelopeBytes). The signature is not checked
// here: the store's validator has no anchors. The node verifies the set
// before it stores it, and again at every start.
func checkAdvisorySetRecord(document []byte, capture *c5.Capture) (c5.DocumentInfo, error) {
	if capture != nil {
		return c5.DocumentInfo{}, errors.New("configuration document: an advisory set has no capture")
	}
	if _, _, err := decodeStoredSet(document); err != nil {
		return c5.DocumentInfo{}, err
	}
	return c5.DocumentInfo{Kind: c5.DocumentEvidence, Series: c5.SeriesAdvisorySet}, nil
}

// decodeStoredSet decodes an envelope and its payload strictly, without the
// signature.
func decodeStoredSet(document []byte) (*advisory.Envelope, *advisory.Set, error) {
	if len(document) > advisory.MaxEnvelopeBytes {
		return nil, nil, fmt.Errorf("configuration document: an advisory set is over %d bytes", advisory.MaxEnvelopeBytes)
	}
	var env advisory.Envelope
	if err := collectorwire.DecodeStrict(document, &env); err != nil {
		return nil, nil, fmt.Errorf("configuration document: the advisory envelope does not decode strictly: %w", err)
	}
	set, err := advisory.Decode(env.Payload)
	if err != nil {
		return nil, nil, fmt.Errorf("configuration document: %w", err)
	}
	if set.Contract != env.Contract {
		return nil, nil, errors.New("configuration document: the advisory payload's contract differs from the envelope's")
	}
	return &env, set, nil
}

func newAdvisoryRun(cfg *Config) *advisoryRun {
	if !cfg.ApplicabilityOn() {
		return nil
	}
	anchors, err := cfg.Applicability.advisoryAnchors()
	if err != nil {
		// The configuration was checked at load.
		panic(fmt.Sprintf("node: advisory anchors passed the load check and now fail: %v", err))
	}
	return &advisoryRun{anchors: anchors, refused: map[[32]byte]string{}, noRoom: map[[32]byte]bool{}, checked: map[[32]byte]bool{}}
}

// startAdvisory loads the set state at start, so the set in use is known
// before the first run.
func (s *Scheduler) startAdvisory(ctx context.Context) {
	if s.adv == nil {
		return
	}
	if err := s.loadAdvisory(ctx); err != nil {
		s.raiseOnceKey(AlarmAdvisoryStateUnknown, "", AlarmAdvisoryStateUnknown, "no advisory set is in use and the set file is not read until the stored sets and the chain can be read: "+err.Error())
	}
	s.publishApplicability()
}

// stepAdvisory runs one tick of the set's intake: load the state if it is
// not loaded, write a pending installation record, then read the file.
func (s *Scheduler) stepAdvisory(ctx context.Context) {
	a := s.adv
	if a == nil {
		return
	}
	if !a.loaded {
		if err := s.loadAdvisory(ctx); err != nil {
			s.raiseOnceKey(AlarmAdvisoryStateUnknown, "", AlarmAdvisoryStateUnknown, "no advisory set is in use and the set file is not read until the stored sets and the chain can be read: "+err.Error())
			return
		}
		s.clearQuietKey(AlarmAdvisoryStateUnknown)
	}
	if a.pending != nil {
		s.writeInstalled(ctx)
	}
	s.readSetFile(ctx)
	if s.evalAll {
		s.evaluateAll(ctx)
	}
	s.publishApplicability()
}

// loadAdvisory derives the floor and the set in use from the store and the
// chain (the note section 3, D4-53). It writes nothing but a missing
// installation record for the newest stored set, after verifying it.
func (s *Scheduler) loadAdvisory(ctx context.Context) error {
	a := s.adv
	db, adb := s.rt.Store(AdvisoryStream), s.rt.Store(AuditStream)
	if db == nil {
		return errors.New("configuration database not open")
	}
	if adb == nil {
		return errAuditNotOpen
	}
	var sets []c5.Stored
	for after := c5.Seq(0); ; {
		got, err := db.Read(ctx, AdvisoryStream, after, 64)
		if err != nil {
			return err
		}
		sets = append(sets, got...)
		if len(got) < 64 {
			break
		}
		after = got[len(got)-1].Key.Seq
	}

	anchor, err := adb.ChainAnchor(ctx, AuditStream)
	if err != nil {
		return err
	}
	installed := map[string]*audit.Advisory{}
	var newest *audit.Advisory
	var firstRetained time.Time
	for after := c5.Seq(0); ; {
		got, err := adb.Read(ctx, AuditStream, after, 500)
		if err != nil {
			return err
		}
		for _, st := range got {
			if firstRetained.IsZero() {
				firstRetained = st.CommittedAt
			}
			after = st.Key.Seq
			if !bytes.Contains(st.Event, []byte(`"advisory.`)) && !bytes.Contains(st.Event, []byte(`\u`)) {
				continue
			}
			rec, err := audit.ParseRecord(st.Event)
			if err != nil {
				return fmt.Errorf("audit record %d: %w", st.Key.Seq, err)
			}
			switch {
			case rec.Action == audit.ActionAdvisorySetInstalled && rec.Advisory != nil:
				installed[rec.Advisory.PayloadSHA256] = rec.Advisory
				newest = rec.Advisory
			case rec.Action == audit.ActionAdvisorySetRefused && rec.Advisory != nil:
				if sum, err := hex.DecodeString(rec.Advisory.FileSHA256); err == nil && len(sum) == 32 {
					a.refused[[32]byte(sum)] = rec.ReasonCode
				}
			}
		}
		if len(got) < 500 {
			break
		}
	}

	a.stored, a.inUse, a.pending, a.floor = len(sets), nil, nil, advisory.Floor{}
	s.checkSetsOverFloor(ctx, sets)
	if newest != nil {
		if sum, err := hex.DecodeString(newest.PayloadSHA256); err == nil && len(sum) == 32 {
			// The chain's newest installation is the floor whatever the
			// store holds, so a stored set that is missing or no longer
			// decodes cannot lower it and let an older set install (C3 on
			// #452). The node then has no set until a newer one arrives.
			a.floor = advisory.Floor{SetID: newest.SetID, Version: newest.Version, PayloadSHA256: [32]byte(sum)}
		}
	}
	a.loaded = true
	if len(sets) == 0 {
		s.noSet(ctx, "no advisory set is installed yet")
		return nil
	}

	n := sets[len(sets)-1]
	env, set, err := decodeStoredSet(n.Event)
	if err != nil {
		// The store's validator passed it at commit, so the store changed
		// under the node. Nothing older is used in its place.
		s.noSet(ctx, fmt.Sprintf("the newest stored set (seq %d) no longer decodes: %v", n.Key.Seq, err))
		return nil
	}
	payloadSum := sha256.Sum256(env.Payload)
	rec := installed[hex.EncodeToString(payloadSum[:])]
	// The installation record follows the set's commit. If the chain was
	// pruned past the set's commit, a missing record may have been pruned,
	// so the set is taken as recorded; otherwise it was never written.
	pruned := anchor.Seq > 0 && (firstRetained.IsZero() || firstRetained.After(n.CommittedAt))
	v, ref := advisory.Verify(n.Event, a.anchors)
	switch {
	case (rec != nil || pruned) && a.floor.Held() && set.Version < a.floor.Version:
		// The chain installed a newer set than any the store holds.
		s.noSet(ctx, fmt.Sprintf("the newest installed set (%s version %d) is not in the store, and no older set is used in its place", a.floor.SetID, a.floor.Version))
		return nil
	case rec != nil || pruned:
		a.floor = advisory.Floor{SetID: set.SetID, Version: set.Version, PayloadSHA256: payloadSum}
	case a.floor.Held() && set.Version <= a.floor.Version:
		// A stored set with no record that is not newer than the floor was
		// not written by this node's install path: it is not repaired, so
		// it cannot hold the intake pending, and nothing older is used
		// (C6 on #452).
		s.noSet(ctx, fmt.Sprintf("the newest stored set (%s version %d) has no installation record and is not newer than the floor (version %d); it is not used", set.SetID, set.Version, a.floor.Version))
		return nil
	case ref == nil:
		// A crash fell between the set's commit and its record: write it
		// now, after verifying the set (D4-26's order).
		a.pending, a.pendingPrev = v, a.floor.Version
		s.writeInstalled(ctx)
		return nil
	}
	if ref != nil {
		// The newest set no longer verifies against the anchors pinned
		// now (a revoked or unpinned key). No set is in use, and no older
		// one is used in its place (C11 1.5, D4-53).
		s.refusedAlarm(ctx, ref, "the newest stored set")
		s.noSet(ctx, fmt.Sprintf("the newest stored set (%s version %d) no longer verifies: %s", set.SetID, set.Version, ref.Code))
		return nil
	}
	s.useSet(ctx, v, n.CommittedAt)
	return nil
}

// storedSetsSizes returns each stored set's size, oldest first.
func (s *Scheduler) storedSetsSizes(sets []c5.Stored) []int64 {
	out := make([]int64, len(sets))
	for i, st := range sets {
		out[i] = int64(len(st.Event))
	}
	return out
}

// checkSetsOverFloor compares the quota with the floor plus every stored set
// beyond the two the floor counts, oldest first, each at its stored size.
func (s *Scheduler) checkSetsOverFloor(ctx context.Context, sets []c5.Stored) {
	sizes := s.storedSetsSizes(sets)
	var extra int64
	for i := 0; i+2 < len(sizes); i++ {
		extra += sizes[i]
	}
	quota := s.rt.cfg.Store.Quotas[string(c5.ClassConfiguration)]
	need := s.rt.cfg.configModuleFloor() + s.rt.cfg.item3Floor() + extra
	if extra == 0 || quota >= need {
		return
	}
	detail := fmt.Sprintf("store.quotas.configuration is %d bytes, below the floor with every stored set: %d bytes (%d stored sets, %d bytes beyond the two the floor counts); the node runs, and the ceiling refuses item 3 writes before configuration monitoring is reached",
		quota, need, len(sizes), extra)
	s.raiseOnceKey(AlarmAdvisorySetsOverFloor, "", AlarmAdvisorySetsOverFloor, detail)
	s.rt.health(ctx, HealthAdvisorySetsOver, map[string]string{"quota_bytes": strconv.FormatInt(quota, 10), "floor_bytes": strconv.FormatInt(need, 10)})
}

// readSetFile reads the set file, if there is one, and acts on it.
func (s *Scheduler) readSetFile(ctx context.Context) {
	a := s.adv
	path := filepath.Join(s.rt.cfg.AdminDir, AdvisorySetFile)
	// The read is bounded at one byte over the envelope's bound, so C11's
	// step 1 refuses a file of that size as malformed. A larger one is
	// refused by the read itself and is not read at all.
	file, err := protect.ReadFileFor(path, advisory.MaxEnvelopeBytes+1, AdminReaders())
	if errors.Is(err, fs.ErrNotExist) {
		s.clearQuietPrefix(AlarmAdvisorySetUnread + " ")
		return
	}
	if err != nil {
		s.raiseOnceKey(AlarmAdvisorySetUnread+" "+err.Error(), "", AlarmAdvisorySetUnread, AdvisorySetFile+" is not read: "+err.Error())
		return
	}
	s.clearQuietPrefix(AlarmAdvisorySetUnread + " ")
	sum := sha256.Sum256(file)
	if code, ok := a.refused[sum]; ok && (a.checked[sum] || !anchorDependent(code)) {
		// Its refusal is in the chain: once per file hash (C11 1.5). A
		// refusal that depends on the anchors is given one more verdict
		// under the anchors loaded now (C6 and C3 on #452).
		s.lastRefusal(sum, code)
		return
	}
	if a.inUse != nil && sum == a.inUseFile {
		return
	}
	v, ref := advisory.Verify(file, a.anchors)
	outcome := advisory.Outcome(0)
	if ref == nil {
		outcome, _, ref = advisory.Admit(v, a.floor, advisoryTestBuild)
	}
	switch {
	case ref != nil && a.refused[sum] == string(ref.Code):
		// The same verdict as the recorded one: nothing new is written.
		a.checked[sum] = true
		s.lastRefusal(sum, string(ref.Code))
		return
	case ref != nil:
		s.refuseSet(ctx, ref)
		return
	case outcome == advisory.InUse:
		a.inUseFile = sum
		return
	case a.pending != nil:
		// A stored set waits for its record: nothing else is installed
		// until it is written.
		return
	}
	if _, err := s.storeItem3(ctx, AdvisoryStream, file, nil); err != nil {
		var full *ceilingError
		if errors.As(err, &full) {
			s.noRoomAlarm(ctx, v, full)
			return
		}
		s.raiseOnceKey(AlarmAdvisorySetNotStored+" "+hex.EncodeToString(sum[:]), "", AlarmAdvisorySetNotStored,
			fmt.Sprintf("set %s version %d passed every check and was not stored: %v; the set in use stays, and the file is read again at the next tick", v.Set.SetID, v.Set.Version, err))
		return
	}
	a.stored++
	a.pending, a.pendingPrev = v, a.floor.Version
	s.writeInstalled(ctx)
}

// writeInstalled writes the pending set's advisory.set_installed. Only once
// it is in the chain does the set come into use and the floor move.
func (s *Scheduler) writeInstalled(ctx context.Context) {
	a := s.adv
	v := a.pending
	node := string(s.rt.cfg.NodeID)
	rec := &audit.Record{Contract: audit.ContractID, NodeID: node, Time: s.rt.received(),
		Actor: audit.Actor{Type: authz.PrincipalNode, ID: node}, Action: audit.ActionAdvisorySetInstalled, Outcome: audit.OutcomeSucceeded,
		Advisory: &audit.Advisory{SetID: v.Set.SetID, Version: v.Set.Version, IssuedAt: v.Set.IssuedAt, PayloadSHA256: hex.EncodeToString(v.PayloadSHA256[:]),
			KeyID: v.KeyID, PreviousVersion: a.pendingPrev}}
	if _, err := s.appendConfigRecord(ctx, rec); err != nil {
		s.raiseOnceKey(AlarmAdvisorySetNotStored+" installed "+hex.EncodeToString(v.PayloadSHA256[:]), "", AlarmAdvisorySetNotStored,
			fmt.Sprintf("set %s version %d is stored but advisory.set_installed was not written: %v; it is not in use until the record is written, which is tried again at every tick", v.Set.SetID, v.Set.Version, err))
		return
	}
	a.pending = nil
	a.floor = advisory.Floor{SetID: v.Set.SetID, Version: v.Set.Version, PayloadSHA256: v.PayloadSHA256}
	s.rt.health(ctx, HealthAdvisorySetInstalled, map[string]string{"set_id": v.Set.SetID, "version": strconv.FormatUint(v.Set.Version, 10),
		"payload_sha256": hex.EncodeToString(v.PayloadSHA256[:])})
	s.useSet(ctx, v, s.now())
}

// useSet makes v the set in use.
func (s *Scheduler) useSet(ctx context.Context, v *advisory.Verified, since time.Time) {
	a := s.adv
	a.inUse, a.since, a.inUseFile = v, since.UTC(), v.FileSHA256
	s.evalAll = true
	s.clearQuietKey(AlarmApplicabilityNoSet)
	s.publishApplicability()
}

// noSet records that no set is in use, raising applicability-no-set once.
func (s *Scheduler) noSet(ctx context.Context, why string) {
	s.adv.inUse = nil
	s.mu.Lock()
	raised := s.quiet[AlarmApplicabilityNoSet]
	s.mu.Unlock()
	if !raised {
		s.raiseOnceKey(AlarmApplicabilityNoSet, "", AlarmApplicabilityNoSet, why+"; no finding is computed until a set is in use")
		s.rt.health(ctx, HealthApplicabilityNoSet, map[string]string{"reason": why})
	}
	s.publishApplicability()
}

// refuseSet writes advisory.set_refused for a refused file, once per file
// hash, and raises the alarm. If the record cannot be written the set is
// still refused, and the alarm says the refusal was not recorded; the next
// tick writes it.
func (s *Scheduler) refuseSet(ctx context.Context, ref *advisory.Refusal) {
	a := s.adv
	node := string(s.rt.cfg.NodeID)
	rec := &audit.Record{Contract: audit.ContractID, NodeID: node, Time: s.rt.received(),
		Actor: audit.Actor{Type: authz.PrincipalNode, ID: node}, Action: audit.ActionAdvisorySetRefused, Outcome: audit.OutcomeDenied,
		ReasonCode: string(ref.Code),
		Advisory:   &audit.Advisory{FileSHA256: hex.EncodeToString(ref.FileSHA256[:]), KeyID: ref.KeyID, SetID: ref.SetID, Version: ref.Version}}
	if _, err := s.appendConfigRecord(ctx, rec); err != nil {
		s.raiseOnceKey(AlarmAdvisorySetRefused+" unrecorded "+hex.EncodeToString(ref.FileSHA256[:]), "", AlarmAdvisorySetRefused,
			fmt.Sprintf("%s refused (%s), and the refusal was not recorded: %v; the set in use stays, and the record is written at the next tick", AdvisorySetFile, ref.Code, err))
		return
	}
	a.refused[ref.FileSHA256] = string(ref.Code)
	a.checked[ref.FileSHA256] = true
	s.refusedAlarm(ctx, ref, AdvisorySetFile)
}

// anchorDependent reports whether a refusal depends on the anchors pinned,
// which change only at a load: a file refused for its key may install once
// its key is pinned. The other codes depend on the file and the floor only.
func anchorDependent(code string) bool {
	switch advisory.Code(code) {
	case advisory.UnknownKey, advisory.RevokedKey, advisory.BadSignature:
		return true
	}
	return false
}

// lastRefusal shows a recorded refusal in status.
func (s *Scheduler) lastRefusal(sum [32]byte, code string) {
	a := s.adv
	if a.last == nil || a.last.FileSHA256 != hex.EncodeToString(sum[:]) {
		a.last = &AdvisoryRefusalStatus{FileSHA256: hex.EncodeToString(sum[:]), Code: code, At: s.now().UTC()}
	}
}

// refusedAlarm raises advisory-set-refused for one file hash.
func (s *Scheduler) refusedAlarm(ctx context.Context, ref *advisory.Refusal, what string) {
	sum := hex.EncodeToString(ref.FileSHA256[:])
	s.adv.last = &AdvisoryRefusalStatus{FileSHA256: sum, Code: string(ref.Code), Detail: ref.Detail, SetID: ref.SetID, Version: ref.Version, At: s.now().UTC()}
	detail := ref.Detail
	if len(detail) > adapter.MaxDetailLen {
		detail = detail[:adapter.MaxDetailLen]
	}
	s.raiseOnceKey(AlarmAdvisorySetRefused+" "+sum, "", AlarmAdvisorySetRefused, fmt.Sprintf("%s (sha256 %s) is refused: %s %q", what, sum, ref.Code, detail))
	d := map[string]string{"file_sha256": sum, "code": string(ref.Code)}
	if ref.SetID != "" {
		d["set_id"], d["version"] = ref.SetID, strconv.FormatUint(ref.Version, 10)
	}
	if ref.KeyID != "" {
		d["key_id"] = ref.KeyID
	}
	s.rt.health(ctx, HealthAdvisorySetRefused, d)
	s.publishApplicability()
}

// noRoomAlarm raises advisory-set-no-room once per file hash. The file stays
// and is tried again at every tick, so it installs once room returns.
func (s *Scheduler) noRoomAlarm(ctx context.Context, v *advisory.Verified, e *ceilingError) {
	a := s.adv
	sum := hex.EncodeToString(v.FileSHA256[:])
	a.last = &AdvisoryRefusalStatus{FileSHA256: sum, Code: AlarmAdvisorySetNoRoom, SetID: v.Set.SetID, Version: v.Set.Version, At: s.now().UTC(),
		Detail: fmt.Sprintf("%d bytes needed, %d bytes free under the item 3 ceiling", e.need, e.free)}
	if a.noRoom[v.FileSHA256] {
		return
	}
	a.noRoom[v.FileSHA256] = true
	s.rt.opt.Status.Raise("", AlarmAdvisorySetNoRoom, fmt.Sprintf("%s (sha256 %s, set %s version %d) passed C11's checks and is not installed: it needs %d bytes and %d bytes are free under the item 3 ceiling; the set in use stays",
		AdvisorySetFile, sum, v.Set.SetID, v.Set.Version, e.need, e.free))
	s.rt.health(ctx, HealthAdvisorySetNoRoom, map[string]string{"file_sha256": sum, "set_id": v.Set.SetID, "version": strconv.FormatUint(v.Set.Version, 10),
		"bytes_needed": strconv.FormatInt(e.need, 10), "bytes_free": strconv.FormatInt(e.free, 10)})
	s.publishApplicability()
}

// publishApplicability puts R9's set state in status.
func (s *Scheduler) publishApplicability() {
	a := s.adv
	if a == nil {
		return
	}
	st := &ApplicabilityStatus{StoredSets: a.stored, Assets: s.findingsStatus()}
	if v := a.inUse; v != nil {
		st.SetInUse = &AdvisorySetStatus{SetID: v.Set.SetID, Version: v.Set.Version, IssuedAt: v.Set.IssuedAt,
			PayloadSHA256: hex.EncodeToString(v.PayloadSHA256[:]), KeyID: v.KeyID, InUseSince: a.since}
	}
	if a.last != nil {
		l := *a.last
		st.LastRefusal = &l
	}
	s.rt.opt.Status.SetApplicability(st)
	s.rt.opt.Status.Write(string(s.rt.cfg.NodeID))
}
