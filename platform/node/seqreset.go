package node

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"slices"

	"otsec.local/otsec/contracts/audit"
	"otsec.local/otsec/contracts/authz"
	c5 "otsec.local/otsec/contracts/store"
	"otsec.local/otsec/modules/security/collectorwire"
	"otsec.local/otsec/modules/security/seal"
	"otsec.local/otsec/platform/store/protect"
)

// The node finds a collector reset, a reinstall that lost the collector's
// stores and so restarted its collector_seq at 1, and holds all
// credentialed collection until an administrator acknowledges it (A1
// D2-15, C8 0.2, docs/phase2/A3-c8-seq-reset.md). A fresh collector has
// lost its failed-auth floors, so collecting before an administrator has
// looked could reach an asset the old collector was protecting.
//
//   - The install key the node trusts is in the audit stream from the
//     first start, as collector.install_key, written before the first
//     request.
//   - Before each request, the node reads the collector's install-key.json.
//     A key it does not trust is a reinstall: it writes collector.seq_reset
//     and sends nothing.
//   - As a backstop, a reply numbered at or below the highest collector_seq
//     of the current epoch is a reset. If the key changed in between, the
//     reset record goes first in that reply's batch, with first_seen. If it
//     did not, it is a restore of old collector stores, or an impostor, and
//     is never acknowledged: collection stays held until the collector is
//     reinstalled with a new key.
//   - The administrator acknowledges by writing seq-reset-ack.json in
//     admin_dir naming the open reset's key; the node writes
//     collector.seq_reset_ack and resumes.
//
// The state follows from the audit stream (fold), so it survives a restart.
const (
	// AlarmInstallKeyUnreadable: install-key.json could not be read, so
	// the node cannot tell whether the collector was reinstalled. Nothing
	// is sent.
	AlarmInstallKeyUnreadable = "collector-install-key-unreadable"
	// AlarmCollectorReset: the collector was reinstalled. Nothing is sent
	// until an administrator acknowledges the new key.
	AlarmCollectorReset = "collector-reset"
	// AlarmCollectorRestored: the collector's numbering went back while its
	// install key stayed the same, or its install key is one the node
	// trusted or recorded a reset for before. A reinstall makes a new key,
	// so either is a restore of old stores or another process (W-1).
	// Nothing is sent, no reset is written, and it is never acknowledged
	// (D2-15; A3, A6 and A1 on #109).
	AlarmCollectorRestored = "collector-restored"
	// AlarmResetAckRefused: seq-reset-ack.json names no open reset's key.
	AlarmResetAckRefused = "collector-reset-ack-refused"
	// AlarmResetAcknowledged: an administrator acknowledged the reset;
	// collection resumes.
	AlarmResetAcknowledged = "collector-reset-acknowledged"
)

// InstallKeyFileName is the collector's public install key in
// collector_public_dir. The collector writes it at every start, before it
// serves, by a temporary file and a rename (A3 #106).
const InstallKeyFileName = "install-key.json"

// InstallKeySchema identifies install-key.json (A3 #106).
const InstallKeySchema = "otsec.collector.install_key/0.1"

// SeqResetAckFileName is the file an administrator writes in admin_dir to
// acknowledge a reset: {"schema": SeqResetAckSchema, "install_key_id": the
// key they confirmed by fingerprint (T-12)}. It is the Phase 2 interim;
// before any device-observed endpoint it becomes an admin-signed C7
// request (D2-15).
const SeqResetAckFileName = "seq-reset-ack.json"

const (
	SeqResetAckSchema  = "otsec.seq-reset-ack/0.1"
	maxInstallKeyBytes = 4 << 10
)

// collectorState is what the audit stream says about the collector's
// numbering, kept in the checkpoint beside the suspensions.
type collectorState struct {
	// TrustedKey is the install key the node trusts: from
	// collector.install_key, then from each acknowledged reset.
	TrustedKey string `json:"trusted_key,omitempty"`
	// OpenResetKey is the key of a collector.seq_reset not yet
	// acknowledged.
	OpenResetKey string `json:"open_reset_key,omitempty"`
	// High is the highest collector_seq recorded in the current epoch.
	High uint64 `json:"high,omitempty"`
	// Restored is set when a collector_seq at or below High was recorded
	// with no reset before it. Only a reset clears it.
	Restored *restored `json:"restored,omitempty"`
	// UsedKeys is every key the node has trusted or written a reset for.
	// A reinstall makes a new key, so a key seen before is a restore or
	// another process, never a reset (C8 0.2 breaks the chain on a reset
	// repeating an earlier one's key; A1 on #109).
	UsedKeys []string `json:"used_keys,omitempty"`
}

func (cs *collectorState) used(key string) bool { return slices.Contains(cs.UsedKeys, key) }

func (cs *collectorState) use(key string) {
	if !cs.used(key) {
		cs.UsedKeys = append(slices.Clone(cs.UsedKeys), key)
	}
}

type restored struct {
	High uint64 `json:"high"`
	Seen uint64 `json:"seen"`
}

// applyCollector applies one audit record to cs. A node-state record the
// node would not have written (a reset that keeps the trusted key, an
// acknowledgement of no open reset, a second trusted key) is an error: the
// state cannot be rebuilt past it.
func applyCollector(cs *collectorState, rec *audit.Record) error {
	switch rec.Action {
	case audit.ActionCollectorInstallKey:
		if cs.OpenResetKey != "" || (cs.TrustedKey != "" && cs.TrustedKey != rec.InstallKeyID) {
			return fmt.Errorf("collector.install_key %s changes the trusted key without an acknowledged reset", rec.InstallKeyID)
		}
		cs.TrustedKey = rec.InstallKeyID
		cs.use(rec.InstallKeyID)
	case audit.ActionCollectorSeqReset:
		if rec.InstallKeyID == cs.TrustedKey {
			return fmt.Errorf("collector.seq_reset keeps the trusted install key %s", rec.InstallKeyID)
		}
		if cs.used(rec.InstallKeyID) {
			return fmt.Errorf("collector.seq_reset repeats install key %s, which was trusted or reset before", rec.InstallKeyID)
		}
		cs.OpenResetKey, cs.High, cs.Restored = rec.InstallKeyID, 0, nil
		cs.use(rec.InstallKeyID)
	case audit.ActionCollectorSeqResetAck:
		if cs.OpenResetKey == "" || cs.OpenResetKey != rec.InstallKeyID {
			return fmt.Errorf("collector.seq_reset_ack names install key %s, which no open reset has", rec.InstallKeyID)
		}
		cs.TrustedKey, cs.OpenResetKey = rec.InstallKeyID, ""
	}
	if n := rec.CollectorSeq; n != 0 {
		if n <= cs.High && cs.Restored == nil {
			cs.Restored = &restored{High: cs.High, Seen: n}
		}
		cs.High = max(cs.High, n)
	}
	return nil
}

// readInstallKey reads the collector's install key ID. The file is public
// and written by the collector; the node checks only that it is a regular
// file, not a link or device, and small (protect.ReadPublicFile). Its integrity comes from the directory's
// DACL (winsvc.Dirs: only the collector, SYSTEM and Administrators can
// write it) and, for an acknowledgement, from the administrator's
// fingerprint check (T-12).
func (s *Scheduler) readInstallKey() (string, error) {
	if s.rt.cfg.CollectorPublicDir == "" {
		return "", errors.New("collector_public_dir is not configured")
	}
	path := filepath.Join(s.rt.cfg.CollectorPublicDir, InstallKeyFileName)
	b, err := protect.ReadPublicFile(path, maxInstallKeyBytes)
	if err != nil {
		return "", err
	}
	var k struct {
		Schema      string `json:"schema"`
		KeyID       string `json:"key_id"`
		PublicKey   string `json:"public_key"`
		Fingerprint string `json:"fingerprint"`
	}
	if err := collectorwire.DecodeStrict(b, &k); err != nil || k.Schema != InstallKeySchema || k.KeyID == "" || k.PublicKey == "" || k.Fingerprint == "" {
		return "", fmt.Errorf("%s is not a %s object with key_id, public_key and fingerprint", path, InstallKeySchema)
	}
	// The key ID an administrator acknowledges must be the key whose
	// fingerprint they confirmed (T-12; A3 on #109): the ID is derived
	// from the key, and so is the fingerprint.
	pub, err := seal.InstallKey{KeyID: k.KeyID, PublicKey: k.PublicKey}.PublicKeyBytes()
	if err != nil {
		return "", fmt.Errorf("%s: %w", path, err)
	}
	if seal.NormalizeFingerprint(k.Fingerprint) != seal.Fingerprint(pub) {
		return "", fmt.Errorf("%s: the fingerprint is not the public key's", path)
	}
	return k.KeyID, nil
}

// collectorRecord is the node's C8 0.2 record of the collector's key or a
// reset.
func (s *Scheduler) collectorRecord(action audit.Action, key string, previousHigh *uint64, firstSeen uint64, detail string) (c5.Record, error) {
	rec := audit.Record{Contract: audit.ContractID, NodeID: string(s.rt.cfg.NodeID), Time: s.rt.received(),
		Actor: audit.Actor{Type: authz.PrincipalNode, ID: string(s.rt.cfg.NodeID)}, Action: action, Outcome: audit.OutcomeInfo,
		InstallKeyID: key, PreviousHigh: previousHigh, FirstSeen: firstSeen, Detail: detail}
	b, err := json.Marshal(rec)
	if err != nil {
		return c5.Record{}, err
	}
	if _, err := audit.ValidatePending(b); err != nil {
		return c5.Record{}, err
	}
	return c5.Record{Stream: AuditStream, Class: c5.ClassAudit, Event: b}, nil
}

func (s *Scheduler) commitAudit(ctx context.Context, recs ...c5.Record) error {
	if _, log, mode := s.rt.view(s.rt.find(AuditDB)); log == nil || !mode.AcceptsEvents() {
		return fmt.Errorf("audit database is %s", s.rt.Mode(AuditDB))
	} else if _, err := log.AppendBatch(ctx, recs); err != nil {
		return err
	}
	return nil
}

// collectorHold reports why no request may be sent to the collector now,
// writing collector.install_key or collector.seq_reset first when the key
// calls for one. It is checked before every request.
func (s *Scheduler) collectorHold(ctx context.Context) (code, detail string) {
	code, detail = s.collectorHoldReason(ctx)
	s.mu.Lock()
	s.collHold = code
	s.mu.Unlock()
	return code, detail
}

func (s *Scheduler) collectorHoldReason(ctx context.Context) (string, string) {
	key, err := s.readInstallKey()
	if err != nil {
		return AlarmInstallKeyUnreadable, "the collector's install key could not be read, so a reinstall cannot be ruled out; nothing is sent: " + err.Error()
	}
	s.settleMu.Lock()
	defer s.settleMu.Unlock()
	// Decide on the stream as it stands, even when the run's settle could
	// not read it: a record whose append reported an error but was
	// committed is applied here, and not written again, which C8 0.2
	// breaks the chain on (a second install_key, a reset repeating a key).
	if err := s.fold(ctx, true); err != nil {
		if !s.foldOK(err) {
			return AlarmSuspensionsUnknown, "the audit stream cannot be applied past a record; nothing is sent: " + err.Error()
		}
		return AlarmAuditUnavailable, "the audit stream could not be read, so the collector's install key cannot be checked against it; nothing is sent: " + err.Error()
	}
	s.mu.Lock()
	cs := s.cs
	s.mu.Unlock()
	var rec c5.Record
	switch {
	case cs.TrustedKey == "" && cs.OpenResetKey == "":
		// The first start, or the first 0.2 start: the key is in the chain
		// before the first request (A6 on #105).
		rec, err = s.collectorRecord(audit.ActionCollectorInstallKey, key, nil, 0, "install key trusted at the node's first start")
	case key != cs.TrustedKey && key != cs.OpenResetKey && cs.used(key):
		return AlarmCollectorRestored, fmt.Sprintf("the collector's install key %s is an earlier key: the node trusted it or recorded a reset to it before (trusted key %s). A reinstall makes a new key, so old stores were restored or another process answered. Nothing is sent, and this is not acknowledged; reinstall the collector", key, keyOrNone(cs.TrustedKey))
	case key != cs.TrustedKey && key != cs.OpenResetKey:
		high := cs.High
		rec, err = s.collectorRecord(audit.ActionCollectorSeqReset, key, &high, 0, "install key changed before a request: the collector was reinstalled")
	}
	if rec.Event != nil {
		if err == nil {
			err = s.commitAudit(ctx, rec)
		}
		if err == nil {
			err = s.fold(ctx, true)
		}
		if err != nil {
			return AlarmAuditUnavailable, "the collector's install key changed or is new, and its audit record was not written; nothing is sent: " + err.Error()
		}
		s.mu.Lock()
		cs = s.cs
		s.mu.Unlock()
		s.publishCollector()
	}
	switch {
	case cs.OpenResetKey != "":
		return AlarmCollectorReset, fmt.Sprintf("the collector was reinstalled: install key %s, trusted key %s. Nothing is sent until an administrator confirms the new key's fingerprint, reviews the suspensions and register revisions, and writes %s naming %s", cs.OpenResetKey, keyOrNone(cs.TrustedKey), SeqResetAckFileName, cs.OpenResetKey)
	case cs.Restored != nil:
		return AlarmCollectorRestored, fmt.Sprintf("collector_seq %d was recorded after %d under the same install key %s: the collector's stores were restored, or another process answered. Nothing is sent, and this is not acknowledged; reinstall the collector", cs.Restored.Seen, cs.Restored.High, cs.TrustedKey)
	}
	return "", ""
}

func keyOrNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}

// resetFirst is the backstop: for a reply whose collector_seq is at or
// below the epoch's high, it returns the collector.seq_reset record to put
// first in the reply's batch when the install key changed since the check
// before the request. With the key unchanged it returns nothing, and the
// reply's own records show the restore when they are applied.
func (s *Scheduler) resetFirst(seq uint64) []c5.Record {
	s.mu.Lock()
	cs := s.cs
	s.mu.Unlock()
	if seq == 0 || seq > cs.High {
		return nil
	}
	key, err := s.readInstallKey()
	if err != nil || key == cs.TrustedKey || key == cs.OpenResetKey || cs.used(key) {
		return nil
	}
	high := cs.High
	rec, err := s.collectorRecord(audit.ActionCollectorSeqReset, key, &high, seq, "a reply's collector_seq went back and the install key changed: the collector was reinstalled")
	if err != nil {
		return nil
	}
	return []c5.Record{rec}
}

// checkAck applies seq-reset-ack.json in admin_dir, if there is one and a
// reset is open. Only a file naming the open reset's key acknowledges it;
// anything else changes nothing and is raised once per file content. A
// file left from an earlier reset, with no reset open, is ignored.
func (s *Scheduler) checkAck(ctx context.Context) {
	s.mu.Lock()
	open := s.cs.OpenResetKey
	s.mu.Unlock()
	if open == "" || s.rt.cfg.AdminDir == "" {
		return
	}
	// As checkClear: only from a directory the node cannot write (A3 on
	// #107).
	if err := protect.CheckDirFor(s.rt.cfg.AdminDir, AdminReaders()); err != nil {
		s.raiseOnceKey(AlarmResetAckRefused+" dir "+err.Error(), "", AlarmResetAckRefused, "admin_dir refused, so "+SeqResetAckFileName+" is not read: "+err.Error())
		return
	}
	path := filepath.Join(s.rt.cfg.AdminDir, SeqResetAckFileName)
	b, err := protect.ReadFileFor(path, MaxClearSuspensionBytes, AdminReaders())
	if errors.Is(err, fs.ErrNotExist) {
		return
	}
	if err != nil {
		s.raiseOnceKey(AlarmResetAckRefused+" err "+err.Error(), "", AlarmResetAckRefused, SeqResetAckFileName+" refused: "+err.Error())
		return
	}
	key := AlarmResetAckRefused + " file " + digest(b)
	// As checkClear: match against the stream as it stands, so an
	// acknowledgement committed despite an append error is not written
	// twice, which breaks the chain.
	s.settleMu.Lock()
	defer s.settleMu.Unlock()
	if err := s.fold(ctx, true); err != nil {
		if s.foldOK(err) {
			s.raiseOnceKey("read "+key, "", AlarmResetAckRefused, "the audit stream could not be read, so the acknowledgement was not matched; nothing acknowledged: "+err.Error())
		}
		return
	}
	s.mu.Lock()
	open = s.cs.OpenResetKey
	s.mu.Unlock()
	if open == "" {
		return
	}
	var ack struct {
		Schema       string `json:"schema"`
		InstallKeyID string `json:"install_key_id"`
	}
	if err := collectorwire.DecodeStrict(b, &ack); err != nil || ack.Schema != SeqResetAckSchema {
		s.raiseOnceKey(key, "", AlarmResetAckRefused, fmt.Sprintf("%s is not a %s object with install_key_id", SeqResetAckFileName, SeqResetAckSchema))
		return
	}
	s.applySeqAck(ctx, SeqResetAckFileName, key, ack.InstallKeyID, open)
}

// applySeqAck acknowledges the open reset on install key open, for an
// acknowledgement that names installKey, from either source:
// seq-reset-ack.json or an accepted node.seq_reset_ack. key is the
// raise-once key. Only an acknowledgement of the open reset's own key
// applies, and only while the collector is still on that key. settleMu is
// held and the chain folded. It returns whether the reset is acknowledged,
// and otherwise why not.
func (s *Scheduler) applySeqAck(ctx context.Context, source, key, installKey, open string) (done bool, why string) {
	refuse := func(k, detail string) (bool, string) {
		s.raiseOnceKey(k, "", AlarmResetAckRefused, detail)
		return false, detail
	}
	if installKey != open {
		return refuse(key, fmt.Sprintf("%s names install key %s; the open reset is on %s; nothing acknowledged", source, installKey, open))
	}
	// The collector must still be on the reset's key: one that went back
	// to an earlier key since is held as restored, not acknowledged.
	if now, err := s.readInstallKey(); err != nil || now != open {
		return refuse("key "+key, fmt.Sprintf("%s names install key %s, but the collector's install key is now %s; nothing acknowledged", source, open, keyOrNone(now)))
	}
	rec, err := s.collectorRecord(audit.ActionCollectorSeqResetAck, open, nil, 0, "acknowledged by "+source)
	if err == nil {
		err = s.commitAudit(ctx, rec)
	}
	if err != nil {
		return refuse("audit "+key, "acknowledgement not recorded in the audit stream, so not applied: "+err.Error())
	}
	// The acknowledgement applies from the stream, as at a start.
	s.settleLocked(ctx)
	s.rt.opt.Status.Raise("", AlarmResetAcknowledged, "reset on install key "+open+" acknowledged by an administrator; collection resumes")
	s.publishCollector()
	return true, ""
}

// publishCollector shows the collector's keys in node status.
func (s *Scheduler) publishCollector() {
	s.mu.Lock()
	cs := s.cs
	s.mu.Unlock()
	st := CollectorStatus{TrustedKey: cs.TrustedKey, OpenResetKey: cs.OpenResetKey, High: cs.High, Restored: cs.Restored != nil}
	s.rt.opt.Status.SetCollector(&st)
	s.rt.opt.Status.Write(string(s.rt.cfg.NodeID))
}
