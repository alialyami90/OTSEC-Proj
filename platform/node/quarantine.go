package node

import (
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"time"

	"otsec.local/otsec/contracts/audit"
	"otsec.local/otsec/contracts/authz"
	c5 "otsec.local/otsec/contracts/store"
	"otsec.local/otsec/modules/security/collectorwire"
	"otsec.local/otsec/platform/store"
	"otsec.local/otsec/platform/store/protect"
)

// Quarantine export and clear (P3-A5; docs/phase3/A5-quarantine-export.md).
// An administrator exports an asset's quarantine stream with the CLI
// (ExportQuarantine), which copies the export's manifest into admin_dir.
// The node checks that manifest against its own stream both ways and
// records quarantine.exported (C8 0.3). An administrator's
// clear-quarantine.json naming a recorded manifest is checked again, item
// by item, recorded as quarantine.cleared before anything is removed, and
// then carried out from that record in C5 Discard steps, one per tick
// (D3-1). Nothing is removed on the node's own initiative.
const (
	QuarantineExportSchema  = "otsec.quarantine-export/0.1"
	ClearQuarantineSchema   = "otsec.clear-quarantine/0.1"
	ClearQuarantineFileName = "clear-quarantine.json"
	// MaxQuarantineManifestBytes and MaxQuarantineItems bound a manifest
	// copy the node reads (A3's limits). An item is about 170 bytes.
	MaxQuarantineManifestBytes = 4 << 20
	MaxQuarantineItems         = 20000
	MaxClearQuarantineBytes    = 4 << 10
)

// Quarantine alarm codes.
const (
	AlarmQuarantineExportRefused   = "quarantine-export-refused"
	AlarmQuarantineExported        = "quarantine-exported"
	AlarmQuarantineClearRefused    = "quarantine-clear-refused"
	AlarmQuarantineClearIncomplete = "quarantine-clear-incomplete"
	AlarmQuarantineCleared         = "quarantine-cleared"
)

// QuarantineExportFileName is the name of an asset's manifest copy in
// admin_dir. The node reads one per scheduled asset, which bounds how many
// it reads.
func QuarantineExportFileName(assetID string) string {
	return "quarantine-export-" + assetID + ".json"
}

// QuarantineManifest is an export's manifest.json: hashes, never content
// (A3-5). Items are every seq the stream stored at export, in order.
type QuarantineManifest struct {
	Schema     string           `json:"schema"`
	NodeID     string           `json:"node_id"`
	AssetID    string           `json:"asset_id"`
	Stream     string           `json:"stream"`
	ExportedAt string           `json:"exported_at"`
	Items      []QuarantineItem `json:"items"`
}

// QuarantineItem is one stored record: its event's SHA-256 and its
// capture's, empty when the record has no capture.
type QuarantineItem struct {
	Seq           uint64 `json:"seq"`
	EventSHA256   string `json:"event_sha256"`
	CaptureSHA256 string `json:"capture_sha256,omitempty"`
}

type clearQuarantine struct {
	Schema         string `json:"schema"`
	AssetID        string `json:"asset_id"`
	ManifestSHA256 string `json:"manifest_sha256"`
	Principal      string `json:"principal"`
}

// quarantineEntry is one quarantine.exported record and what the chain
// holds about its clear, keyed in Scheduler.quar by the manifest hash. The
// checkpoint keeps them (suspensionsFile.Quarantine), so pruning the audit
// stream does not lose them.
type quarantineEntry struct {
	AssetID  string `json:"asset_id"`
	FirstSeq uint64 `json:"first_seq"`
	LastSeq  uint64 `json:"last_seq"`
	Items    uint64 `json:"items"`
	// Cleared: the chain holds a succeeded quarantine.cleared for it, so
	// its range is removed (A1 (a)).
	Cleared bool `json:"cleared,omitempty"`
	// Clears are the clear_sha256 of every quarantine.cleared naming it.
	// A file whose hash is here was applied already and is not read again.
	Clears []string `json:"clears,omitempty"`
}

var sha256Hex = regexp.MustCompile(`^[0-9a-f]{64}$`)

func sha256Of(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// ExportQuarantine is `otsec quarantine export`: it writes every record of
// the asset's quarantine stream, byte for byte, to a new directory dir,
// with manifest.json, and copies the manifest into admin_dir as
// QuarantineExportFileName. It opens the evidence database read-only
// beside a running node and never writes the store. dir must not exist; it
// is created with the store directory's rule (store.CreateDir), because an
// export can hold an unredacted password (A3-5).
func ExportQuarantine(ctx context.Context, cfg *Config, assetID, dir string, now time.Time) (QuarantineManifest, error) {
	stream := QuarantineStream(assetID)
	l, err := cfg.Layout()
	if err != nil {
		return QuarantineManifest{}, err
	}
	var dbID c5.DatabaseID
	for _, d := range l.Databases {
		for _, s := range d.Streams {
			if s.ID == stream {
				dbID = d.ID
			}
		}
	}
	if dbID == "" {
		return QuarantineManifest{}, fmt.Errorf("asset %q has no quarantine stream on this node (it is not scheduled)", assetID)
	}
	if _, err := os.Lstat(dir); err == nil {
		return QuarantineManifest{}, fmt.Errorf("%s exists; an export goes to a new directory (A3-5)", dir)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return QuarantineManifest{}, err
	}
	db, err := store.OpenReadOnly(ctx, cfg.Store.Dir, cfg.NodeID, dbID)
	if err != nil {
		return QuarantineManifest{}, err
	}
	defer db.Close()
	if first, err := db.Read(ctx, stream, 0, 1); err != nil {
		return QuarantineManifest{}, err
	} else if len(first) == 0 {
		return QuarantineManifest{}, fmt.Errorf("%s holds no records; nothing to export", stream)
	}
	if err := store.CreateDir(dir, ""); err != nil {
		return QuarantineManifest{}, err
	}
	m := QuarantineManifest{Schema: QuarantineExportSchema, NodeID: string(cfg.NodeID), AssetID: assetID, Stream: string(stream),
		ExportedAt: now.UTC().Format(time.RFC3339)}
	var after c5.Seq
	for {
		got, err := db.Read(ctx, stream, after, 500)
		if err != nil {
			return QuarantineManifest{}, err
		}
		for _, st := range got {
			n := strconv.FormatUint(uint64(st.Key.Seq), 10)
			it := QuarantineItem{Seq: uint64(st.Key.Seq), EventSHA256: sha256Of(st.Event)}
			if err := writeNew(filepath.Join(dir, n+".event.json"), st.Event); err != nil {
				return QuarantineManifest{}, err
			}
			if st.EvidenceRef != "" {
				c, err := db.ReadCapture(ctx, st.EvidenceRef)
				if err != nil {
					return QuarantineManifest{}, fmt.Errorf("capture of seq %d: %w", st.Key.Seq, err)
				}
				if err := writeNew(filepath.Join(dir, n+".capture"), c.Bytes); err != nil {
					return QuarantineManifest{}, err
				}
				it.CaptureSHA256 = sha256Of(c.Bytes)
			}
			m.Items = append(m.Items, it)
			after = st.Key.Seq
		}
		if len(got) < 500 {
			break
		}
	}
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return QuarantineManifest{}, err
	}
	b = append(b, '\n')
	if err := writeNew(filepath.Join(dir, "manifest.json"), b); err != nil {
		return QuarantineManifest{}, err
	}
	if cfg.AdminDir == "" {
		return m, fmt.Errorf("the export is complete in %s, but the configuration has no admin_dir, so the node cannot read its manifest", dir)
	}
	if err := writeAdminCopy(cfg.AdminDir, QuarantineExportFileName(assetID), b); err != nil {
		return m, fmt.Errorf("the export is complete in %s, but its manifest was not copied to admin_dir: %w; copy manifest.json there as %s, read-only", dir, err, QuarantineExportFileName(assetID))
	}
	return m, nil
}

// writeNew writes a file that must not exist yet.
func writeNew(path string, b []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// writeAdminCopy writes name in admin_dir through a temporary file, so the
// node never reads half a manifest. On Linux the file is 0440, the mode
// the node reads admin files with; on Windows it takes admin_dir's
// inherited DACL, as an administrator's other files there do.
func writeAdminCopy(adminDir, name string, b []byte) error {
	tmp, err := os.CreateTemp(adminDir, ".quarantine-export-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(b); err != nil {
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
	if err := os.Chmod(tmp.Name(), 0o440); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), filepath.Join(adminDir, name))
}

// applyQuarantine applies one audit record to the exports the chain holds.
func applyQuarantine(m map[string]*quarantineEntry, rec *audit.Record) {
	if rec.Quarantine == nil || rec.Target == nil {
		return
	}
	q := rec.Quarantine
	switch rec.Action {
	case audit.ActionQuarantineExported:
		if m[q.ManifestSHA256] == nil {
			m[q.ManifestSHA256] = &quarantineEntry{AssetID: rec.Target.AssetID, FirstSeq: q.FirstSeq, LastSeq: q.LastSeq, Items: q.Items}
		}
	case audit.ActionQuarantineCleared:
		e := m[q.ManifestSHA256]
		if e == nil {
			// The node writes a clear only for a recorded export. The
			// record carries the range, which is all a resume uses.
			e = &quarantineEntry{AssetID: rec.Target.AssetID, FirstSeq: q.FirstSeq, LastSeq: q.LastSeq, Items: q.Items}
			m[q.ManifestSHA256] = e
		}
		if rec.Outcome == audit.OutcomeSucceeded {
			e.Cleared = true
		}
		if !slices.Contains(e.Clears, q.ClearSHA256) {
			e.Clears = append(e.Clears, q.ClearSHA256)
		}
	}
}

// QuarantineTick does the node's part of the export and clear, once per
// Runtime tick: it records each manifest copy in admin_dir that checks out
// against the stream, applies clear-quarantine.json, and takes one Discard
// step of a recorded clear (A1 (c)). It holds settleMu, so the chain's
// records are applied once and in order, and decides only after folding
// the chain as it stands.
func (s *Scheduler) QuarantineTick(ctx context.Context) {
	s.settleMu.Lock()
	defer s.settleMu.Unlock()
	if err := s.fold(ctx, true); err != nil {
		s.foldOK(err)
		return
	}
	if s.rt.cfg.AdminDir != "" {
		if err := protect.CheckDirFor(s.rt.cfg.AdminDir, AdminReaders()); err != nil {
			s.raiseOnceKey("quarantine dir "+err.Error(), "", AlarmQuarantineExportRefused, "admin_dir refused, so quarantine exports and clears are not read: "+err.Error())
		} else {
			s.checkExports(ctx)
			s.checkQuarantineClear(ctx)
		}
	}
	s.stepClear(ctx)
	s.refreshQuarantine(ctx)
}

// scheduledAssets are the assets with a quarantine stream, each once, in
// schedule order.
func (s *Scheduler) scheduledAssets() []string {
	var out []string
	for _, c := range s.rt.cfg.Schedule {
		if !slices.Contains(out, c.AssetID) {
			out = append(out, c.AssetID)
		}
	}
	return out
}

// checkExports records each manifest copy that checks out and is not yet
// in the chain. A copy that does not check out is refused once per content.
func (s *Scheduler) checkExports(ctx context.Context) {
	for _, a := range s.scheduledAssets() {
		name := QuarantineExportFileName(a)
		b, err := protect.ReadFileFor(filepath.Join(s.rt.cfg.AdminDir, name), MaxQuarantineManifestBytes, AdminReaders())
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			s.raiseOnceKey("quarantine export err "+err.Error(), a, AlarmQuarantineExportRefused, name+" refused: "+err.Error())
			continue
		}
		h := sha256Of(b)
		s.mu.Lock()
		known := s.quar[h] != nil
		s.mu.Unlock()
		if known {
			continue
		}
		q, err := s.verifyManifest(ctx, a, b)
		if err != nil {
			s.raiseOnceKey("quarantine export "+h, a, AlarmQuarantineExportRefused, name+" does not match this node's stream, so it is not recorded and cannot be cleared: "+err.Error())
			continue
		}
		q.ManifestSHA256 = h
		if err := s.commitQuarantineRecord(ctx, audit.ActionQuarantineExported, audit.OutcomeInfo, "", a, q, "manifest verified against "+string(QuarantineStream(a))); err != nil {
			s.raiseOnceKey("quarantine export audit "+h, a, AlarmQuarantineExportRefused, name+" checked out but was not recorded; it is tried again: "+err.Error())
			continue
		}
		if err := s.fold(ctx, true); s.foldOK(err) {
			s.rt.opt.Status.Raise(a, AlarmQuarantineExported, fmt.Sprintf("export of %s verified against the stream and recorded: seqs %d to %d, %d items, manifest %s", a, q.FirstSeq, q.LastSeq, q.Items, h))
		}
	}
}

// verifyManifest decodes a manifest copy and checks it against the asset's
// quarantine stream both ways (A3): every listed seq is stored with equal
// event and capture hashes, and every seq the stream stores between the
// first and the last listed is listed. So the range names exactly the set
// stored there now.
func (s *Scheduler) verifyManifest(ctx context.Context, assetID string, b []byte) (*audit.Quarantine, error) {
	var m QuarantineManifest
	if err := collectorwire.DecodeStrict(b, &m); err != nil {
		return nil, fmt.Errorf("not a manifest: %w", err)
	}
	switch {
	case m.Schema != QuarantineExportSchema:
		return nil, fmt.Errorf("schema %q", m.Schema)
	case m.NodeID != string(s.rt.cfg.NodeID):
		return nil, fmt.Errorf("it is node %q's", m.NodeID)
	case m.AssetID != assetID || m.Stream != string(QuarantineStream(assetID)):
		return nil, fmt.Errorf("it names asset %q, stream %q", m.AssetID, m.Stream)
	case len(m.Items) == 0 || len(m.Items) > MaxQuarantineItems:
		return nil, fmt.Errorf("%d items; 1 to %d are read", len(m.Items), MaxQuarantineItems)
	}
	for i, it := range m.Items {
		if it.Seq == 0 || (i > 0 && it.Seq <= m.Items[i-1].Seq) {
			return nil, fmt.Errorf("item %d: seq %d is not above the one before", i, it.Seq)
		}
		if !sha256Hex.MatchString(it.EventSHA256) || (it.CaptureSHA256 != "" && !sha256Hex.MatchString(it.CaptureSHA256)) {
			return nil, fmt.Errorf("item %d: a hash is not lowercase hex SHA-256", i)
		}
	}
	first, last := m.Items[0].Seq, m.Items[len(m.Items)-1].Seq
	stored, err := s.storedRange(ctx, assetID, first, last)
	if err != nil {
		return nil, err
	}
	if len(stored) != len(m.Items) {
		return nil, fmt.Errorf("the stream stores %d records in seqs %d to %d and the manifest lists %d", len(stored), first, last, len(m.Items))
	}
	db := s.rt.Store(QuarantineStream(assetID))
	for i, it := range m.Items {
		st := stored[i]
		if uint64(st.Key.Seq) != it.Seq {
			return nil, fmt.Errorf("seq %d is listed, and the stream stores seq %d in its place", it.Seq, st.Key.Seq)
		}
		if sha256Of(st.Event) != it.EventSHA256 {
			return nil, fmt.Errorf("seq %d: the stored event's hash differs", it.Seq)
		}
		switch {
		case it.CaptureSHA256 == "" && st.EvidenceRef != "":
			return nil, fmt.Errorf("seq %d: the stored record has a capture the manifest does not list", it.Seq)
		case it.CaptureSHA256 != "":
			if st.EvidenceRef == "" {
				return nil, fmt.Errorf("seq %d: the stored record has no capture", it.Seq)
			}
			c, err := db.ReadCapture(ctx, st.EvidenceRef)
			if err != nil {
				return nil, fmt.Errorf("seq %d: capture: %w", it.Seq, err)
			}
			if sha256Of(c.Bytes) != it.CaptureSHA256 {
				return nil, fmt.Errorf("seq %d: the stored capture's hash differs", it.Seq)
			}
		}
	}
	return &audit.Quarantine{FirstSeq: first, LastSeq: last, Items: uint64(len(m.Items))}, nil
}

// storedRange returns the records the asset's quarantine stream stores in
// seqs first to last, in order.
func (s *Scheduler) storedRange(ctx context.Context, assetID string, first, last uint64) ([]c5.Stored, error) {
	stream := QuarantineStream(assetID)
	db := s.rt.Store(stream)
	if db == nil {
		return nil, errors.New("evidence database not open")
	}
	var out []c5.Stored
	after := c5.Seq(first - 1)
	for {
		got, err := db.Read(ctx, stream, after, 500)
		if err != nil {
			return nil, err
		}
		for _, st := range got {
			if uint64(st.Key.Seq) > last {
				return out, nil
			}
			out = append(out, st)
			after = st.Key.Seq
		}
		if len(got) < 500 {
			return out, nil
		}
		if len(out) > MaxQuarantineItems {
			return nil, fmt.Errorf("more than %d records stored in seqs %d to %d", MaxQuarantineItems, first, last)
		}
	}
}

// checkQuarantineClear applies clear-quarantine.json, in the design's
// order: the chain holds the export (A3-1); a clear of an export already
// cleared changes nothing and is recorded as stale (A3-4); every listed
// item is still stored and hash-equal, or nothing is removed (A3-2); and
// quarantine.cleared is committed before anything is removed (A3-3).
// Removal is stepClear's, from that record, never from the file.
func (s *Scheduler) checkQuarantineClear(ctx context.Context) {
	b, err := protect.ReadFileFor(filepath.Join(s.rt.cfg.AdminDir, ClearQuarantineFileName), MaxClearQuarantineBytes, AdminReaders())
	if errors.Is(err, fs.ErrNotExist) {
		return
	}
	if err != nil {
		s.refuseQuarantineClear("err "+err.Error(), "", ClearQuarantineFileName+" refused: "+err.Error())
		return
	}
	ch := sha256Of(b)
	s.mu.Lock()
	applied := false
	for _, e := range s.quar {
		applied = applied || slices.Contains(e.Clears, ch)
	}
	s.mu.Unlock()
	if applied {
		return // the chain holds this file's clear; it may stay in place
	}
	var cl clearQuarantine
	if err := collectorwire.DecodeStrict(b, &cl); err != nil || cl.Schema != ClearQuarantineSchema || !sha256Hex.MatchString(cl.ManifestSHA256) ||
		(authz.Principal{Type: authz.PrincipalHuman, ID: cl.Principal}).Validate() != nil {
		s.refuseQuarantineClear("file "+ch, "", fmt.Sprintf("%s is not a %s object with asset_id, manifest_sha256 and a human principal", ClearQuarantineFileName, ClearQuarantineSchema))
		return
	}
	s.mu.Lock()
	e := s.quar[cl.ManifestSHA256]
	var entry quarantineEntry
	if e != nil {
		entry = *e
	}
	s.mu.Unlock()
	if e == nil || entry.AssetID != cl.AssetID {
		s.refuseQuarantineClear("file "+ch, cl.AssetID, fmt.Sprintf("%s names manifest %s, for which the chain holds no quarantine.exported record of asset %s; nothing removed", ClearQuarantineFileName, cl.ManifestSHA256, cl.AssetID))
		return
	}
	q := &audit.Quarantine{ManifestSHA256: cl.ManifestSHA256, FirstSeq: entry.FirstSeq, LastSeq: entry.LastSeq, Items: entry.Items, ClearSHA256: ch, RequestedBy: cl.Principal}
	if entry.Cleared {
		if err := s.commitQuarantineRecord(ctx, audit.ActionQuarantineCleared, audit.OutcomeInfo, audit.ReasonAlreadyCleared, cl.AssetID, q, ClearQuarantineFileName+" names a manifest already cleared; nothing removed"); err != nil {
			s.refuseQuarantineClear("audit "+ch, cl.AssetID, "stale clear not recorded: "+err.Error())
			return
		}
		s.foldOK(s.fold(ctx, true))
		return
	}
	// The items come from the manifest copy the node verified: the copy in
	// admin_dir must still be that one.
	name := QuarantineExportFileName(cl.AssetID)
	mb, err := protect.ReadFileFor(filepath.Join(s.rt.cfg.AdminDir, name), MaxQuarantineManifestBytes, AdminReaders())
	if err != nil || sha256Of(mb) != cl.ManifestSHA256 {
		s.refuseQuarantineClear("copy "+ch, cl.AssetID, fmt.Sprintf("%s in admin_dir is no longer manifest %s, so its items cannot be checked; nothing removed (clear the newest recorded export instead)", name, cl.ManifestSHA256))
		return
	}
	if got, err := s.verifyManifest(ctx, cl.AssetID, mb); err != nil || got.FirstSeq != entry.FirstSeq || got.LastSeq != entry.LastSeq || got.Items != entry.Items {
		why := "its range differs from the record"
		if err != nil {
			why = err.Error()
		}
		s.refuseQuarantineClear("check "+ch, cl.AssetID, "the stream no longer matches manifest "+cl.ManifestSHA256+"; nothing removed: "+why)
		return
	}
	if err := s.commitQuarantineRecord(ctx, audit.ActionQuarantineCleared, audit.OutcomeSucceeded, "", cl.AssetID, q,
		fmt.Sprintf("%s applied; seqs %d to %d are removed in steps after this record", ClearQuarantineFileName, entry.FirstSeq, entry.LastSeq)); err != nil {
		s.refuseQuarantineClear("audit "+ch, cl.AssetID, "clear not recorded in the audit stream, so nothing is removed: "+err.Error())
		return
	}
	if err := s.fold(ctx, true); s.foldOK(err) {
		s.mu.Lock()
		delete(s.quarDone, cl.ManifestSHA256)
		s.mu.Unlock()
	}
}

func (s *Scheduler) refuseQuarantineClear(key, assetID, detail string) {
	s.raiseOnceKey("quarantine clear "+key, assetID, AlarmQuarantineClearRefused, detail)
}

func (s *Scheduler) commitQuarantineRecord(ctx context.Context, action audit.Action, outcome audit.Outcome, reason, assetID string, q *audit.Quarantine, detail string) error {
	rec := audit.Record{Contract: audit.ContractID, NodeID: string(s.rt.cfg.NodeID), Time: s.rt.received(),
		Actor: audit.Actor{Type: authz.PrincipalNode, ID: string(s.rt.cfg.NodeID)}, Action: action, Outcome: outcome, ReasonCode: reason,
		Target: &audit.Target{AssetID: assetID}, Detail: detail, Quarantine: q}
	b, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	if _, err := audit.ValidatePending(b); err != nil {
		return err
	}
	_, log, mode := s.rt.view(s.rt.find(AuditDB))
	if log == nil || !mode.AcceptsEvents() {
		return fmt.Errorf("audit database is %s", s.rt.Mode(AuditDB))
	}
	// A receipt before anything is removed (audit before act, D1-11).
	_, err = log.Append(ctx, c5.Record{Stream: AuditStream, Class: c5.ClassAudit, Event: b})
	return err
}

// stepClear takes one C5 Discard step of a recorded clear whose range
// still holds stored seqs (A1 (a) to (c)). It removes only seqs inside the
// record's stream and range, which the export check proved were all
// listed; a seq added later is above the range. A range found empty is
// done, and an asset whose clears are all done has its halt read again.
func (s *Scheduler) stepClear(ctx context.Context) {
	consumers, err := s.rt.cfg.Consumers()
	if err != nil {
		s.raiseOnceKey("quarantine consumers", "", AlarmQuarantineClearIncomplete, "consumers unknown, so no clear step: "+err.Error())
		return
	}
	for _, h := range s.pendingClears() {
		s.mu.Lock()
		e := *s.quar[h]
		s.mu.Unlock()
		stream := QuarantineStream(e.AssetID)
		db := s.rt.Store(stream)
		if db == nil {
			return
		}
		got, err := db.Read(ctx, stream, c5.Seq(e.FirstSeq-1), c5.DiscardStepEvents)
		if err != nil {
			s.raiseOnceKey("quarantine step "+h, e.AssetID, AlarmQuarantineClearIncomplete, "clear of manifest "+h+" not finished; the stream could not be read: "+err.Error())
			return
		}
		var seqs []c5.Seq
		for _, st := range got {
			if uint64(st.Key.Seq) >= e.FirstSeq && uint64(st.Key.Seq) <= e.LastSeq {
				seqs = append(seqs, st.Key.Seq)
			}
		}
		if len(seqs) == 0 {
			s.clearDone(ctx, h, e.AssetID)
			continue
		}
		s.raiseOnceKey("quarantine step "+h, e.AssetID, AlarmQuarantineClearIncomplete,
			fmt.Sprintf("clear of manifest %s recorded; removing seqs %d to %d, %d per tick; runs of this asset are held until it is done", h, e.FirstSeq, e.LastSeq, c5.DiscardStepEvents))
		if _, err := db.Discard(ctx, consumers, stream, seqs); err != nil {
			s.raiseOnceKey("quarantine discard "+h, e.AssetID, AlarmQuarantineClearIncomplete, "clear step of manifest "+h+" failed; it is tried again next tick: "+err.Error())
		} else if left, err := s.anyStored(ctx, e.AssetID, e.FirstSeq, e.LastSeq); err == nil && !left {
			s.clearDone(ctx, h, e.AssetID)
		}
		return // one step per tick
	}
}

// pendingClears are the manifest hashes of recorded clears not known to
// be done, in a fixed order.
func (s *Scheduler) pendingClears() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for h, e := range s.quar {
		if e.Cleared && !s.quarDone[h] {
			out = append(out, h)
		}
	}
	slices.SortFunc(out, func(a, b string) int {
		ea, eb := s.quar[a], s.quar[b]
		if c := cmp.Compare(ea.AssetID, eb.AssetID); c != 0 {
			return c
		}
		return cmp.Compare(ea.FirstSeq, eb.FirstSeq)
	})
	return out
}

// clearDone marks a recorded clear's range as empty. Once none of the
// asset's clears is pending, a halt for an unauthorized line ends if no
// such quarantine is left in the stream (A3: never mid-removal).
func (s *Scheduler) clearDone(ctx context.Context, h, assetID string) {
	s.mu.Lock()
	s.quarDone[h] = true
	s.mu.Unlock()
	s.clearQuietKey("quarantine step " + h)
	s.clearQuietKey("quarantine discard " + h)
	if s.clearing(assetID) {
		return
	}
	detail := "the quarantine clear of manifest " + h + " is done"
	s.mu.Lock()
	halt := s.halted[assetID] == AlarmUnauthorizedLine
	s.mu.Unlock()
	if halt {
		halted, err := s.durableHalt(ctx, assetID)
		s.mu.Lock()
		if err == nil && !halted && s.halted[assetID] == AlarmUnauthorizedLine {
			delete(s.halted, assetID)
		}
		s.mu.Unlock()
		switch {
		case err != nil:
			detail += "; the halt stays, as the quarantine could not be read: " + err.Error()
		case halted:
			detail += "; the halt stays, as an unauthorized-line quarantine is left outside the cleared range"
		default:
			detail += "; no unauthorized-line quarantine is left, so collection resumes"
		}
	}
	s.rt.opt.Status.Raise(assetID, AlarmQuarantineCleared, detail)
}

// clearing reports whether a recorded clear of the asset is not done:
// its runs are held until it is.
func (s *Scheduler) clearing(assetID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for h, e := range s.quar {
		if e.AssetID == assetID && e.Cleared && !s.quarDone[h] {
			return true
		}
	}
	return false
}

// refreshQuarantine finds which exports' ranges are empty, without
// removing anything, and publishes what is left: a recorded export whose
// range still holds records, cleared or not. A start calls it before any
// run, so a clear stopped partway holds its asset from the first run.
func (s *Scheduler) refreshQuarantine(ctx context.Context) {
	s.mu.Lock()
	var todo []string
	for h := range s.quar {
		if !s.quarDone[h] {
			todo = append(todo, h)
		}
	}
	s.mu.Unlock()
	for _, h := range todo {
		s.mu.Lock()
		e := *s.quar[h]
		s.mu.Unlock()
		if left, err := s.anyStored(ctx, e.AssetID, e.FirstSeq, e.LastSeq); err == nil && !left {
			s.mu.Lock()
			s.quarDone[h] = true
			s.mu.Unlock()
		}
	}
	s.publishQuarantine()
}

// anyStored reports whether the stream stores any seq in first..last.
func (s *Scheduler) anyStored(ctx context.Context, assetID string, first, last uint64) (bool, error) {
	stream := QuarantineStream(assetID)
	db := s.rt.Store(stream)
	if db == nil {
		return false, errors.New("evidence database not open")
	}
	got, err := db.Read(ctx, stream, c5.Seq(first-1), 1)
	if err != nil {
		return false, err
	}
	return len(got) == 1 && uint64(got[0].Key.Seq) <= last, nil
}

// QuarantineStatus is a recorded export whose range still holds records,
// as node status shows it.
type QuarantineStatus struct {
	AssetID        string `json:"asset_id"`
	ManifestSHA256 string `json:"manifest_sha256"`
	FirstSeq       uint64 `json:"first_seq"`
	LastSeq        uint64 `json:"last_seq"`
	Items          uint64 `json:"items"`
	// Clearing: a clear is recorded and its removal is not done; runs of
	// the asset are held. Otherwise the export is not cleared.
	Clearing bool `json:"clearing,omitempty"`
}

func (s *Scheduler) publishQuarantine() {
	s.mu.Lock()
	var out []QuarantineStatus
	for h, e := range s.quar {
		if !s.quarDone[h] {
			out = append(out, QuarantineStatus{AssetID: e.AssetID, ManifestSHA256: h, FirstSeq: e.FirstSeq, LastSeq: e.LastSeq, Items: e.Items, Clearing: e.Cleared})
		}
	}
	s.mu.Unlock()
	slices.SortFunc(out, func(a, b QuarantineStatus) int {
		if c := cmp.Compare(a.AssetID, b.AssetID); c != 0 {
			return c
		}
		return cmp.Compare(a.FirstSeq, b.FirstSeq)
	})
	s.rt.opt.Status.SetQuarantine(out)
}
