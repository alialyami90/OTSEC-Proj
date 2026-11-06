package node

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	c1 "otsec.local/otsec/contracts/asset"
	"otsec.local/otsec/contracts/audit"
	"otsec.local/otsec/contracts/config"
	"otsec.local/otsec/contracts/finding"
	c5 "otsec.local/otsec/contracts/store"
	"otsec.local/otsec/modules/applicability"
)

// Findings (R9, C12, the node note section 4, D4-53 and D4-54). With
// applicability on and a set in use, the node runs the matcher for an asset
// at the end of each of its collection runs, for every asset at start and
// whenever a set comes into use. It stores each finding the matcher returns
// in config/<asset>, through storeItem3, except a product-not-named finding
// for an entry with no stored finding for the asset (D4-54).

// AlarmFindingChanged is raised once for each evaluation that stored a
// finding: a new one, or a revision of the asset's latest for its entry
// (the note, section 6). It names each advisory and both classes. Level 1.
const AlarmFindingChanged = "finding-changed"

// HealthFindingChanged is one stored finding's event on platform/health.
const HealthFindingChanged = "finding.changed"

// AlarmNotEvaluated is raised once per asset and cause when an evaluation
// could not be completed: its inputs could not be read, the matcher refused
// them, or a finding it returned was not stored. The asset's last completed
// evaluation in status stays where it was. A ceiling refusal raises
// AlarmAssetStoreFull instead. Level 1.
const AlarmNotEvaluated = "applicability-not-evaluated"

// AlarmDeclaredNotRecorded is raised once per asset when the policy.apply
// record of its declared identity could not be written or kept, so the
// asset's operator identity cannot be cited and it is not evaluated on it.
const AlarmDeclaredNotRecorded = "asset-identity-not-recorded"

// ReasonAssetIdentityDeclared is the reason_code of the policy.apply record
// of a declared identity (D4-54). Its detail is declaredDetail's.
const ReasonAssetIdentityDeclared = "asset_identity_declared"

// DeclaredIdentitiesFileName is the store directory file that keeps the
// newest declared-identity record of each asset, so a record the chain no
// longer holds is cited again, never written again (C6 on #455). A lost
// file and a pruned chain mean the record is written again.
const DeclaredIdentitiesFileName = "declared-identities.json"

const declaredSchema = "otsec.node-declared/0.1"

const maxDeclaredFileBytes = 4 << 20

var declaredDetailRe = regexp.MustCompile(`^asset (\S+) declared identity sha256:([0-9a-f]{64})$`)

func declaredDetail(assetID, sum string) string {
	return fmt.Sprintf("asset %s declared identity sha256:%s", assetID, sum)
}

// declaredRecord is one asset's newest declared-identity record.
type declaredRecord struct {
	SHA256 string    `json:"sha256"`
	Seq    uint64    `json:"seq"`
	At     time.Time `json:"at"` // when it was committed
}

type declaredFile struct {
	Schema string                    `json:"schema"`
	Assets map[string]declaredRecord `json:"assets"`
}

// checkFindingRecord is ConfigDocuments' check of a C12 finding: a strict
// decode, C12's Validate, and the bytes the node's encoder writes, since a
// later revision names it by the hash of those bytes (C5 0.8 section 1).
func checkFindingRecord(document []byte, capture *c5.Capture) (c5.DocumentInfo, error) {
	if capture != nil {
		return c5.DocumentInfo{}, errors.New("configuration document: a finding has no capture")
	}
	if _, err := decodeFinding(document); err != nil {
		return c5.DocumentInfo{}, err
	}
	return c5.DocumentInfo{Kind: c5.DocumentEvidence, Series: c5.SeriesFinding}, nil
}

func decodeFinding(document []byte) (finding.Finding, error) {
	var f finding.Finding
	if err := decodeExact(document, &f, "finding"); err != nil {
		return f, err
	}
	if err := f.Validate(); err != nil {
		return f, fmt.Errorf("finding: %w", err)
	}
	return f, nil
}

// findingsState is what the matcher reads from one asset's configuration
// stream, besides its identity. Only the scheduler's goroutine uses it.
type findingsState struct {
	after c5.Seq // the stream is read through this seq
	// newest is the asset's latest stored finding for each entry.
	newest map[string]applicability.Previous
	// snap is the newest C9 snapshot, and sections its sections' digest.
	snap     *applicability.Snapshot
	sections [32]byte
	// change is the latest configuration change retrieved: the newest
	// snapshot whose sections differ from the stored one before it. The
	// oldest snapshot still stored counts as one, since what came before
	// it is not known.
	change *finding.Read
	last   *LastEvaluationStatus
}

// LastEvaluationStatus is an asset's last completed evaluation: every
// finding it returned was stored (D4-54). IdentityEvidenceID is the newest
// identity record it read, empty when it read none, so status shows it
// against status.identity's evidence_id.
type LastEvaluationStatus struct {
	SetID              string    `json:"set_id"`
	Version            uint64    `json:"version"`
	At                 time.Time `json:"at"`
	IdentityEvidenceID string    `json:"identity_evidence_id,omitempty"`
}

// AssetFindingsStatus is one asset's findings as status shows them.
// Classes counts its latest findings whose advisory is in the set in use.
// An entry with no stored finding is product-not-named under the set of the
// last completed evaluation (D4-54).
type AssetFindingsStatus struct {
	LastEvaluation *LastEvaluationStatus `json:"last_evaluation,omitempty"`
	Classes        map[finding.Class]int `json:"classes,omitempty"`
}

// snapshotHead is the part of a C9 snapshot the matcher reads.
type snapshotHead struct {
	Kind         string `json:"kind"`
	InvocationID string `json:"invocation_id"`
	RetrievedAt  string `json:"retrieved_at"`
	Sections     []struct {
		Class    string              `json:"class"`
		State    config.SectionState `json:"state"`
		Settings []config.Setting    `json:"settings,omitempty"`
	} `json:"sections"`
}

// findingsOf returns the asset's state, reading what its stream gained
// since the last call.
func (s *Scheduler) findingsOf(ctx context.Context, assetID string) (*findingsState, error) {
	fs := s.finds[assetID]
	if fs == nil {
		fs = &findingsState{newest: map[string]applicability.Previous{}}
	}
	stream := ConfigStream(assetID)
	db := s.rt.Store(stream)
	if db == nil {
		return nil, errors.New("the configuration database is not open")
	}
	for {
		got, err := db.Read(ctx, stream, fs.after, 16)
		if err != nil {
			return nil, err
		}
		if len(got) == 0 {
			break
		}
		for _, r := range got {
			if err := fs.fold(r); err != nil {
				return nil, fmt.Errorf("configuration record %d: %w", r.Key.Seq, err)
			}
			fs.after = r.Key.Seq
		}
	}
	s.finds[assetID] = fs
	return fs, nil
}

// fold reads one stored record into the state.
func (fs *findingsState) fold(r c5.Stored) error {
	switch {
	case bytes.HasPrefix(r.Event, []byte(`{"schema":"`+finding.Identifier+`"`)):
		f, err := decodeFinding(r.Event)
		if err != nil {
			return err
		}
		fs.newest[f.Advisory] = applicability.Previous{Finding: f, Hash: finding.Hash(r.Event)}
	case bytes.HasPrefix(r.Event, []byte(`{"schema":"otsec.config/`)):
		var h snapshotHead
		if err := json.Unmarshal(r.Event, &h); err != nil {
			return err
		}
		if h.Kind != config.KindSnapshot {
			return nil
		}
		b, err := json.Marshal(h.Sections)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(b)
		if fs.snap == nil || sum != fs.sections {
			fs.change = &finding.Read{ID: h.InvocationID, AtUTC: h.RetrievedAt}
		}
		// A setting printed in two sections with different values is left
		// out, so it reads as unread, never as one of them.
		settings, conflict := map[string]string{}, map[string]bool{}
		for _, sec := range h.Sections {
			if sec.State != config.Present {
				continue
			}
			for _, st := range sec.Settings {
				if v, ok := settings[st.Name]; ok && v != st.Value {
					conflict[st.Name] = true
				}
				settings[st.Name] = st.Value
			}
		}
		for k := range conflict {
			delete(settings, k)
		}
		fs.snap, fs.sections = &applicability.Snapshot{ID: h.InvocationID, AtUTC: h.RetrievedAt, Settings: settings}, sum
	}
	return nil
}

// notEvaluated raises AlarmNotEvaluated once for the asset and cause.
func (s *Scheduler) notEvaluated(assetID, cause, why string) {
	s.raiseOnceKey("not-evaluated "+assetID+" "+cause, assetID, AlarmNotEvaluated, "no finding is computed for this asset until it is fixed: "+why)
}

// evaluateAll evaluates every declared asset.
func (s *Scheduler) evaluateAll(ctx context.Context) {
	s.evalAll = false
	for _, a := range s.rt.cfg.assets {
		s.evaluate(ctx, a.AssetID)
	}
}

// evaluate runs the matcher for one asset under the set in use and stores
// what it returns. It does nothing with no set in use, or while the item 3
// ceiling pauses the matcher; the next evaluation catches up, since the
// matcher compares with the stored findings.
func (s *Scheduler) evaluate(ctx context.Context, assetID string) {
	if s.adv == nil || s.adv.inUse == nil || s.item3Paused(ctx) {
		return
	}
	set := s.adv.inUse.Set
	fs, err := s.findingsOf(ctx, assetID)
	if err != nil {
		s.notEvaluated(assetID, "read", "the configuration stream could not be read: "+err.Error())
		return
	}
	in, evidence, err := s.matcherInput(ctx, assetID, fs)
	if err != nil {
		s.notEvaluated(assetID, "input", err.Error())
		return
	}
	at := s.now().UTC()
	in.EvaluatedUTC = at.Format(time.RFC3339Nano)
	out, err := applicability.Evaluate(in, set, fs.newest)
	if err != nil {
		s.notEvaluated(assetID, "matcher", err.Error())
		return
	}
	var changed []string
	defer func() {
		if len(changed) > 0 {
			s.rt.opt.Status.Raise(assetID, AlarmFindingChanged, fmt.Sprintf("%d finding(s) stored under set %s version %d: %s",
				len(changed), set.SetID, set.Version, strings.Join(changed, ", ")))
		}
		s.publishApplicability()
	}()
	for _, f := range out {
		_, had := fs.newest[f.Advisory]
		if f.Reason == finding.ProductNotNamed && !had {
			continue // D4-54: not stored, and shown by the last evaluation
		}
		b, err := json.Marshal(f)
		if err == nil {
			_, err = s.storeItem3(ctx, ConfigStream(assetID), b, nil)
		}
		if err != nil {
			var ce *ceilingError
			if !errors.As(err, &ce) {
				s.notEvaluated(assetID, "store", fmt.Sprintf("the finding for %s was not stored: %v", f.Advisory, err))
			}
			return
		}
		fs.newest[f.Advisory] = applicability.Previous{Finding: f, Hash: finding.Hash(b)}
		from := "none"
		if f.From != "" {
			from = string(f.From)
		}
		changed = append(changed, fmt.Sprintf("%s %s to %s", f.Advisory, from, f.Class))
		s.rt.health(ctx, HealthFindingChanged, map[string]string{"asset_id": assetID, "advisory": f.Advisory,
			"class": string(f.Class), "from": string(f.From), "revision": strconv.Itoa(f.Revision),
			"set_id": set.SetID, "set_version": strconv.FormatUint(set.Version, 10)})
	}
	s.clearQuietPrefix("not-evaluated " + assetID + " ")
	fs.last = &LastEvaluationStatus{SetID: set.SetID, Version: set.Version, At: at, IdentityEvidenceID: evidence}
}

// matcherInput builds the matcher's input for the asset from its stored
// records, and returns the newest identity record's evidence ID, if any.
// A firmware ID read from the device makes the identity device-read, cited
// by the run that first read it; otherwise it is the asset's declaration in
// the node's configuration, cited by its policy.apply record.
func (s *Scheduler) matcherInput(ctx context.Context, assetID string, fs *findingsState) (applicability.Input, string, error) {
	in := applicability.Input{AssetID: assetID, Settings: fs.snap, LatestChange: fs.change}
	st := s.identityOf(ctx, assetID)
	if st == nil {
		return in, "", errors.New("the stored identity records could not be read")
	}
	evidence := ""
	if st.doc != nil {
		evidence = st.doc.InvocationID
		if fid, ref, ok := deviceRead(st.doc.Asset, c1.AttrFirmwareID); ok {
			model, _, _ := deviceRead(st.doc.Asset, c1.AttrModel)
			version, _, _ := deviceRead(st.doc.Asset, c1.AttrFirmwareVersion)
			in.Identity = applicability.Identity{Source: finding.DeviceRead, Evidence: ref, FirmwareID: fid, Model: model, FirmwareVersion: version}
			in.Identity.LatestRead = &finding.Read{ID: st.doc.InvocationID, AtUTC: st.doc.ReadAt}
			if st.last != nil && st.last.InvocationID != "" {
				in.Identity.LatestRead = &finding.Read{ID: st.last.InvocationID, AtUTC: st.last.ReadAt}
			}
			mismatchInput(&in, st)
			return in, evidence, nil
		}
	}
	declared, _ := s.rt.cfg.Asset(assetID)
	ref, err := s.declaredRef(ctx, declared)
	if err != nil {
		return in, evidence, err
	}
	// A mismatch counts under an operator identity too (C1 on #458), until
	// a confirming read or a changed declaration clears it (C4 on #459): a
	// mismatch stored before the declaration's record was written is of an
	// earlier declaration.
	if !s.declared[assetID].At.After(st.lastAt) {
		mismatchInput(&in, st)
	}
	in.Identity = applicability.Identity{Source: finding.Operator, Evidence: ref, FirmwareID: operatorValue(declared, c1.AttrFirmwareID),
		Model: operatorValue(declared, c1.AttrModel), FirmwareVersion: operatorValue(declared, c1.AttrFirmwareVersion)}
	return in, evidence, nil
}

// mismatchInput gives the matcher the asset's stored mismatch, if any.
func mismatchInput(in *applicability.Input, st *identityState) {
	if st.last != nil && st.last.Mismatch != nil {
		m := st.last.Mismatch
		in.LatestMismatch, in.MismatchFID = &finding.Read{ID: m.InvocationID, AtUTC: m.ReadAt}, m.FID
	}
}

// deviceRead returns the attribute's device-read value and the run that
// first read it.
func deviceRead(a c1.Asset, name string) (value, ref string, ok bool) {
	at, ok := a.Attribute(name)
	if !ok {
		return "", "", false
	}
	for _, ob := range at.Observations {
		if ob.EffectiveKind() == c1.DeviceRead {
			return ob.Value, ob.Source.Ref, true
		}
	}
	return "", "", false
}

// operatorValue returns the attribute's operator-entered value, if any.
func operatorValue(a c1.Asset, name string) string {
	at, ok := a.Attribute(name)
	if !ok {
		return ""
	}
	for _, ob := range at.Observations {
		if ob.EffectiveKind() == c1.Operator {
			return ob.Value
		}
	}
	return ""
}

// declaredSum is the SHA-256 of the asset's declared identity: each
// attribute's operator-entered value, by name. It is empty when the asset
// declares none.
func declaredSum(a c1.Asset) string {
	type kv struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	}
	var list []kv
	for _, at := range a.Attributes {
		if v := operatorValue(a, at.Name); v != "" {
			list = append(list, kv{at.Name, v})
		}
	}
	if len(list) == 0 {
		return ""
	}
	slices.SortFunc(list, func(x, y kv) int { return strings.Compare(x.Name, y.Name) })
	b, _ := json.Marshal(list)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// startDeclared writes the policy.apply record of every declared identity
// that is new or changed, with applicability on (D4-54).
func (s *Scheduler) startDeclared(ctx context.Context) {
	if s.adv == nil {
		return
	}
	for _, a := range s.rt.cfg.assets {
		if declaredSum(a) == "" {
			continue
		}
		if _, err := s.declaredRef(ctx, a); err != nil {
			s.raiseOnceKey("declared "+a.AssetID, a.AssetID, AlarmDeclaredNotRecorded, err.Error())
		}
	}
}

// declaredRef returns the audit reference of the record of a's declared
// identity as it is now, writing the record if the newest one is of
// another declaration. A record is cited for as long as the declaration is
// unchanged, whether or not the chain still holds it.
func (s *Scheduler) declaredRef(ctx context.Context, a c1.Asset) (string, error) {
	sum := declaredSum(a)
	if sum == "" {
		return "", errors.New("the asset's configuration declares no identity attribute")
	}
	if s.declared == nil {
		m, err := s.loadDeclared(ctx)
		if err != nil {
			return "", fmt.Errorf("the declared-identity records could not be read: %w", err)
		}
		s.declared = m
	}
	ref := func(seq uint64) string { return fmt.Sprintf("audit:%s:%d", s.rt.cfg.NodeID, seq) }
	if r, ok := s.declared[a.AssetID]; ok && r.SHA256 == sum {
		return ref(r.Seq), nil
	}
	rec, err := s.rt.AuditRecord(audit.ActionPolicyApply, audit.OutcomeInfo, ReasonAssetIdentityDeclared, declaredDetail(a.AssetID, sum))
	if err != nil {
		return "", err
	}
	log := s.rt.Log(AuditStream)
	if log == nil {
		return "", errAuditNotOpen
	}
	got, err := log.AppendBatch(ctx, []c5.Record{rec})
	if err != nil {
		return "", fmt.Errorf("the declared identity's policy.apply record was not written: %w", err)
	}
	s.declared[a.AssetID] = declaredRecord{SHA256: sum, Seq: uint64(got[0].Key().Seq), At: s.now().UTC()}
	s.clearQuietKey("declared " + a.AssetID)
	if err := s.writeDeclared(); err != nil {
		// The chain still holds the record, and the next start reads it
		// there until it is pruned.
		s.raiseOnceKey("declared-file", "", AlarmDeclaredNotRecorded, DeclaredIdentitiesFileName+" not written, so a declared identity's record may be written again after the chain is pruned: "+err.Error())
	}
	return ref(uint64(got[0].Key().Seq)), nil
}

// loadDeclared reads the newest declared-identity record of each asset from
// the chain and from DeclaredIdentitiesFileName, the newest of the two
// winning. A file entry that names a seq the chain should still hold, and
// does not, is dropped, so a file from another store is never cited.
func (s *Scheduler) loadDeclared(ctx context.Context) (map[string]declaredRecord, error) {
	adb := s.rt.Store(AuditStream)
	if adb == nil {
		return nil, errAuditNotOpen
	}
	chain := map[string]declaredRecord{}
	var first, last c5.Seq
	for after := c5.Seq(0); ; {
		got, err := adb.Read(ctx, AuditStream, after, 500)
		if err != nil {
			return nil, err
		}
		for _, st := range got {
			if first == 0 {
				first = st.Key.Seq
			}
			after, last = st.Key.Seq, st.Key.Seq
			if !bytes.Contains(st.Event, []byte(ReasonAssetIdentityDeclared)) {
				continue
			}
			rec, err := audit.ParseRecord(st.Event)
			if err != nil {
				return nil, fmt.Errorf("audit record %d: %w", st.Key.Seq, err)
			}
			if rec.Action != audit.ActionPolicyApply || rec.ReasonCode != ReasonAssetIdentityDeclared {
				continue
			}
			if m := declaredDetailRe.FindStringSubmatch(rec.Detail); m != nil {
				chain[m[1]] = declaredRecord{SHA256: m[2], Seq: uint64(st.Key.Seq), At: st.CommittedAt}
			}
		}
		if len(got) < 500 {
			break
		}
	}
	out := chain
	f, err := readDeclared(filepath.Join(s.rt.cfg.Store.Dir, DeclaredIdentitiesFileName))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		s.raiseOnceKey("declared-file", "", AlarmDeclaredNotRecorded, DeclaredIdentitiesFileName+" unreadable, so a declared identity the chain no longer holds is recorded again: "+err.Error())
	}
	for id, r := range f.Assets {
		if r.Seq > uint64(last) || (first != 0 && r.Seq >= uint64(first)) {
			continue // the chain holds it, or should
		}
		if c, ok := out[id]; !ok || c.Seq < r.Seq {
			out[id] = r
		}
	}
	return out, nil
}

func readDeclared(path string) (declaredFile, error) {
	fh, err := os.Open(path)
	if err != nil {
		return declaredFile{}, err
	}
	defer fh.Close()
	// Bounded, so a damaged or planted file cannot exhaust memory (C3 on
	// #458): a few hundred bytes per declared asset.
	b, err := io.ReadAll(io.LimitReader(fh, maxDeclaredFileBytes+1))
	if err != nil {
		return declaredFile{}, err
	}
	if len(b) > maxDeclaredFileBytes {
		return declaredFile{}, fmt.Errorf("%s: over %d bytes", path, maxDeclaredFileBytes)
	}
	var f declaredFile
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return declaredFile{}, fmt.Errorf("%s: %w", path, err)
	}
	if f.Schema != declaredSchema {
		return declaredFile{}, fmt.Errorf("%s: schema %q", path, f.Schema)
	}
	return f, nil
}

// writeDeclared replaces DeclaredIdentitiesFileName with s.declared.
func (s *Scheduler) writeDeclared() error {
	path := filepath.Join(s.rt.cfg.Store.Dir, DeclaredIdentitiesFileName)
	b, err := json.MarshalIndent(declaredFile{Schema: declaredSchema, Assets: s.declared}, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".declared-*")
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
	return os.Rename(tmp.Name(), path)
}

// findingsStatus is each asset's findings for status.
func (s *Scheduler) findingsStatus() map[string]AssetFindingsStatus {
	if s.adv == nil || len(s.finds) == 0 {
		return nil
	}
	inSet := map[string]bool{}
	if v := s.adv.inUse; v != nil {
		for _, e := range v.Set.Entries {
			inSet[e.ID] = true
		}
	}
	out := map[string]AssetFindingsStatus{}
	for id, fs := range s.finds {
		var st AssetFindingsStatus
		if fs.last != nil {
			l := *fs.last
			st.LastEvaluation = &l
		}
		for adv, p := range fs.newest {
			if inSet[adv] {
				if st.Classes == nil {
					st.Classes = map[finding.Class]int{}
				}
				st.Classes[p.Finding.Class]++
			}
		}
		out[id] = st
	}
	return out
}
