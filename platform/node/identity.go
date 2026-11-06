package node

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"time"

	"otsec.local/otsec/contracts/adapter"
	c1 "otsec.local/otsec/contracts/asset"
	c5 "otsec.local/otsec/contracts/store"
	"otsec.local/otsec/modules/asset"
	"otsec.local/otsec/platform/store"
)

// The node's two identity documents (C5 0.8 section 1). Each writes its
// schema as the first field, so the readers that skip by schema prefix
// (storedBaselines, checkpoints) skip them.
const (
	// IdentitySchema is the identity record: the asset's C1 0.3 record as
	// modules/asset left it, the run that stored it, the hash of the
	// asset's previous identity record, and the pieces of the run
	// transcripts its observations' spans point into. Evidence, series
	// identity.
	IdentitySchema = "otsec.identity/0.1"
	// IdentityReadSchema is the latest-read record: the run that last read
	// the identity, and when (C12's identity.latest_read). Working state,
	// series identity.read.
	IdentityReadSchema = "otsec.identityread/0.1"
)

// AlarmIdentityChanged is raised when a run stores an identity record that
// differs from the asset's previous one (the note, section 6). It names the
// attributes and both records' evidence IDs, never a value: the values are
// in status. A changed FID or model is a security signal of its own, apart
// from R9. Level 1.
const AlarmIdentityChanged = "identity-changed"

// AlarmIdentityNotStored is raised once per asset when a run read an
// identity that could not be stored, or the stored records could not be
// read. The run's own records are unaffected, and the next run tries again.
// A write the item 3 ceiling refuses raises AlarmAssetStoreFull instead.
const AlarmIdentityNotStored = "identity-not-stored"

// AlarmIdentityReadNotRemoved is raised once per asset when an older
// identity.read could not be removed. The removal is tried again after the
// next identity.read commits (C5 0.8 section 2).
const AlarmIdentityReadNotRemoved = "identity-read-not-removed"

// Health events of the identity records, on platform/health.
const (
	HealthIdentityChanged      = "identity.changed"
	HealthIdentityReadsRemoved = "identity.reads-removed"
)

// identityDoc is an otsec.identity/0.1 document. Its capture is the bytes of
// Pieces, in order.
type identityDoc struct {
	Schema  string `json:"schema"`
	AssetID string `json:"asset_id"`
	// InvocationID is the run that stored this record: the evidence ID
	// findings cite. ReadAt is when that run ended.
	InvocationID string `json:"invocation_id"`
	ReadAt       string `json:"read_at"`
	// Previous is the SHA-256 of the asset's previous identity document,
	// empty for its first.
	Previous string          `json:"previous,omitempty"`
	Pieces   []identityPiece `json:"pieces,omitempty"`
	Asset    c1.Asset        `json:"asset"`
}

// identityPiece is one run's transcript bytes, from Offset for Length, as
// they lie in the capture after the pieces before it.
type identityPiece struct {
	InvocationID string `json:"invocation_id"`
	Offset       int64  `json:"offset"`
	Length       int64  `json:"length"`
}

// identityReadDoc is an otsec.identityread/0.1 document. InvocationID and
// ReadAt are always the last confirming read, so removing older reads never
// removes it (C6 on #455). Both are empty only in a document that carries a
// mismatch for an asset no read has confirmed yet (C1 on #458).
type identityReadDoc struct {
	Schema       string `json:"schema"`
	AssetID      string `json:"asset_id"`
	InvocationID string `json:"invocation_id,omitempty"`
	ReadAt       string `json:"read_at,omitempty"`
	// Mismatch is a read after the confirming one that refused the
	// identity (D4-54, a C5 0.8 amendment). It is set only from such a read
	// and is cleared by the next confirming read, which writes a document
	// without it.
	Mismatch *identityMismatch `json:"mismatch,omitempty"`
}

// identityMismatch is one read that refused the asset's identity: SEL
// refused.identity_mismatch, or SNMP's authenticated
// failed.identity_mismatch (D4-54). FID is the FID the device reported:
// device text, at most C1's value bound, kept only so that the matcher can
// tell whether an entry names it, and never adopted as the identity.
type identityMismatch struct {
	InvocationID string `json:"invocation_id"`
	ReadAt       string `json:"read_at"`
	FID          string `json:"fid,omitempty"`
	// DeclaredSHA256 is set only on an asset whose identity is its
	// declaration: the hash of the declared identity the read contradicted.
	// The mismatch counts until the declaration's hash differs from it
	// (C1 on #458, D4-55).
	DeclaredSHA256 string `json:"declared_sha256,omitempty"`
}

// decodeExact decodes b into v with no unknown field and no trailing data,
// and checks b is the bytes json.Marshal writes for what it decoded.
func decodeExact(b []byte, v any, what string) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("%s: %w", what, err)
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return fmt.Errorf("%s: trailing data", what)
	}
	again, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if !bytes.Equal(again, b) {
		return fmt.Errorf("%s: not the bytes the node's encoder writes", what)
	}
	return nil
}

// sessionRead reports whether ob was read in a C2 session, so its span
// points into that run's transcript.
func sessionRead(ob c1.Observation) bool {
	return ob.Source.Span != nil && (ob.Source.Method == c1.AdapterSession || ob.Source.Method == c1.SimulatorRun)
}

// decodeIdentity decodes and checks an identity record.
func decodeIdentity(document []byte, capture *c5.Capture) (identityDoc, error) {
	var d identityDoc
	n := int64(len(document))
	if capture != nil {
		n += int64(len(capture.Bytes))
	}
	if n > MaxIdentityRecordBytes {
		return d, fmt.Errorf("identity record: %d bytes with its capture, over %d", n, MaxIdentityRecordBytes)
	}
	var raw struct {
		identityDoc
		Asset json.RawMessage `json:"asset"`
	}
	dec := json.NewDecoder(bytes.NewReader(document))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&raw); err != nil {
		return d, fmt.Errorf("identity record: %w", err)
	}
	a, err := c1.Decode(raw.Asset)
	if err != nil {
		return d, fmt.Errorf("identity record: %w", err)
	}
	d = raw.identityDoc
	d.Asset = a
	if err := decodeExact(document, &identityDoc{}, "identity record"); err != nil {
		return d, err
	}
	bad := func(format string, args ...any) (identityDoc, error) {
		return d, fmt.Errorf("identity record: "+format, args...)
	}
	switch {
	case d.Schema != IdentitySchema:
		return bad("schema %q", d.Schema)
	case !c1.ValidAssetID(d.AssetID) || d.AssetID != a.AssetID:
		return bad("asset_id %q is not its record's %q", d.AssetID, a.AssetID)
	case a.Schema != c1.Contract:
		return bad("the asset record is %s, not %s", a.Schema, c1.Contract)
	case d.InvocationID == "":
		return bad("invocation_id is empty")
	case !c1.ValidTime(d.ReadAt):
		return bad("read_at %q is not an RFC 3339 UTC time", d.ReadAt)
	case d.Previous != "" && !sha256Hex.MatchString(d.Previous):
		return bad("previous is not 64 lowercase hex digits")
	}
	var total int64
	for i, p := range d.Pieces {
		if p.InvocationID == "" || p.Offset < 0 || p.Length <= 0 {
			return bad("pieces[%d] needs an invocation_id, an offset >= 0 and a length > 0", i)
		}
		total += p.Length
	}
	switch {
	case capture == nil && total > 0, capture != nil && int64(len(capture.Bytes)) != total:
		return bad("the capture is not the %d bytes its pieces name", total)
	case capture != nil:
		if err := capture.Validate(); err != nil {
			return d, err
		}
	}
	// Every span a session observation points to lies in a piece of its
	// own run, so the record holds the device's bytes after its stream is
	// pruned (the note, section 2).
	for _, at := range a.Attributes {
		for _, ob := range at.Observations {
			if !sessionRead(ob) {
				continue
			}
			sp := ob.Source.Span
			if !slices.ContainsFunc(d.Pieces, func(p identityPiece) bool {
				return p.InvocationID == ob.Source.Ref && p.Offset <= sp.Offset && sp.Offset+sp.Length <= p.Offset+p.Length
			}) {
				return bad("%s's span %d+%d in run %s is in no piece of the capture", at.Name, sp.Offset, sp.Length, ob.Source.Ref)
			}
		}
	}
	return d, nil
}

// decodeIdentityRead decodes and checks a latest-read record.
func decodeIdentityRead(document []byte) (identityReadDoc, error) {
	var d identityReadDoc
	if int64(len(document)) > MaxIdentityReadBytes {
		return d, fmt.Errorf("identity read: %d bytes, over %d", len(document), MaxIdentityReadBytes)
	}
	if err := decodeExact(document, &d, "identity read"); err != nil {
		return d, err
	}
	switch {
	case d.Schema != IdentityReadSchema:
		return d, fmt.Errorf("identity read: schema %q", d.Schema)
	case !c1.ValidAssetID(d.AssetID):
		return d, fmt.Errorf("identity read: asset_id %q", d.AssetID)
	case d.InvocationID == "" && d.ReadAt == "" && d.Mismatch == nil:
		return d, errors.New("identity read: no confirming read and no mismatch")
	case d.InvocationID == "" && d.ReadAt == "":
		// A mismatch on an asset no read has confirmed (C1 on #458).
	case d.InvocationID == "":
		return d, errors.New("identity read: invocation_id is empty")
	case !c1.ValidTime(d.ReadAt):
		return d, fmt.Errorf("identity read: read_at %q is not an RFC 3339 UTC time", d.ReadAt)
	}
	if m := d.Mismatch; m != nil {
		switch {
		case m.InvocationID == "":
			return d, errors.New("identity read: mismatch.invocation_id is empty")
		case !c1.ValidTime(m.ReadAt):
			return d, fmt.Errorf("identity read: mismatch.read_at %q is not an RFC 3339 UTC time", m.ReadAt)
		case len(m.FID) > c1.MaxValueBytes:
			return d, fmt.Errorf("identity read: mismatch.fid is over %d bytes", c1.MaxValueBytes)
		case m.DeclaredSHA256 != "" && !sha256Hex.MatchString(m.DeclaredSHA256):
			return d, fmt.Errorf("identity read: mismatch.declared_sha256 %q is not 64 lowercase hex digits", m.DeclaredSHA256)
		}
	}
	return d, nil
}

// checkIdentityRecord is ConfigDocuments' check of an identity record.
func checkIdentityRecord(document []byte, capture *c5.Capture) (c5.DocumentInfo, error) {
	if _, err := decodeIdentity(document, capture); err != nil {
		return c5.DocumentInfo{}, err
	}
	return c5.DocumentInfo{Kind: c5.DocumentEvidence, Series: c5.SeriesIdentity}, nil
}

// checkIdentityReadRecord is ConfigDocuments' check of a latest-read record.
func checkIdentityReadRecord(document []byte, capture *c5.Capture) (c5.DocumentInfo, error) {
	if capture != nil {
		return c5.DocumentInfo{}, errors.New("configuration document: an identity read has no capture")
	}
	if _, err := decodeIdentityRead(document); err != nil {
		return c5.DocumentInfo{}, err
	}
	return c5.DocumentInfo{Kind: c5.DocumentWorkingState, Series: c5.SeriesIdentityRead}, nil
}

// identityState is one asset's identity records as the scheduler holds
// them. Only the scheduler's goroutine uses it.
type identityState struct {
	doc      *identityDoc // the newest identity record, nil if none
	docBytes []byte
	capture  []byte
	storedAt time.Time
	reads    []c5.Seq // the identity.read records in the stream, oldest first
	last     *identityReadDoc
	// unstored is set when a run's identity outcome was not stored, and
	// cleared when one is. The matcher skips the asset meanwhile, since it
	// would evaluate without what the run read (C6 on #458).
	unstored bool
	removed  uint64 // identity.read records removed in this process
}

// identityOf returns the asset's state, reading its stream the first time.
// It returns nil, with the alarm raised, when the stream cannot be read; the
// next run tries again.
func (s *Scheduler) identityOf(ctx context.Context, assetID string) *identityState {
	if st, ok := s.idents[assetID]; ok {
		return st
	}
	st, unsignalled, err := s.loadIdentity(ctx, assetID)
	if err != nil {
		s.raiseOnceKey("identity "+assetID, assetID, AlarmIdentityNotStored, "the stored identity records could not be read, so no identity is stored until they can: "+err.Error())
		return nil
	}
	s.idents[assetID] = st
	if unsignalled != nil {
		s.identityChanged(ctx, assetID, unsignalled, st.doc)
	}
	return st
}

// loadIdentity reads the asset's identity records from config/<asset>. A
// change is committed in the configuration database and signalled in the
// evidence database, so a crash can fall between them (C6 on #454). The
// newest record is a change whose signal may be lost when it names a
// previous record and no identity.read follows it, since every applied run
// stores its read after the signal. loadIdentity then returns that previous
// record as unsignalled, and the change is raised at start. A crash after
// the signal and before the read raises it a second time, never not at all.
func (s *Scheduler) loadIdentity(ctx context.Context, assetID string) (*identityState, *identityDoc, error) {
	stream := ConfigStream(assetID)
	db := s.rt.Store(stream)
	if db == nil {
		return nil, nil, errors.New("the configuration database is not open")
	}
	st := &identityState{}
	var newest, previous *c5.Stored
	var after c5.Seq
	for {
		got, err := db.Read(ctx, stream, after, 16)
		if err != nil {
			return nil, nil, err
		}
		if len(got) == 0 {
			break
		}
		for i := range got {
			r := got[i]
			after = r.Key.Seq
			switch {
			case bytes.HasPrefix(r.Event, []byte(`{"schema":"`+IdentitySchema)):
				previous, newest = newest, &got[i]
			case bytes.HasPrefix(r.Event, []byte(`{"schema":"`+IdentityReadSchema)):
				d, err := decodeIdentityRead(r.Event)
				if err != nil {
					return nil, nil, fmt.Errorf("identity read %d: %w", r.Key.Seq, err)
				}
				st.reads, st.last = append(st.reads, r.Key.Seq), &d
			}
		}
	}
	if newest == nil {
		return st, nil, nil
	}
	d, capture, err := readIdentity(ctx, db, newest)
	if err != nil {
		return nil, nil, err
	}
	st.doc, st.docBytes, st.storedAt, st.capture = &d, newest.Event, newest.CommittedAt, capture
	if d.Previous == "" || (len(st.reads) > 0 && st.reads[len(st.reads)-1] > newest.Key.Seq) {
		return st, nil, nil
	}
	// The previous record is the one before the newest. Should it not be
	// (it is never removed), the change is still raised, against nothing.
	prev := &identityDoc{InvocationID: "(not found)"}
	if previous != nil && digest(previous.Event) == d.Previous {
		p, _, err := readIdentity(ctx, db, previous)
		if err != nil {
			return nil, nil, err
		}
		prev = &p
	}
	return st, prev, nil
}

// readIdentity reads one stored identity record with its capture.
func readIdentity(ctx context.Context, db *store.DB, r *c5.Stored) (identityDoc, []byte, error) {
	var capture *c5.Capture
	if r.EvidenceRef != "" {
		c, err := db.ReadCapture(ctx, r.EvidenceRef)
		if err != nil {
			return identityDoc{}, nil, fmt.Errorf("identity record %d: %w", r.Key.Seq, err)
		}
		capture = &c
	}
	d, err := decodeIdentity(r.Event, capture)
	if err != nil {
		return identityDoc{}, nil, fmt.Errorf("identity record %d: %w", r.Key.Seq, err)
	}
	if capture == nil {
		return d, nil, nil
	}
	return d, capture.Bytes, nil
}

// storeIdentity applies a run's identity to the asset's records, with asset
// on (C5 0.8, the note section 2). A run that did not collect, or whose
// identity did not match, changes nothing (asset.ErrNotApplied). A run whose
// identity differs from the stored one stores a new identity record, and
// every applied run then stores an identity.read and removes the older ones.
// Both go through storeItem3, so the ceiling bounds them. If the identity
// record is not stored, no identity.read is either: the read would say an
// identity the store does not hold was confirmed.
func (s *Scheduler) storeIdentity(ctx context.Context, col Collection, res adapter.Result) {
	if !s.rt.cfg.AssetOn() {
		return
	}
	st := s.identityOf(ctx, col.AssetID)
	if st == nil {
		s.forgetEvaluation(col.AssetID)
		return
	}
	if s.mismatchRead(col, res) {
		s.storeMismatch(ctx, col, res, st)
		return
	}
	notStored := func(err error) {
		s.forgetEvaluation(col.AssetID)
		s.raiseOnceKey("identity "+col.AssetID, col.AssetID, AlarmIdentityNotStored, "run "+res.InvocationID+" read an identity that was not stored: "+err.Error())
	}
	declared, _ := s.rt.cfg.Asset(col.AssetID)
	var stored []c1.Attribute
	if st.doc != nil {
		stored = st.doc.Asset.Attributes
	}
	rec, _, err := asset.Apply(withStoredReads(declared, stored), res, col.Endpoint)
	if errors.Is(err, asset.ErrNotApplied) {
		return
	}
	if err != nil {
		notStored(err)
		return
	}
	stream := ConfigStream(col.AssetID)
	if st.doc == nil || !sameAttributes(st.doc.Asset, rec) {
		doc, capture, err := identityRecord(col.AssetID, rec, res, st)
		if err != nil {
			notStored(err)
			return
		}
		if _, err := s.storeItem3(ctx, stream, doc, capture); err != nil {
			var ce *ceilingError
			if !errors.As(err, &ce) {
				notStored(err)
			}
			s.forgetEvaluation(col.AssetID)
			return
		}
		prev := st.doc
		d, _ := decodeIdentity(doc, capture)
		st.doc, st.docBytes, st.storedAt, st.capture = &d, doc, s.now().UTC(), nil
		if capture != nil {
			st.capture = capture.Bytes
		}
		if prev != nil {
			s.identityChanged(ctx, col.AssetID, prev, &d)
		}
	}
	rd := identityReadDoc{Schema: IdentityReadSchema, AssetID: col.AssetID, InvocationID: res.InvocationID, ReadAt: res.EndedAt}
	s.storeRead(ctx, col.AssetID, st, rd, "run "+res.InvocationID+" read an identity that was not stored: ")
}

// mismatchRead reports whether res is a read that refused the asset's
// identity and so feeds the matcher's LatestMismatch: SEL
// refused.identity_mismatch, or an SNMP poll's authenticated
// failed.identity_mismatch. An SEL failed.identity_mismatch (the SER header
// serial), an unauthenticated refused.engine_id_mismatch and
// failed.snmp_fid_unreadable never do (D4-54).
func (s *Scheduler) mismatchRead(col Collection, res adapter.Result) bool {
	if res.Error == nil || res.Identity.Result != adapter.IdentityMismatch {
		return false
	}
	if s.rt.cfg.snmpEntry(col) {
		return res.Error.Code == adapter.FailedIdentityMismatchLate
	}
	return res.Error.Code == adapter.RefusedIdentityMismatch
}

// storeMismatch stores an identity.read that keeps the last confirming read
// and adds the mismatch (D4-54). An asset no read has confirmed, whose
// identity is its declaration, keeps the mismatch with no latest-read part,
// since the matcher reads it under an operator identity too (C1 on #458).
// Under an operator identity the mismatch names the declaration it
// contradicted, by its hash.
func (s *Scheduler) storeMismatch(ctx context.Context, col Collection, res adapter.Result, st *identityState) {
	rd := identityReadDoc{Schema: IdentityReadSchema, AssetID: col.AssetID}
	switch {
	case st.last != nil:
		rd.InvocationID, rd.ReadAt = st.last.InvocationID, st.last.ReadAt
	case st.doc != nil:
		rd.InvocationID, rd.ReadAt = st.doc.InvocationID, st.doc.ReadAt
	}
	rd.Mismatch = &identityMismatch{InvocationID: res.InvocationID, ReadAt: res.EndedAt}
	for _, it := range res.Identity.Items {
		if it.Name == c1.AttrFirmwareID && it.Observed != it.Expected && len(it.Observed) <= c1.MaxValueBytes {
			rd.Mismatch.FID = it.Observed
		}
	}
	if _, _, read := deviceReadFID(st); !read {
		declared, _ := s.rt.cfg.Asset(col.AssetID)
		rd.Mismatch.DeclaredSHA256 = declaredSum(declared)
	}
	s.storeRead(ctx, col.AssetID, st, rd, "run "+res.InvocationID+" refused the identity, and the mismatch was not stored: ")
}

// storeRead stores one identity.read through the ceiling and removes the
// older ones.
func (s *Scheduler) storeRead(ctx context.Context, assetID string, st *identityState, rd identityReadDoc, what string) {
	b, err := json.Marshal(rd)
	if err == nil {
		var seq c5.Seq
		if seq, err = s.storeItem3(ctx, ConfigStream(assetID), b, nil); err == nil {
			s.clearQuietKey("identity " + assetID)
			st.reads, st.last, st.unstored = append(st.reads, seq), &rd, false
			s.removeOlderReads(ctx, assetID, st)
			s.publishIdentity()
			return
		}
	}
	s.forgetEvaluation(assetID)
	var ce *ceilingError
	if !errors.As(err, &ce) {
		s.raiseOnceKey("identity "+assetID, assetID, AlarmIdentityNotStored, what+err.Error())
	}
}

// removeOlderReads removes every identity.read but the newest, in steps of
// c5.RemoveConfigStep. A removal that fails raises its alarm once, and what
// it did not remove is tried again after the next identity.read.
func (s *Scheduler) removeOlderReads(ctx context.Context, assetID string, st *identityState) {
	stream := ConfigStream(assetID)
	db := s.rt.Store(stream)
	key := "identity-read " + assetID
	for len(st.reads) > 1 && db != nil {
		seqs := st.reads[:min(len(st.reads)-1, c5.RemoveConfigStep)]
		got, err := db.RemoveConfig(ctx, stream, c5.SeriesIdentityRead, seqs)
		if err != nil {
			s.raiseOnceKey(key, assetID, AlarmIdentityReadNotRemoved, fmt.Sprintf("older identity reads %v not removed, so they stay in the configuration class until the next read: %v", seqs, err))
			return
		}
		s.clearQuietKey(key)
		st.reads = st.reads[len(seqs):]
		if got.Records > 0 {
			st.removed += uint64(got.Records)
			s.rt.health(ctx, HealthIdentityReadsRemoved, map[string]string{"asset_id": assetID,
				"records": strconv.Itoa(got.Records), "bytes": strconv.FormatInt(got.Bytes, 10)})
		}
	}
}

// identityChanged raises AlarmIdentityChanged and its health event.
func (s *Scheduler) identityChanged(ctx context.Context, assetID string, prev, now *identityDoc) {
	var names []string
	for _, at := range now.Asset.Attributes {
		if old, ok := prev.Asset.Attribute(at.Name); !ok || old.Value != at.Value {
			names = append(names, at.Name)
		}
	}
	for _, at := range prev.Asset.Attributes {
		if _, ok := now.Asset.Attribute(at.Name); !ok {
			names = append(names, at.Name)
		}
	}
	if len(names) == 0 {
		names = []string{"sources only"}
	}
	list := strings.Join(names, ",")
	s.rt.opt.Status.Raise(assetID, AlarmIdentityChanged, fmt.Sprintf("the identity changed (%s): record %s replaces %s", list, now.InvocationID, prev.InvocationID))
	s.rt.health(ctx, HealthIdentityChanged, map[string]string{"asset_id": assetID, "attributes": list,
		"evidence_id": now.InvocationID, "previous_evidence_id": prev.InvocationID})
}

// withStoredReads is the declared record with its device reads replaced by
// the stored record's, put back as modules/asset's merge would have put
// them, so Apply keeps each first read and a value the run did not read
// again. A device read in the node's configuration is dropped: the node
// holds no bytes for it (EP-2), and only reads whose bytes an identity
// record holds are stored. The operator's observations come from the
// declaration as it is now, so a changed declaration shows as a change.
func withStoredReads(declared c1.Asset, stored []c1.Attribute) c1.Asset {
	out := declared
	out.Attributes = nil
	for _, at := range declared.Attributes {
		at.Observations = slices.DeleteFunc(slices.Clone(at.Observations), func(o c1.Observation) bool { return o.EffectiveKind() == c1.DeviceRead })
		if len(at.Observations) == 0 {
			continue
		}
		at.Confidence = c1.DeriveConfidence(at.Value, at.Observations)
		out.Attributes = append(out.Attributes, at)
	}
	for _, sat := range stored {
		for _, ob := range sat.Observations {
			if ob.EffectiveKind() != c1.DeviceRead {
				continue
			}
			i := slices.IndexFunc(out.Attributes, func(at c1.Attribute) bool { return at.Name == sat.Name })
			if i < 0 {
				out.Attributes = append(out.Attributes, c1.Attribute{Name: sat.Name, Value: ob.Value, Confidence: c1.SingleSource, Observations: []c1.Observation{ob}})
				continue
			}
			at := &out.Attributes[i]
			j := slices.IndexFunc(at.Observations, func(o c1.Observation) bool {
				return o.EvidenceClass == ob.EvidenceClass && o.Source.Method == ob.Source.Method
			})
			if j >= 0 {
				at.Observations[j] = ob
			} else {
				at.Observations = append(at.Observations, ob)
			}
			if !slices.ContainsFunc(at.Observations, func(o c1.Observation) bool { return o.EvidenceClass == c1.OperatorDeclared }) {
				at.Value = ob.Value
			}
			at.Confidence = c1.DeriveConfidence(at.Value, at.Observations)
		}
	}
	return out
}

// sameAttributes reports whether two records hold the same attributes, with
// the same values and sources.
func sameAttributes(a, b c1.Asset) bool {
	x, err1 := json.Marshal(a.Attributes)
	y, err2 := json.Marshal(b.Attributes)
	return err1 == nil && err2 == nil && bytes.Equal(x, y)
}

// identityRecord builds the identity document and capture for rec. Each
// session observation's span is copied from its own run's bytes: this run's
// transcript, or for a read the record kept, the stored record's capture.
// Spans of one run that overlap or touch are one piece.
func identityRecord(assetID string, rec c1.Asset, res adapter.Result, st *identityState) ([]byte, *c5.Capture, error) {
	type span struct {
		inv      string
		from, to int64
	}
	var spans []span
	for _, at := range rec.Attributes {
		for _, ob := range at.Observations {
			if sessionRead(ob) {
				sp := ob.Source.Span
				spans = append(spans, span{ob.Source.Ref, sp.Offset, sp.Offset + sp.Length})
			}
		}
	}
	slices.SortFunc(spans, func(a, b span) int {
		if c := strings.Compare(a.inv, b.inv); c != 0 {
			return c
		}
		return cmp.Compare(a.from, b.from)
	})
	var merged []span
	for _, sp := range spans {
		if n := len(merged); n > 0 && merged[n-1].inv == sp.inv && sp.from <= merged[n-1].to {
			merged[n-1].to = max(merged[n-1].to, sp.to)
			continue
		}
		merged = append(merged, sp)
	}
	d := identityDoc{Schema: IdentitySchema, AssetID: assetID, InvocationID: res.InvocationID, ReadAt: res.EndedAt, Asset: rec}
	if st.doc != nil {
		d.Previous = digest(st.docBytes)
	}
	var data []byte
	for _, sp := range merged {
		b, err := spanBytes(sp.inv, sp.from, sp.to, res, st)
		if err != nil {
			return nil, nil, err
		}
		data = append(data, b...)
		d.Pieces = append(d.Pieces, identityPiece{InvocationID: sp.inv, Offset: sp.from, Length: sp.to - sp.from})
	}
	doc, err := json.Marshal(d)
	if err != nil {
		return nil, nil, err
	}
	var capture *c5.Capture
	if len(data) > 0 {
		capture = &c5.Capture{SHA256: digest(data), Bytes: data}
	}
	return doc, capture, nil
}

// spanBytes returns run inv's transcript bytes from..to.
func spanBytes(inv string, from, to int64, res adapter.Result, st *identityState) ([]byte, error) {
	if inv == res.InvocationID {
		if to > int64(len(res.Transcript.Data)) {
			return nil, fmt.Errorf("span %d..%d is outside run %s's transcript", from, to, inv)
		}
		return res.Transcript.Data[from:to], nil
	}
	if st.doc != nil {
		var at int64
		for _, p := range st.doc.Pieces {
			if p.InvocationID == inv && p.Offset <= from && to <= p.Offset+p.Length {
				return st.capture[at+from-p.Offset : at+to-p.Offset], nil
			}
			at += p.Length
		}
	}
	return nil, fmt.Errorf("span %d..%d of run %s is in neither this run nor the stored identity record", from, to, inv)
}

// IdentityStatus is an asset's identity as status shows it (the note,
// section 6), with asset on.
type IdentityStatus struct {
	// Attributes are the newest identity record's, each with its value
	// and sources. Empty when no identity is stored yet.
	Attributes []c1.Attribute `json:"attributes,omitempty"`
	// EvidenceID is the run that stored the newest identity record.
	EvidenceID string    `json:"evidence_id,omitempty"`
	StoredAt   time.Time `json:"stored_at,omitzero"`
	// LastRead is the last run that confirmed it.
	LastRead *IdentityReadStatus `json:"last_read,omitempty"`
	// Mismatch is a later run that refused the identity, until a run
	// confirms it again.
	Mismatch *IdentityReadStatus `json:"mismatch,omitempty"`
	// ReadsRemoved counts the older identity.read records removed in this
	// process.
	ReadsRemoved uint64 `json:"reads_removed,omitempty"`
}

// IdentityReadStatus is one run that read the identity.
type IdentityReadStatus struct {
	InvocationID string `json:"invocation_id"`
	At           string `json:"at"`
}

// publishIdentity puts every loaded asset's identity in status.
func (s *Scheduler) publishIdentity() {
	m := map[string]IdentityStatus{}
	for id, st := range s.idents {
		var is IdentityStatus
		if st.doc != nil {
			is.Attributes, is.EvidenceID, is.StoredAt = st.doc.Asset.Attributes, st.doc.InvocationID, st.storedAt
		}
		if st.last != nil {
			if st.last.InvocationID != "" {
				is.LastRead = &IdentityReadStatus{InvocationID: st.last.InvocationID, At: st.last.ReadAt}
			}
			if m := st.last.Mismatch; m != nil {
				is.Mismatch = &IdentityReadStatus{InvocationID: m.InvocationID, At: m.ReadAt}
			}
		}
		is.ReadsRemoved = st.removed
		m[id] = is
	}
	s.rt.opt.Status.SetIdentity(m)
	s.rt.opt.Status.Write(string(s.rt.cfg.NodeID))
}

// startIdentity reads every scheduled asset's identity records, with asset
// on, so status shows them from the start.
func (s *Scheduler) startIdentity(ctx context.Context) {
	if !s.rt.cfg.AssetOn() {
		return
	}
	for _, col := range s.rt.cfg.Schedule {
		s.identityOf(ctx, col.AssetID)
	}
	s.publishIdentity()
}
