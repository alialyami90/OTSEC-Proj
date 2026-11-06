package applicability

import (
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"time"

	"otsec.local/otsec/contracts/advisory"
	"otsec.local/otsec/contracts/finding"
)

// The matcher's name and version, written into every finding.
const (
	Name    = "otsec-applicability"
	Version = "0.1.0"
)

// Input is everything the matcher reads about one asset. The node fills it
// from its stored records.
type Input struct {
	AssetID      string
	EvaluatedUTC string // when the node ran the evaluation, RFC 3339 UTC
	Identity     Identity
	// Settings is the asset's latest C9 snapshot, or nil if none is held.
	Settings *Snapshot
	// LatestChange is the latest configuration change retrieved for the
	// asset, by its invocation ID and time (D4-49 Q6 (iv)).
	LatestChange *finding.Read
	// LatestMismatch is the latest device read that refused the asset's
	// identity (refused.identity_mismatch on the SEL-751, an authenticated
	// failed.identity_mismatch on SNMPv3). It adopts no value, and makes the
	// identity stale until a later read confirms it (C1 on #445). An
	// unauthenticated refused.engine_id_mismatch and a
	// failed.snmp_fid_unreadable are not mismatches: neither shows another
	// FID (D4-53, C1 on #445).
	LatestMismatch *finding.Read
	// MismatchFID is the FID the latest mismatch read reported. It is never
	// adopted, but an entry naming its model cannot be product-not-named
	// while the mismatch stands (C1 on #451).
	MismatchFID string
	// Controls are the operator-recorded network controls for the asset.
	Controls []Control
}

// Identity is the asset's latest identity record.
type Identity struct {
	Source finding.Source
	// Evidence cites the record: the invocation ID of the run that first
	// read it (device-read), its event ID (passive), or its audit reference
	// (operator).
	Evidence        string
	FirmwareID      string // the FID, as read or declared
	Model           string // C1 0.3 model; empty to take it from the FID
	FirmwareVersion string // C1 0.3 firmware_version; may be empty
	// LatestRead is the latest run that read the same value (device-read
	// only).
	LatestRead *finding.Read
}

// Snapshot is a C9 settings snapshot: the invocation ID of the read, its
// time, and each setting's value as stored.
type Snapshot struct {
	ID       string
	AtUTC    string
	Settings map[string]string
}

// Control is a recorded control that blocks Key (<tcp|udp>/<port>), cited
// by its audit reference.
type Control struct {
	Key      string
	Evidence string
}

// Previous is the asset's latest stored finding for one entry, with the
// Hash of its bytes as stored.
type Previous struct {
	Finding finding.Finding
	Hash    string
}

// fidRe is the SEL FID form (note §3). The letter is any capital, so an X
// branch FID still yields its product and is then left unplaceable.
var fidRe = regexp.MustCompile(`^(SEL-[0-9A-Z]+)-(([A-Z])([0-9]{3})-V([0-9]+))-Z[0-9]{6}-D[0-9]{8}$`)

var endpointRe = regexp.MustCompile(`^R([0-9]{3})-V([0-9]+)$`)

// fid is a parsed FID.
type fid struct {
	product   string
	version   string // R301-V2, as printed
	placeable bool   // an R branch whose parts agree with the identity
	branch    string
	v         uint64
}

// parseFID parses the identity's FID. The product is the device-read model
// when one is given, else the FID's product part; ok is false when neither
// gives one.
func parseFID(id Identity) (f fid, ok bool) {
	m := fidRe.FindStringSubmatch(id.FirmwareID)
	if m == nil {
		return fid{product: id.Model}, id.Model != ""
	}
	f = fid{product: m[1], version: m[2], branch: m[4]}
	if id.Model != "" {
		f.product = id.Model
	}
	v, err := strconv.ParseUint(m[5], 10, 64)
	f.v = v
	f.placeable = err == nil && m[3] == "R" &&
		(id.Model == "" || id.Model == m[1]) &&
		(id.FirmwareVersion == "" || id.FirmwareVersion == m[2])
	return f, true
}

// Evaluate matches in against every entry of set and returns the findings
// that are new or changed, in the set's entry order. prev holds the asset's
// latest finding per entry ID.
func Evaluate(in Input, set *advisory.Set, prev map[string]Previous) ([]finding.Finding, error) {
	if err := set.Validate(); err != nil {
		return nil, err
	}
	f, ok := parseFID(in.Identity)
	if !ok {
		return nil, errors.New("applicability: the identity names no product")
	}
	e := evaluator{in: in, fid: f}
	var err error
	if e.current, e.contradicting, err = identityCurrent(in); err != nil {
		return nil, err
	}
	if m := in.LatestMismatch; m != nil {
		e.mismatched = slices.Contains(e.contradicting, *m)
	}
	if mm := fidRe.FindStringSubmatch(in.MismatchFID); e.mismatched && mm != nil {
		e.mismatchProduct = mm[1]
	}
	if e.settingsCurrent, err = settingsCurrent(in); err != nil {
		return nil, err
	}
	var out []finding.Finding
	for _, entry := range set.Entries {
		nf := e.entry(entry)
		nf.Set = finding.Set{ID: set.SetID, Version: set.Version, IssuedAt: set.IssuedAt}
		p, had := prev[entry.ID]
		if had && same(p.Finding, nf) {
			continue
		}
		if had {
			nf.Revision, nf.Previous, nf.From = p.Finding.Revision+1, p.Hash, p.Finding.Class
		}
		if err := nf.Validate(); err != nil {
			return nil, fmt.Errorf("applicability: entry %s: %w", entry.ID, err)
		}
		out = append(out, nf)
	}
	return out, nil
}

// identityCurrent reports whether a device-read identity is current: its
// latest read is later than the latest change retrieved and the latest
// mismatch (note §6). It also returns the reads that made it stale.
func identityCurrent(in Input) (bool, []finding.Read, error) {
	if in.Identity.Source != finding.DeviceRead {
		return true, nil, nil
	}
	var read time.Time
	if r := in.Identity.LatestRead; r != nil {
		t, err := parseUTC(r.AtUTC)
		if err != nil {
			return false, nil, err
		}
		read = t
	}
	var after []finding.Read
	for _, c := range []*finding.Read{in.LatestChange, in.LatestMismatch} {
		if c == nil {
			continue
		}
		t, err := parseUTC(c.AtUTC)
		if err != nil {
			return false, nil, err
		}
		if !t.Before(read) {
			after = append(after, *c)
		}
	}
	return in.Identity.LatestRead != nil && len(after) == 0, after, nil
}

// settingsCurrent reports whether the snapshot is current: no change was
// retrieved after it.
func settingsCurrent(in Input) (bool, error) {
	if in.Settings == nil {
		return false, nil
	}
	at, err := parseUTC(in.Settings.AtUTC)
	if err != nil || in.LatestChange == nil {
		return err == nil, err
	}
	ch, err := parseUTC(in.LatestChange.AtUTC)
	return err == nil && !ch.After(at), err
}

func parseUTC(s string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return t, fmt.Errorf("applicability: %q is not an RFC 3339 time", s)
	}
	return t, nil
}

type evaluator struct {
	in              Input
	fid             fid
	current         bool
	contradicting   []finding.Read
	mismatched      bool   // a mismatch later than the latest read contradicts the FID
	mismatchProduct string // the model that mismatch read reported, if it parses
	settingsCurrent bool
}

func (e *evaluator) base(class finding.Class) finding.Finding {
	id := e.in.Identity
	fi := finding.Identity{
		Product:  e.fid.product,
		Version:  id.FirmwareID,
		Source:   id.Source,
		Evidence: []finding.Evidence{{Source: id.Source, ID: id.Evidence}},
	}
	if id.Source == finding.DeviceRead && id.LatestRead != nil {
		r := *id.LatestRead
		fi.LatestRead = &r
	}
	return finding.Finding{
		Schema:       finding.Identifier,
		AssetID:      e.in.AssetID,
		Revision:     1,
		Class:        class,
		EvaluatedUTC: e.in.EvaluatedUTC,
		Matcher:      finding.Matcher{Name: Name, Version: Version},
		Identity:     fi,
	}
}

var notApplicable = map[finding.Source]finding.Class{
	finding.DeviceRead: finding.NotApplicable,
	finding.Operator:   finding.NotApplicableOperator,
	finding.Passive:    finding.NotApplicablePassive,
}

func (e *evaluator) entry(entry advisory.Entry) finding.Finding {
	f := e.base("")
	f.Advisory = entry.ID
	na := func(r finding.Reason) finding.Finding {
		f.Class, f.Reason = notApplicable[e.in.Identity.Source], r
		return f
	}
	named, namesMismatch, inside, unplaceable := false, false, false, false
	for _, a := range entry.Affected {
		if e.mismatchProduct != "" && a.Product == e.mismatchProduct {
			namesMismatch = true
		}
		if a.Product != e.fid.product {
			continue
		}
		named = true
		if slices.Contains(a.Versions, e.in.Identity.FirmwareID) {
			inside = true
		}
		for _, r := range a.Ranges {
			if r.Introduced == "" && r.Fixed == "" {
				inside = true
			} else if a.Scheme == advisory.SchemeSELFID && e.fid.placeable && e.fid.in(r) {
				inside = true
			}
		}
		if a.Scheme == advisory.SchemeSELFID && !e.fid.placeable {
			unplaceable = true
		}
	}
	switch {
	case !named && !namesMismatch:
		return na(finding.ProductNotNamed)
	case e.mismatched || !inside && unplaceable:
		// A FID the scheme cannot place, or one a later mismatch read
		// contradicts (C6 on #451), can make the asset neither outside a
		// range nor clear of a precondition.
		f.Class = finding.ApplicableByVersion
		f.Preconditions = []finding.Precondition{{Name: advisory.ReservedFirmwareVersion, State: finding.Unread}}
		e.markStale(&f)
		return f
	case !inside:
		return na(finding.OutsideRange)
	}
	return e.inside(f, entry)
}

// in reports whether the FID is inside r, which has at least one endpoint
// (C11 has checked both are on one branch).
func (f fid) in(r advisory.Range) bool {
	lo, hi := uint64(0), uint64(0)
	bounded := false
	for i, s := range []string{r.Introduced, r.Fixed} {
		if s == "" {
			continue
		}
		m := endpointRe.FindStringSubmatch(s)
		if m == nil || m[1] != f.branch {
			return false
		}
		v, err := strconv.ParseUint(m[2], 10, 64)
		if err != nil {
			return false
		}
		if i == 0 {
			lo = v
		} else {
			hi, bounded = v, true
		}
	}
	return f.v >= lo && (!bounded || f.v < hi)
}

// inside applies note §5 step 4.
func (e *evaluator) inside(f finding.Finding, entry advisory.Entry) finding.Finding {
	var pres, notMet []finding.Precondition
	unread := false
	notMetKeys := map[string]bool{}
	for _, it := range entry.Preconditions {
		p := e.read(it)
		pres = append(pres, p)
		switch p.State {
		case finding.Unread:
			unread = true
		case finding.NotMet:
			notMet = append(notMet, p)
			notMetKeys[it.Key] = true
		}
	}
	var held []finding.Mitigation
	sameSetting := false
	for _, it := range entry.Mitigations {
		p := e.read(it)
		if p.State != finding.Evidenced {
			continue
		}
		held = append(held, finding.Mitigation{Name: it.Name, OperatorAttested: allOperator(p.Evidence), Evidence: p.Evidence})
		if it.Kind == advisory.KindSetting && notMetKeys[it.Key] {
			sameSetting = true
		}
	}
	deviceRead := e.in.Identity.Source == finding.DeviceRead
	switch {
	case len(notMet) > 0 && sameSetting, len(notMet) == 0 && len(held) > 0:
		f.Class, f.Preconditions, f.Mitigations = finding.Mitigated, pres, held
	case len(notMet) > 0 && deviceRead:
		f.Class, f.Reason, f.Preconditions = finding.NotApplicable, finding.PreconditionNotMet, notMet
	case len(notMet) == 0 && deviceRead && e.current && !unread:
		f.Class, f.Preconditions = finding.Confirmed, pres
	default:
		f.Class, f.Preconditions = finding.ApplicableByVersion, pres
		e.markStale(&f)
	}
	return f
}

// markStale marks a device-read identity that is not current stale, and
// cites each read that made it so.
func (e *evaluator) markStale(f *finding.Finding) {
	if e.in.Identity.Source != finding.DeviceRead || e.current {
		return
	}
	f.Identity.Evidence[0].Stale = true
	for _, r := range e.contradicting {
		if r.ID != e.in.Identity.Evidence {
			f.Identity.Evidence = append(f.Identity.Evidence, finding.Evidence{Source: finding.DeviceRead, ID: r.ID})
		}
	}
}

// read gives one precondition or mitigation its state from current
// evidence (note §4). A service has no read path before R6.7, and C1 0.3's
// attribute records are not yet an input, so both stay unread: unread never
// hides an advisory.
func (e *evaluator) read(it advisory.Item) finding.Precondition {
	p := finding.Precondition{Name: it.Name, State: finding.Unread}
	switch it.Kind {
	case advisory.KindSetting:
		if !e.settingsCurrent {
			return p
		}
		val, ok := e.in.Settings.Settings[it.Key]
		if !ok {
			// A key missing from the snapshot may be a section not read, so
			// absent is never shown either.
			return p
		}
		holds := true
		switch it.Op {
		case advisory.OpIn:
			holds = slices.Contains(it.Values, val)
		case advisory.OpNotIn:
			holds = !slices.Contains(it.Values, val)
		case advisory.OpAbsent:
			holds = false
		}
		p.State = finding.NotMet
		if holds {
			p.State = finding.Evidenced
		}
		p.Evidence = []finding.Evidence{{Source: finding.DeviceRead, ID: e.in.Settings.ID}}
	case advisory.KindControl:
		for _, c := range e.in.Controls {
			if c.Key == it.Key {
				p.State = finding.Evidenced
				p.Evidence = []finding.Evidence{{Source: finding.Operator, ID: c.Evidence}}
				break
			}
		}
	}
	return p
}

func allOperator(ev []finding.Evidence) bool {
	for _, x := range ev {
		if x.Source != finding.Operator {
			return false
		}
	}
	return len(ev) > 0
}

// same reports whether two findings differ in nothing C12 §7 lists: the
// revision fields, the evaluation time, the matcher and
// identity.latest_read are left out.
func same(a, b finding.Finding) bool {
	strip := func(f finding.Finding) finding.Finding {
		f.Revision, f.Previous, f.From, f.EvaluatedUTC, f.Matcher = 0, "", "", "", finding.Matcher{}
		f.Identity.LatestRead = nil
		return f
	}
	return reflect.DeepEqual(strip(a), strip(b))
}
