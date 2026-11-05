package finding

import (
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"testing"
)

const testAsset = "5e3a1c2d-9b8f-4e7a-8c6d-1f2e3d4c5b6a"

var (
	idRead  = Evidence{Source: DeviceRead, ID: "site-a-node1:sel751-feeder1/identity:7"}
	cfgRead = Evidence{Source: DeviceRead, ID: "site-a-node1:sel751-feeder1/config:3"}
	seen    = Evidence{Source: Passive, ID: "site-a-node1:passive/services:12"}
	entered = Evidence{Source: Operator, ID: "audit:site-a-node1:40"}
)

// confirmed is a valid confirmed finding; each case below starts from it.
func confirmed() *Finding {
	return &Finding{
		Schema:       Identifier,
		AssetID:      testAsset,
		Advisory:     "test-only-0001",
		Set:          Set{ID: "otsec-sel", Version: 3, IssuedAt: "2026-11-01T00:00:00Z"},
		Revision:     1,
		Class:        Confirmed,
		EvaluatedUTC: "2026-11-05T06:00:00Z",
		Matcher:      Matcher{Name: "otsec-applicability", Version: "0.1"},
		Identity:     Identity{Product: "SEL-751", Version: "SEL-751-R301-V2-Z009005-D20220607", Source: DeviceRead, Evidence: []Evidence{idRead}},
		Preconditions: []Precondition{
			{Name: "web-server-enabled", State: Evidenced, Evidence: []Evidence{cfgRead}},
			{Name: "http-reachable", State: Evidenced, Evidence: []Evidence{seen}},
		},
	}
}

func TestValidFindings(t *testing.T) {
	for name, mut := range map[string]func(*Finding){
		"confirmed": func(*Finding) {},
		"applicable-by-version, a precondition unread": func(f *Finding) {
			f.Class = ApplicableByVersion
			f.Preconditions[0] = Precondition{Name: "web-server-enabled", State: Unread}
		},
		"applicable-by-version, operator identity": func(f *Finding) {
			f.Class = ApplicableByVersion
			f.Identity.Source, f.Identity.Evidence = Operator, []Evidence{entered}
		},
		"mitigated, operator-attested": func(f *Finding) {
			f.Class = Mitigated
			f.Mitigations = []Mitigation{{Name: "http-blocked-at-firewall", OperatorAttested: true, Evidence: []Evidence{entered}}}
		},
		"not-applicable, outside the range": func(f *Finding) {
			f.Class, f.Reason, f.Preconditions = NotApplicable, OutsideRange, nil
		},
		"not-applicable, a precondition not met": func(f *Finding) {
			f.Class, f.Reason = NotApplicable, PreconditionNotMet
			f.Preconditions[0].State = NotMet
		},
		"not-applicable-passive": func(f *Finding) {
			f.Class, f.Reason, f.Preconditions = NotApplicablePassive, OutsideRange, nil
			f.Identity.Source, f.Identity.Evidence = Passive, []Evidence{seen}
		},
		"applicable-by-version, stale evidence named": func(f *Finding) {
			f.Class = ApplicableByVersion
			f.Preconditions[0].Evidence[0].Stale = true
		},
		"applicable-by-version, operator identity, a precondition not met": func(f *Finding) {
			f.Class, f.Preconditions[0].State = ApplicableByVersion, NotMet
			f.Identity.Source, f.Identity.Evidence = Operator, []Evidence{entered}
		},
		"mitigated, the precondition's setting named as the mitigation": func(f *Finding) {
			f.Class, f.Preconditions[0].State = Mitigated, NotMet
			f.Mitigations = []Mitigation{{Name: "web-server-disabled", Evidence: []Evidence{cfgRead}}}
		},
		"not-applicable-operator": func(f *Finding) {
			f.Class, f.Reason, f.Preconditions = NotApplicableOperator, ProductNotNamed, nil
			f.Identity.Source, f.Identity.Evidence = Operator, []Evidence{entered}
		},
		"a later revision": func(f *Finding) {
			f.Revision, f.Previous, f.From = 2, Hash([]byte("revision 1")), ApplicableByVersion
		},
	} {
		f := confirmed()
		mut(f)
		if err := f.Validate(); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestInvalidFindings(t *testing.T) {
	for name, c := range map[string]struct {
		mut  func(*Finding)
		want Code
	}{
		"another contract":                    {func(f *Finding) { f.Schema = "otsec.baseline/0.1" }, CodeSchema},
		"no set date":                         {func(f *Finding) { f.Set.IssuedAt = "" }, CodeMissing},
		"no set ID":                           {func(f *Finding) { f.Set.ID = "" }, CodeForm},
		"set version 0":                       {func(f *Finding) { f.Set.Version = 0 }, CodeRange},
		"a class not in the list":             {func(f *Finding) { f.Class = "exploitable" }, CodeForm},
		"revision 1 that replaces something":  {func(f *Finding) { f.From = ApplicableByVersion }, CodeConflict},
		"a later revision that names nothing": {func(f *Finding) { f.Revision = 2 }, CodeMissing},
		"identity with no evidence":           {func(f *Finding) { f.Identity.Evidence = nil }, CodeMissing},
		"an evidence ID of no form":           {func(f *Finding) { f.Identity.Evidence[0].ID = "the relay said so" }, CodeForm},
		"identity evidence of another source": {func(f *Finding) { f.Identity.Evidence[0].Source = Operator }, CodeConflict},
		"confirmed on an operator identity": {func(f *Finding) {
			f.Identity.Source, f.Identity.Evidence = Operator, []Evidence{entered}
		}, CodeConflict},
		"confirmed on a passive identity": {func(f *Finding) {
			f.Identity.Source, f.Identity.Evidence = Passive, []Evidence{seen}
		}, CodeConflict},
		"confirmed with a precondition unread": {func(f *Finding) {
			f.Preconditions[1] = Precondition{Name: "http-reachable", State: Unread}
		}, CodeConflict},
		"confirmed on an operator's precondition":    {func(f *Finding) { f.Preconditions[0].Evidence = []Evidence{entered} }, CodeConflict},
		"an evidenced precondition with no evidence": {func(f *Finding) { f.Preconditions[0].Evidence = nil }, CodeMissing},
		"an unread precondition with evidence": {func(f *Finding) {
			f.Class, f.Preconditions[0].State = ApplicableByVersion, Unread
		}, CodeConflict},
		"a precondition named twice": {func(f *Finding) { f.Preconditions[1].Name = f.Preconditions[0].Name }, CodeForm},
		"an unread precondition dropped into not-applicable": {func(f *Finding) {
			f.Class, f.Reason, f.Preconditions[0] = NotApplicable, OutsideRange, Precondition{Name: "web-server-enabled", State: Unread}
		}, CodeConflict},
		"a mitigation on a confirmed finding": {func(f *Finding) {
			f.Mitigations = []Mitigation{{Name: "x", Evidence: []Evidence{cfgRead}}}
		}, CodeConflict},
		"mitigated with no mitigation": {func(f *Finding) { f.Class = Mitigated }, CodeMissing},
		"an operator's mitigation not labelled": {func(f *Finding) {
			f.Class, f.Mitigations = Mitigated, []Mitigation{{Name: "x", Evidence: []Evidence{entered}}}
		}, CodeConflict},
		"not-applicable with no reason":     {func(f *Finding) { f.Class, f.Preconditions = NotApplicable, nil }, CodeConflict},
		"a reason on an applicable finding": {func(f *Finding) { f.Reason = OutsideRange }, CodeConflict},
		"not-applicable on an operator identity": {func(f *Finding) {
			f.Class, f.Reason, f.Preconditions = NotApplicable, OutsideRange, nil
			f.Identity.Source, f.Identity.Evidence = Operator, []Evidence{entered}
		}, CodeConflict},
		"not-applicable-operator on a device read": {func(f *Finding) {
			f.Class, f.Reason, f.Preconditions = NotApplicableOperator, OutsideRange, nil
		}, CodeConflict},
		"confirmed on stale identity evidence": {func(f *Finding) { f.Identity.Evidence[0].Stale = true }, CodeConflict},
		"confirmed on a stale precondition":    {func(f *Finding) { f.Preconditions[1].Evidence[0].Stale = true }, CodeConflict},
		"not-applicable-passive on a device read": {func(f *Finding) {
			f.Class, f.Reason, f.Preconditions = NotApplicablePassive, OutsideRange, nil
		}, CodeConflict},
		"a precondition not met on a device-read applicable finding": {func(f *Finding) {
			f.Class, f.Preconditions[0].State = ApplicableByVersion, NotMet
		}, CodeConflict},
		"not met shown only passively": {func(f *Finding) {
			f.Class, f.Reason, f.Preconditions = NotApplicable, PreconditionNotMet, []Precondition{{Name: "http-reachable", State: NotMet, Evidence: []Evidence{seen}}}
		}, CodeConflict},
		"too much evidence": {func(f *Finding) {
			for range MaxEvidence {
				f.Identity.Evidence = append(f.Identity.Evidence, idRead)
			}
		}, CodeRange},
	} {
		f := confirmed()
		c.mut(f)
		err := f.Validate()
		if !slices.Contains(Codes(err), c.want) {
			t.Errorf("%s: %v, want a %s failure", name, err, c.want)
		}
	}
}

// TestNoFieldStatesExploitability: no field of the record, at any depth,
// is named for exploitability, risk or severity (R9.2, P10).
func TestNoFieldStatesExploitability(t *testing.T) {
	banned := []string{"exploit", "risk", "severity", "cvss", "score", "vulnerable", "impact"}
	var walk func(reflect.Type)
	walk = func(ty reflect.Type) {
		for ty.Kind() == reflect.Slice || ty.Kind() == reflect.Pointer {
			ty = ty.Elem()
		}
		if ty.Kind() != reflect.Struct {
			return
		}
		for i := range ty.NumField() {
			sf := ty.Field(i)
			name := strings.ToLower(sf.Name + " " + sf.Tag.Get("json"))
			for _, b := range banned {
				if strings.Contains(name, b) {
					t.Errorf("%s.%s is named for %q", ty.Name(), sf.Name, b)
				}
			}
			walk(sf.Type)
		}
	}
	walk(reflect.TypeOf(Finding{}))
}

// TestReclassificationIsARevision: a later revision names the stored bytes
// of the one it replaces and its class, so the change is on record.
func TestReclassificationIsARevision(t *testing.T) {
	r1 := confirmed()
	r1.Class, r1.Preconditions[0] = ApplicableByVersion, Precondition{Name: "web-server-enabled", State: Unread}
	b1, err := json.Marshal(r1)
	if err != nil {
		t.Fatal(err)
	}
	r2 := confirmed()
	r2.Revision, r2.Previous, r2.From = 2, Hash(b1), r1.Class
	if err := r2.Validate(); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(r2.Previous, "sha256:") || len(r2.Previous) != 71 {
		t.Errorf("previous %q", r2.Previous)
	}
}
