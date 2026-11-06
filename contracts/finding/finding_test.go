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
	idRead  = Evidence{Source: DeviceRead, ID: "0b6c2f1e-7d3a-4c5b-9e8f-1a2b3c4d5e6f"} // a C2 invocation ID
	cfgRead = Evidence{Source: DeviceRead, ID: "9f8e7d6c-5b4a-4321-8fed-cba987654321"}
	seen    = Evidence{Source: Passive, ID: "site-a-node1:passive/services:12"} // a stored event
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
		Identity: Identity{Product: "SEL-751", Version: "SEL-751-R301-V2-Z009005-D20220607", Source: DeviceRead, Evidence: []Evidence{idRead},
			LatestRead: &Read{ID: "4d2e6a10-3b7c-4f9e-8a1d-2c3b4a5f6e7d", AtUTC: "2026-11-05T05:59:00Z"}},
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
			f.Identity.Source, f.Identity.Evidence, f.Identity.LatestRead = Operator, []Evidence{entered}, nil
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
			f.Identity.Source, f.Identity.Evidence, f.Identity.LatestRead = Passive, []Evidence{seen}, nil
		},
		"applicable-by-version, stale evidence named": func(f *Finding) {
			f.Class = ApplicableByVersion
			f.Preconditions[0].Evidence[0].Stale = true
		},
		"applicable-by-version, operator identity, a precondition not met": func(f *Finding) {
			f.Class, f.Preconditions[0].State = ApplicableByVersion, NotMet
			f.Identity.Source, f.Identity.Evidence, f.Identity.LatestRead = Operator, []Evidence{entered}, nil
		},
		"mitigated, the precondition's setting named as the mitigation": func(f *Finding) {
			f.Class, f.Preconditions[0].State = Mitigated, NotMet
			f.Mitigations = []Mitigation{{Name: "web-server-disabled", Evidence: []Evidence{cfgRead}}}
		},
		"not-applicable-operator": func(f *Finding) {
			f.Class, f.Reason, f.Preconditions = NotApplicableOperator, ProductNotNamed, nil
			f.Identity.Source, f.Identity.Evidence, f.Identity.LatestRead = Operator, []Evidence{entered}, nil
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
		"an audit reference to no node ID": {func(f *Finding) {
			f.Mitigations, f.Class = []Mitigation{{Name: "x", OperatorAttested: true, Evidence: []Evidence{{Source: Operator, ID: "audit:Not A Node:4"}}}}, Mitigated
		}, CodeForm},
		"an invocation ID in upper case":    {func(f *Finding) { f.Identity.Evidence[0].ID = "0B6C2F1E-7D3A-4C5B-9E8F-1A2B3C4D5E6F" }, CodeForm},
		"confirmed with no latest read":     {func(f *Finding) { f.Identity.LatestRead = nil }, CodeMissing},
		"a latest read of no invocation ID": {func(f *Finding) { f.Identity.LatestRead.ID = "site-a-node1:x:1" }, CodeForm},
		"a latest read on an operator identity": {func(f *Finding) {
			f.Class, f.Identity.Source, f.Identity.Evidence = ApplicableByVersion, Operator, []Evidence{entered}
		}, CodeConflict},
		// C6's probes on #440.
		"mitigated on stale mitigation evidence": {func(f *Finding) {
			f.Class = Mitigated
			f.Mitigations = []Mitigation{{Name: "web-server-disabled", Evidence: []Evidence{{Source: DeviceRead, ID: cfgRead.ID, Stale: true}}}}
		}, CodeConflict},
		"precondition-not-met on stale evidence": {func(f *Finding) {
			f.Class, f.Reason = NotApplicable, PreconditionNotMet
			f.Preconditions[0] = Precondition{Name: "web-server-enabled", State: NotMet, Evidence: []Evidence{{Source: DeviceRead, ID: cfgRead.ID, Stale: true}}}
		}, CodeConflict},
		"operator-attested reckoned over stale evidence too": {func(f *Finding) {
			f.Class = Mitigated
			f.Mitigations = []Mitigation{{Name: "web-server-disabled", Evidence: []Evidence{{Source: DeviceRead, ID: cfgRead.ID, Stale: true}, entered}}}
		}, CodeConflict},
		"device-read evidence citing an audit record": {func(f *Finding) {
			f.Identity.Evidence = []Evidence{{Source: DeviceRead, ID: entered.ID}}
		}, CodeForm},
		"operator evidence citing a device read": {func(f *Finding) {
			f.Class = ApplicableByVersion
			f.Identity.Source, f.Identity.Evidence, f.Identity.LatestRead = Operator, []Evidence{{Source: Operator, ID: idRead.ID}}, nil
		}, CodeForm},
		"passive evidence citing an invocation": {func(f *Finding) {
			f.Preconditions[1].Evidence = []Evidence{{Source: Passive, ID: cfgRead.ID}}
		}, CodeForm},
		// D4-57 (C6's F-025): an audit reference is also a well-formed
		// event ID, with "audit" as the node, so the prefix decides.
		"passive evidence citing an audit record": {func(f *Finding) {
			f.Preconditions[1].Evidence = []Evidence{{Source: Passive, ID: entered.ID}}
		}, CodeForm},
		"an invocation ID of version 0": {func(f *Finding) { f.Identity.Evidence[0].ID = "0b6c2f1e-7d3a-0c5b-9e8f-1a2b3c4d5e6f" }, CodeForm},
		"an invocation ID of another variant": {func(f *Finding) {
			f.Identity.Evidence[0].ID = "0b6c2f1e-7d3a-4c5b-7e8f-1a2b3c4d5e6f"
		}, CodeForm},
		"an audit reference to seq 0": {func(f *Finding) {
			f.Mitigations, f.Class = []Mitigation{{Name: "x", OperatorAttested: true, Evidence: []Evidence{{Source: Operator, ID: "audit:site-a-node1:0"}}}}, Mitigated
		}, CodeForm},
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

// Known names exactly the minors this build reads, so a node can refuse
// any other rather than skip it (D4-61).
func TestKnown(t *testing.T) {
	for _, s := range []string{Identifier, "otsec.finding/0.1", "otsec.finding/0.2"} {
		if !Known(s) {
			t.Errorf("Known(%q) = false", s)
		}
	}
	for _, s := range []string{"", "otsec.finding/0.3", "otsec.finding/0.10", "otsec.finding/1.0",
		"otsec.finding/0.01", "otsec.finding/0.1 ", "otsec.config/0.1", "OTSEC.FINDING/0.1"} {
		if Known(s) {
			t.Errorf("Known(%q) = true", s)
		}
	}
}

// mismatched is a valid 0.2 finding on an operator identity that a device
// read refused (D4-55, D4-61): applicable-by-version, firmware-version
// unread, the declaration stale, and the refusing read in identity.mismatch.
func mismatched() *Finding {
	f := confirmed()
	f.Class = ApplicableByVersion
	f.Identity.Source, f.Identity.LatestRead = Operator, nil
	f.Identity.Evidence = []Evidence{{Source: Operator, ID: entered.ID, Stale: true}}
	f.Identity.Mismatch = &Read{ID: "7c1d2e3f-4a5b-4c6d-9e7f-8a9b0c1d2e3f", AtUTC: "2026-11-05T05:58:00.123456789Z"}
	f.Preconditions = []Precondition{{Name: "firmware-version", State: Unread}}
	return f
}

// C12 0.2's rules 1 to 5 on identity.mismatch (docs/phase4/D4-c12-0.2.md
// section 4).
func TestMismatchRules(t *testing.T) {
	for name, mut := range map[string]func(*Finding){
		"an operator identity under a mismatch": func(*Finding) {},
		"a passive identity under a mismatch": func(f *Finding) {
			f.Identity.Source, f.Identity.Evidence = Passive, []Evidence{{Source: Passive, ID: seen.ID, Stale: true}}
		},
		"other preconditions beside firmware-version": func(f *Finding) {
			f.Preconditions = append(f.Preconditions, Precondition{Name: "web-server-enabled", State: Evidenced, Evidence: []Evidence{cfgRead}})
		},
		// Rule 4 is for 0.2 records only: a 0.1 reader is kept.
		"a 0.1 record, a stale operator identity, no mismatch": func(f *Finding) {
			f.Schema, f.Identity.Mismatch = "otsec.finding/0.1", nil
		},
	} {
		f := mismatched()
		mut(f)
		if err := f.Validate(); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, c := range map[string]struct {
		mut  func(*Finding)
		want Code
	}{
		"rule 1: an ID of no invocation form": {func(f *Finding) { f.Identity.Mismatch.ID = entered.ID }, CodeForm},
		"rule 1: an upper-case invocation ID": {func(f *Finding) { f.Identity.Mismatch.ID = strings.ToUpper(f.Identity.Mismatch.ID) }, CodeForm},
		"rule 1: no time":                     {func(f *Finding) { f.Identity.Mismatch.AtUTC = "" }, CodeMissing},
		"rule 1: a local time":                {func(f *Finding) { f.Identity.Mismatch.AtUTC = "2026-11-05T08:58:00+03:00" }, CodeForm},
		"rule 2: on a device-read identity": {func(f *Finding) {
			f.Identity.Source, f.Identity.Evidence = DeviceRead, []Evidence{{Source: DeviceRead, ID: idRead.ID, Stale: true}}
		}, CodeConflict},
		"rule 3: the identity's evidence current": {func(f *Finding) { f.Identity.Evidence[0].Stale = false }, CodeConflict},
		"rule 3: not-applicable-operator": {func(f *Finding) {
			f.Class, f.Reason, f.Preconditions = NotApplicableOperator, OutsideRange, nil
		}, CodeConflict},
		"rule 3: mitigated": {func(f *Finding) {
			f.Class = Mitigated
			f.Mitigations = []Mitigation{{Name: "http-blocked-at-firewall", OperatorAttested: true, Evidence: []Evidence{entered}}}
		}, CodeConflict},
		"rule 3: firmware-version not named": {func(f *Finding) { f.Preconditions = nil }, CodeConflict},
		"rule 3: firmware-version named, not unread": {func(f *Finding) {
			f.Preconditions[0] = Precondition{Name: "firmware-version", State: Evidenced, Evidence: []Evidence{cfgRead}}
		}, CodeConflict},
		"rule 4: a stale operator identity that names no mismatch": {func(f *Finding) { f.Identity.Mismatch = nil }, CodeConflict},
		"rule 4: a stale passive identity that names no mismatch": {func(f *Finding) {
			f.Identity.Source, f.Identity.Evidence, f.Identity.Mismatch = Passive, []Evidence{{Source: Passive, ID: seen.ID, Stale: true}}, nil
		}, CodeConflict},
		"rule 5: in a 0.1 record": {func(f *Finding) { f.Schema = "otsec.finding/0.1" }, CodeSchema},
		// The operator's entry still never stands as a device read (C6 on #440).
		"the mismatch read cited as the identity's own evidence": {func(f *Finding) {
			f.Identity.Evidence = append(f.Identity.Evidence, Evidence{Source: DeviceRead, ID: f.Identity.Mismatch.ID})
		}, CodeConflict},
	} {
		f := mismatched()
		c.mut(f)
		err := f.Validate()
		if !slices.Contains(Codes(err), c.want) {
			t.Errorf("%s: got %v, want a %s failure", name, err, c.want)
		}
	}
}

// A 0.1 record decodes into this build's type and encodes to its own
// bytes, so its Hash, which a later revision names, is unchanged (D4-61).
func TestA01RecordKeepsItsBytes(t *testing.T) {
	f := confirmed()
	f.Schema = "otsec.finding/0.1"
	b, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), `"mismatch"`) {
		t.Fatalf("a 0.1 record carries the 0.2 field: %s", b)
	}
	var back Finding
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	again, err := json.Marshal(&back)
	if err != nil {
		t.Fatal(err)
	}
	if string(again) != string(b) || back.Validate() != nil {
		t.Errorf("a 0.1 record did not keep its bytes or stopped validating: %s", again)
	}
}

// Every minor begins with its schema, so an older reader recognises the
// record by its prefix and refuses a minor it does not know rather than
// skipping it (D4-61).
func TestEncodingBeginsWithSchema(t *testing.T) {
	for _, f := range []*Finding{confirmed(), mismatched()} {
		b, err := json.Marshal(f)
		if err != nil {
			t.Fatal(err)
		}
		if want := `{"schema":"` + Identifier + `",`; !strings.HasPrefix(string(b), want) {
			t.Errorf("a finding begins %.40q, want %q", b, want)
		}
	}
}
