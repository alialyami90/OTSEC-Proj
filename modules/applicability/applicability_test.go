package applicability

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"otsec.local/otsec/contracts/advisory"
	"otsec.local/otsec/contracts/finding"
)

func row(t *testing.T, g gtFile, id string) gtRow {
	t.Helper()
	for _, r := range g.Identities {
		if r.ID == id {
			return r
		}
	}
	t.Fatalf("no row %s", id)
	return gtRow{}
}

// byEntry indexes findings by advisory, and the stored hash of each.
func byEntry(t *testing.T, fs []finding.Finding) map[string]Previous {
	t.Helper()
	out := map[string]Previous{}
	for _, f := range fs {
		b, err := json.Marshal(f)
		if err != nil {
			t.Fatal(err)
		}
		out[f.Advisory] = Previous{Finding: f, Hash: finding.Hash(b)}
	}
	return out
}

func eval(t *testing.T, in Input, set *advisory.Set, prev map[string]Previous) []finding.Finding {
	t.Helper()
	out, err := Evaluate(in, set, prev)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func find(fs []finding.Finding, id string) *finding.Finding {
	for i := range fs {
		if fs[i].Advisory == id {
			return &fs[i]
		}
	}
	return nil
}

// A reclassification is a new revision naming the one it replaces; an
// evaluation that changes nothing, or only identity.latest_read, records
// nothing (C12, D4-53).
func TestRevisions(t *testing.T) {
	g := loadGT(t)
	set := gtSet(t, g)
	in := gtInput(row(t, g, "D1"))
	first := eval(t, in, set, nil)
	prev := byEntry(t, first)

	if out := eval(t, in, set, prev); len(out) != 0 {
		t.Fatalf("an unchanged evaluation recorded %d findings", len(out))
	}
	again := in
	again.Identity.LatestRead = &finding.Read{ID: "55555555-5555-4555-8555-555555555555", AtUTC: "2026-11-05T11:00:00Z"}
	again.EvaluatedUTC = "2026-11-05T11:01:00Z"
	if out := eval(t, again, set, prev); len(out) != 0 {
		t.Fatalf("a change to latest_read alone recorded %d findings", len(out))
	}

	// A configuration change after the identity read: the three confirmed
	// findings fall, and TEST-ADV-06 gains a stale mark under the same class.
	// Each is revision 2 naming revision 1.
	changed := in
	changed.LatestChange = &finding.Read{ID: snapshotID, AtUTC: afterRead}
	changed.Settings = &Snapshot{ID: snapshotID, AtUTC: afterRead, Settings: map[string]string{"EHTTP": "Y"}}
	out := eval(t, changed, set, prev)
	got := map[string]bool{}
	for _, f := range out {
		got[f.Advisory] = true
		p := prev[f.Advisory]
		if f.Revision != 2 || f.Previous != p.Hash || f.From != p.Finding.Class {
			t.Errorf("%s: revision %d previous %q from %q", f.Advisory, f.Revision, f.Previous, f.From)
		}
		if f.Class != finding.ApplicableByVersion || !f.Identity.Evidence[0].Stale {
			t.Errorf("%s: %s, stale %v", f.Advisory, f.Class, f.Identity.Evidence[0].Stale)
		}
	}
	for _, id := range []string{"TEST-ADV-03", "TEST-ADV-06", "TEST-ADV-07", "TEST-ADV-08"} {
		if !got[id] {
			t.Errorf("%s: no revision recorded", id)
		}
	}
	if len(out) != 4 {
		t.Errorf("%d revisions, want 4", len(out))
	}

	// A newer set is a change to every finding.
	newer := *set
	newer.Version = 2
	if out := eval(t, in, &newer, prev); len(out) != len(set.Entries) {
		t.Errorf("a new set recorded %d of %d findings", len(out), len(set.Entries))
	}
}

// A new stale mark under the same class is a revision too (D4-53).
func TestStaleMarkAloneIsARevision(t *testing.T) {
	g := loadGT(t)
	set := gtSet(t, g)
	in := gtInput(row(t, g, "D3"))
	prev := byEntry(t, eval(t, in, set, nil))
	in.LatestChange = &finding.Read{ID: snapshotID, AtUTC: afterRead}
	f := find(eval(t, in, set, prev), "TEST-ADV-03")
	if f == nil || f.Class != finding.ApplicableByVersion || f.From != finding.ApplicableByVersion || f.Revision != 2 {
		t.Fatalf("got %+v", f)
	}
}

// An identity mismatch adopts nothing and makes the identity stale until a
// later read confirms it again (C1 on #445).
func TestMismatchMakesIdentityStale(t *testing.T) {
	g := loadGT(t)
	set := gtSet(t, g)
	in := gtInput(row(t, g, "D1"))
	in.LatestMismatch = &finding.Read{ID: mismatchID, AtUTC: afterRead}
	f := find(eval(t, in, set, nil), "TEST-ADV-07")
	ev := f.Identity.Evidence
	if f.Class != finding.ApplicableByVersion || len(ev) != 2 || !ev[0].Stale || ev[0].ID != recordID || ev[1].ID != mismatchID {
		t.Fatalf("got %s with %+v", f.Class, ev)
	}
	if f.Identity.Version != row(t, g, "D1").FID {
		t.Errorf("the mismatch changed the identity to %q", f.Identity.Version)
	}
	in.Identity.LatestRead = &finding.Read{ID: readID, AtUTC: "2026-11-05T10:06:00Z"}
	if f := find(eval(t, in, set, nil), "TEST-ADV-07"); f.Class != finding.Confirmed {
		t.Fatalf("after a later confirming read: %s", f.Class)
	}
}

func oneEntry(product string, scheme advisory.Scheme, ranges []advisory.Range, versions []string) *advisory.Set {
	return &advisory.Set{Contract: advisory.Identifier, SetID: "unit", Version: 1, IssuedAt: "2026-11-05T00:00:00Z",
		Purpose: advisory.PurposeTest, Entries: []advisory.Entry{{ID: "TEST-UNIT-01", TestOnly: true,
			Sources:  []advisory.Source{{Kind: advisory.SourceOther, Ref: "unit", Published: "2026-11-05"}},
			Affected: []advisory.Affected{{Vendor: "SEL", Product: product, Scheme: scheme, Ranges: ranges, Versions: versions}}}}}
}

func deviceRead(fid, model, version string) Input {
	return Input{AssetID: assetID, EvaluatedUTC: evaluated, Identity: Identity{Source: finding.DeviceRead,
		Evidence: recordID, FirmwareID: fid, Model: model, FirmwareVersion: version,
		LatestRead: &finding.Read{ID: readID, AtUTC: readAt}}}
}

// A FID the scheme cannot place is never not-applicable while the product is
// named (C2 on #446: the SEL-751 manual's X397 example).
func TestUnplaceableFID(t *testing.T) {
	r400 := []advisory.Range{{Introduced: "R400-V0", Fixed: "R400-V7"}}
	all := []advisory.Range{{}}
	x := "SEL-751-X397-V0-Z007003-D20170305"
	cases := []struct {
		name  string
		in    Input
		set   *advisory.Set
		class finding.Class
	}{
		{"X branch, device-read", deviceRead(x, "SEL-751", "X397-V0"), oneEntry("SEL-751", advisory.SchemeSELFID, r400, nil), finding.ApplicableByVersion},
		{"X branch, model taken from the FID", deviceRead(x, "", ""), oneEntry("SEL-751", advisory.SchemeSELFID, r400, nil), finding.ApplicableByVersion},
		{"X branch, a full FID listed", deviceRead(x, "SEL-751", ""), oneEntry("SEL-751", advisory.SchemeSELFID, nil,
			[]string{"SEL-751-R400-V0-Z100100-D20240930"}), finding.ApplicableByVersion},
		{"X branch, product not named", deviceRead(x, "SEL-751", ""), oneEntry("SEL-751A", advisory.SchemeSELFID, r400, nil), finding.NotApplicable},
		{"X branch, a range with no endpoint", deviceRead(x, "SEL-751", ""), oneEntry("SEL-751", advisory.SchemeSELFID, all, nil), finding.Confirmed},
		{"model disagrees with the FID", deviceRead("SEL-751-R400-V3-Z100100-D20240930", "SEL-751A", ""), oneEntry("SEL-751A", advisory.SchemeSELFID, r400, nil), finding.ApplicableByVersion},
		{"version disagrees with the FID", deviceRead("SEL-751-R400-V3-Z100100-D20240930", "SEL-751", "R400-V9"), oneEntry("SEL-751", advisory.SchemeSELFID, r400, nil), finding.ApplicableByVersion},
		{"V too large to compare", deviceRead("SEL-751-R400-V99999999999999999999-Z100100-D20240930", "", ""), oneEntry("SEL-751", advisory.SchemeSELFID, r400, nil), finding.ApplicableByVersion},
		{"a form not read", deviceRead("SEL-2731M R102-V1", "SEL-2731M", "R102-V1"), oneEntry("SEL-2731M", advisory.SchemeSELFID, r400, nil), finding.ApplicableByVersion},
		{"placeable and outside, for contrast", deviceRead("SEL-751-R400-V7-Z100100-D20250731", "SEL-751", "R400-V7"), oneEntry("SEL-751", advisory.SchemeSELFID, r400, nil), finding.NotApplicable},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := eval(t, c.in, c.set, nil)[0]
			if f.Class != c.class {
				t.Fatalf("got %s %s, want %s", f.Class, f.Reason, c.class)
			}
			if f.Class == finding.ApplicableByVersion && (len(f.Preconditions) != 1 || f.Preconditions[0].Name != advisory.ReservedFirmwareVersion) {
				t.Errorf("firmware-version is not named unread: %+v", f.Preconditions)
			}
		})
	}
}

// Under exact, the whole firmware_id is compared and an empty range covers
// every version, whatever the FID's form.
func TestExactScheme(t *testing.T) {
	in := deviceRead("vendor-build-7", "SEL-3555", "")
	for _, c := range []struct {
		set   *advisory.Set
		class finding.Class
	}{
		{oneEntry("SEL-3555", advisory.SchemeExact, nil, []string{"vendor-build-7"}), finding.Confirmed},
		{oneEntry("SEL-3555", advisory.SchemeExact, nil, []string{"vendor-build-8"}), finding.NotApplicable},
		{oneEntry("SEL-3555", advisory.SchemeExact, []advisory.Range{{}}, nil), finding.Confirmed},
	} {
		if f := eval(t, in, c.set, nil)[0]; f.Class != c.class {
			t.Errorf("%v: got %s, want %s", c.set.Entries[0].Affected[0], f.Class, c.class)
		}
	}
}

func TestInputRefused(t *testing.T) {
	set := oneEntry("SEL-751", advisory.SchemeSELFID, []advisory.Range{{}}, nil)
	noProduct := deviceRead("not a FID", "", "")
	badTime := deviceRead("SEL-751-R400-V3-Z100100-D20240930", "", "")
	badTime.Identity.LatestRead.AtUTC = "yesterday"
	badID := deviceRead("SEL-751-R400-V3-Z100100-D20240930", "", "")
	badID.Identity.Evidence = "audit:node-a:1" // an operator's entry standing as a device read
	invalidSet := *set
	invalidSet.Version = 0
	for name, c := range map[string]struct {
		in  Input
		set *advisory.Set
	}{
		"no product": {noProduct, set}, "bad time": {badTime, set}, "evidence form": {badID, set},
		"invalid set": {deviceRead("SEL-751-R400-V3-Z100100-D20240930", "", ""), &invalidSet},
	} {
		if _, err := Evaluate(c.in, c.set, nil); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// The package's own code imports only what a pure function needs: no
// network, file, process or clock (V-M8, note §1). The contracts it imports
// parse addresses but open nothing.
func TestImportsArePure(t *testing.T) {
	allowed := map[string]bool{"errors": true, "fmt": true, "reflect": true, "regexp": true, "slices": true,
		"strconv": true, "time": true,
		"otsec.local/otsec/contracts/advisory": true, "otsec.local/otsec/contracts/finding": true}
	files, _ := filepath.Glob("*.go")
	fset := token.NewFileSet()
	seen := 0
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		seen++
		for _, imp := range f.Imports {
			p, _ := strconv.Unquote(imp.Path.Value)
			if !allowed[p] {
				t.Errorf("%s imports %s", name, p)
			}
		}
		// time is used to parse the given times, never to read a clock.
		ast.Inspect(f, func(n ast.Node) bool {
			if s, ok := n.(*ast.SelectorExpr); ok {
				if x, ok := s.X.(*ast.Ident); ok && x.Name == "time" && s.Sel.Name != "Parse" && s.Sel.Name != "RFC3339Nano" && s.Sel.Name != "Time" {
					t.Errorf("%s uses time.%s", name, s.Sel.Name)
				}
			}
			return true
		})
	}
	if seen == 0 {
		t.Fatal("no source files read")
	}
}

// FuzzFID: whatever FID a device reports, the matcher returns a valid
// finding or refuses the input, and a FID it cannot place on an R branch is
// never not-applicable while the product is named.
func FuzzFID(f *testing.F) {
	for _, s := range []string{"SEL-751-R400-V3-Z100100-D20240930", "SEL-751-X397-V0-Z007003-D20170305",
		"SEL-751-R400-V7-Z100100-D20250731", "SEL-751-R400-V99999999999999999999-Z100100-D20240930", "SEL-751", ""} {
		f.Add(s)
	}
	set := oneEntry("SEL-751", advisory.SchemeSELFID, []advisory.Range{{Introduced: "R400-V0", Fixed: "R400-V7"}}, nil)
	f.Fuzz(func(t *testing.T, s string) {
		in := deviceRead(s, "", "")
		out, err := Evaluate(in, set, nil)
		if err != nil {
			if fidRe.MatchString(s) {
				t.Fatalf("%q: %v", s, err)
			}
			return
		}
		fd := out[0]
		if fd.Reason == finding.OutsideRange {
			m := fidRe.FindStringSubmatch(s)
			if m == nil || m[3] != "R" {
				t.Fatalf("%q: an unplaceable FID came out not-applicable", s)
			}
		}
	})
}

// Under a mismatch, an entry naming the model the mismatch read reported is
// not product-not-named; one naming neither model is, and so is every entry
// when the mismatch FID does not parse (C1 on #451).
func TestMismatchModel(t *testing.T) {
	r400 := []advisory.Range{{Introduced: "R400-V0", Fixed: "R400-V7"}}
	for _, c := range []struct {
		fid, product string
		class        finding.Class
	}{
		{"SEL-751A-R100-V1-Z000000-D20250101", "SEL-751A", finding.ApplicableByVersion},
		{"SEL-751A-R100-V1-Z000000-D20250101", "SEL-2730M", finding.NotApplicable},
		{"not a FID", "SEL-751A", finding.NotApplicable},
	} {
		in := deviceRead("SEL-751-R400-V3-Z100100-D20240930", "SEL-751", "R400-V3")
		in.LatestMismatch = &finding.Read{ID: mismatchID, AtUTC: afterRead}
		in.MismatchFID = c.fid
		f := eval(t, in, oneEntry(c.product, advisory.SchemeSELFID, r400, nil), nil)[0]
		if f.Class != c.class || f.Identity.Product != "SEL-751" {
			t.Errorf("%s against %s: %s %s, product %s", c.fid, c.product, f.Class, f.Reason, f.Identity.Product)
		}
		if f.Class == finding.ApplicableByVersion && (!f.Identity.Evidence[0].Stale || f.Identity.Evidence[1].ID != mismatchID) {
			t.Errorf("%s: evidence %+v", c.fid, f.Identity.Evidence)
		}
	}
	// With the mismatch older than the latest read, its model counts for
	// nothing.
	in := deviceRead("SEL-751-R400-V3-Z100100-D20240930", "SEL-751", "R400-V3")
	in.LatestMismatch = &finding.Read{ID: mismatchID, AtUTC: beforeRead}
	in.MismatchFID = "SEL-751A-R100-V1-Z000000-D20250101"
	if f := eval(t, in, oneEntry("SEL-751A", advisory.SchemeSELFID, r400, nil), nil)[0]; f.Reason != finding.ProductNotNamed {
		t.Errorf("an old mismatch: %s %s", f.Class, f.Reason)
	}
}
