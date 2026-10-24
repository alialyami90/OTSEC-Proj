package register

import (
	"os"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

// content is A2's SEL-751 register content, built by
// testdata/build_sel751.py from the Phase 0 package and S22 Appendix A.
const content = "testdata/sel-751.json"

func loadContent(t *testing.T) *Package {
	t.Helper()
	data, err := os.ReadFile(content)
	if err != nil {
		t.Fatal(err)
	}
	p, err := Decode(data)
	if err != nil {
		t.Fatalf("content package invalid: %v", err)
	}
	return p
}

// TestContentFirmwareRows: firmware.known is the FID rows of S22 Tables A.1
// to A.5 and nothing else. The per-branch counts were taken from the manual
// independently of the build script, and agree with A6's count of 78.
func TestContentFirmwareRows(t *testing.T) {
	p := loadContent(t)
	want := map[string]int{
		"R501": 1, "R500": 2, "R402": 5, "R401": 8, "R400": 10,
		"R302": 10, "R301": 6, "R300": 10,
		"R202": 6, "R201": 2, "R200": 3, // R200 has 4 rows; two share one FID
		"R113": 3, "R112": 4, "R110": 1, "R109": 1, "R108": 1, "R106": 1,
		"R105": 1, "R103": 1, "R102": 1, "R101": 1,
	}
	got := map[string]int{}
	seen := map[string]bool{}
	ref := regexp.MustCompile(`^Table A\.[1-5] sheet [0-9]+ p\. A\.[0-9]+$`)
	tables := map[string]string{"R5": "A.1", "R4": "A.2", "R3": "A.3", "R2": "A.4", "R1": "A.5"}
	for _, k := range p.Firmware.Known {
		if seen[k.FID] {
			t.Errorf("%s listed twice", k.FID)
		}
		seen[k.FID] = true
		got[k.Branch]++
		if k.Citation.Source != "S22" {
			t.Errorf("%s cites %s, want S22", k.FID, k.Citation.Source)
		}
		if k.FID == "SEL-751-R200-V4-Z007003-D20170922" {
			if !strings.Contains(k.Citation.Ref, "sheets 3 and 4") {
				t.Errorf("%s: citation %q does not name both rows", k.FID, k.Citation.Ref)
			}
			continue
		}
		if !ref.MatchString(k.Citation.Ref) {
			t.Errorf("%s: citation %q is not a table, sheet and page", k.FID, k.Citation.Ref)
		}
		if tb := tables[k.Branch[:2]]; !strings.HasPrefix(k.Citation.Ref, "Table "+tb+" ") {
			t.Errorf("%s: cited %q, but branch %s is in Table %s", k.FID, k.Citation.Ref, k.Branch, tb)
		}
	}
	if len(p.Firmware.Known) != 78 {
		t.Errorf("%d known FIDs, want 78", len(p.Firmware.Known))
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("FIDs per branch:\n got %v\nwant %v", got, want)
	}
	for _, b := range p.Firmware.Branches {
		if b.Branch == "R100" {
			t.Error("R100 branch rule kept, but no Appendix A row has an R100 FID")
		}
	}
}

// TestContentDecidesLikePhase0: revision 2 changes citations and the known
// list, not decisions. Every FID known to both packages gets the same
// decision, and the two dropped FIDs are the R100-V0 strings that are not
// rows.
func TestContentDecidesLikePhase0(t *testing.T) {
	old, p := load(t), loadContent(t)
	if p.Revision <= old.Revision {
		t.Errorf("revision %d does not supersede %d", p.Revision, old.Revision)
	}
	known := map[string]bool{}
	for _, k := range p.Firmware.Known {
		known[k.FID] = true
	}
	var dropped []string
	for _, k := range old.Firmware.Known {
		if !known[k.FID] {
			dropped = append(dropped, k.FID)
			if k.Branch != "R100" {
				t.Errorf("dropped %s, which is not an R100 string", k.FID)
			}
			if _, err := p.Firmware.Decide(k.FID); err == nil {
				t.Errorf("dropped %s still allowed", k.FID)
			}
			continue
		}
		a, errA := old.Firmware.Decide(k.FID)
		b, errB := p.Firmware.Decide(k.FID)
		if (errA == nil) != (errB == nil) || (errA == nil && !reflect.DeepEqual(a, b)) {
			t.Errorf("%s: phase 0 decides %v %v, content decides %v %v", k.FID, a, errA, b, errB)
		}
	}
	if len(dropped) != 2 {
		t.Errorf("dropped %v, want the two R100-V0 strings", dropped)
	}
	inOld := map[string]bool{}
	for _, o := range old.Firmware.Known {
		inOld[o.FID] = true
	}
	for _, k := range p.Firmware.Known {
		if !inOld[k.FID] {
			t.Errorf("%s is new; the Phase 0 extraction should have had every row", k.FID)
		}
	}
}

// TestContentAllowlistUnchanged: the lines the collector may send, and the
// lines it refuses, are the Phase 0 ones. Only citations, evidence and the
// classification of the deny-by-default SER rule change.
func TestContentAllowlistUnchanged(t *testing.T) {
	old, p := load(t), loadContent(t)
	strip := func(o Operation) Operation { o.Citations, o.Notes = nil, ""; return o }
	if len(old.Operations) != len(p.Operations) {
		t.Fatalf("%d operations, want %d", len(p.Operations), len(old.Operations))
	}
	for i := range old.Operations {
		if !reflect.DeepEqual(strip(old.Operations[i]), strip(p.Operations[i])) {
			t.Errorf("operation %s changed", old.Operations[i].ID)
		}
	}
	if !reflect.DeepEqual(old.SessionControl, p.SessionControl) {
		t.Error("session_control changed")
	}
	if !reflect.DeepEqual(old.Preconditions, p.Preconditions) || !reflect.DeepEqual(old.Warnings, p.Warnings) {
		t.Error("preconditions or warnings changed")
	}
	if len(old.Denied) != len(p.Denied) {
		t.Fatalf("%d deny rules, want %d", len(p.Denied), len(old.Denied))
	}
	for i, d := range p.Denied {
		o := old.Denied[i]
		if d.ID != o.ID || d.Pattern != o.Pattern || d.AccessLevel != o.AccessLevel {
			t.Errorf("deny rule %s changed", o.ID)
		}
		if d.ID == "sel.ser.other_args" {
			if d.Classification != Unknown || d.Evidence.Class != DocumentedUntested {
				t.Errorf("sel.ser.other_args: %s, %s", d.Classification, d.Evidence.Class)
			}
			if d.Citations[0].Source != "S22" {
				t.Errorf("sel.ser.other_args cites %s", d.Citations[0].Source)
			}
		} else if d.Classification != o.Classification {
			t.Errorf("deny rule %s reclassified", d.ID)
		}
	}
	for _, s := range p.Sources {
		if s.ID == "A2-P0" {
			t.Error("A2-P0 is cited by nothing and should be gone")
		}
	}
	m, err := NewMatcher(p)
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range corpus(t, "sel-deny-corpus.txt") {
		if v, id := m.Match(l); v == VerdictOperation || v == VerdictSessionControl {
			t.Errorf("deny corpus %q classified %s (%s)", l, v, id)
		}
	}
	for _, l := range corpus(t, "allow-corpus.txt") {
		if v, _ := m.Match(l); v != VerdictOperation && v != VerdictSessionControl {
			t.Errorf("allow corpus %q classified %s", l, v)
		}
	}
}
