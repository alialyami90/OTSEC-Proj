package register

import (
	"os"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// content is A2's SEL-751 register content, built by
// testdata/build_sel751.py from the Phase 0 package and S22 Appendix A.
const content = "testdata/sel-751.json"

// contentRev4 is revision 4 as it was signed, pinned: the last package in
// format 0.2, and the one the C2 goldens and the SER tests are written for.
const contentRev4 = "testdata/sel-751-rev4.json"

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

// TestContentAllowlistUnchanged: the lines the collector may send are the
// Phase 0 ones plus revision 5's SHO forms (TestContentRev5), and every other
// line Phase 0 refuses is still refused. Deny rules only grow
// (TestContentDenyRulesOnlyGrow).
func TestContentAllowlistUnchanged(t *testing.T) {
	old, p := load(t), loadContent(t)
	strip := func(o Operation) Operation { o.Citations, o.Notes, o.Limits = nil, "", nil; return o }
	if len(p.Operations) < len(old.Operations) {
		t.Fatalf("%d operations, want at least %d", len(p.Operations), len(old.Operations))
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
	for _, d := range p.Denied {
		if d.ID == "sel.ser.other_args" {
			if d.Classification != Unknown || d.Evidence.Class != DocumentedUntested {
				t.Errorf("sel.ser.other_args: %s, %s", d.Classification, d.Evidence.Class)
			}
			if d.Citations[0].Source != "S22" {
				t.Errorf("sel.ser.other_args cites %s", d.Citations[0].Source)
			}
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

// rev2 is revision 2 as signed, pinned for the rollback floor and for these
// comparisons.
func loadRev2(t *testing.T) *Package {
	t.Helper()
	data, err := os.ReadFile("testdata/sel-751-rev2.json")
	if err != nil {
		t.Fatal(err)
	}
	p, err := Decode(data)
	if err != nil || p.Revision != 2 {
		t.Fatalf("revision 2: %v", err)
	}
	return p
}

// rev3 is revision 3, the last otsec.register/0.1 package, written by
// build_sel751.py on the way to revision 4.
func loadRev3(t *testing.T) *Package {
	t.Helper()
	data, err := os.ReadFile("testdata/sel-751-rev3.json")
	if err != nil {
		t.Fatal(err)
	}
	p, err := Decode(data)
	if err != nil || p.Revision != 3 || p.Contract != "otsec.register/0.1" {
		t.Fatalf("revision 3: %v", err)
	}
	return p
}

func loadRev4(t *testing.T) *Package {
	t.Helper()
	data, err := os.ReadFile(contentRev4)
	if err != nil {
		t.Fatal(err)
	}
	p, err := Decode(data)
	if err != nil {
		t.Fatalf("revision 4: %v", err)
	}
	return p
}

// TestContentRev4: revision 4 is revision 3 in format 0.2 plus the DATE_F
// context read for SER (D3-2) and SHO G's corrected DATE_F citation (S22
// Table 4.84, not Table 4.90). Every line, deny rule, condition and firmware
// entry is unchanged, so the deny corpus result cannot move.
func TestContentRev4(t *testing.T) {
	old, p := loadRev3(t), loadRev4(t)
	if p.Revision != 4 || p.Contract != "otsec.register/0.2" || p.Issued != "2026-10-26" {
		t.Fatalf("revision %d, %s, issued %s", p.Revision, p.Contract, p.Issued)
	}
	want := []ContextRead{{ID: "ctx.date_f", Setting: "DATE_F", ReadBy: "sel.settings.show_global",
		For: []string{"sel.ser.read_all"}, Values: []string{"MDY", "YMD", "DMY"}}}
	got := slices.Clone(p.Context)
	for i := range got {
		if got[i].Reason == "" {
			t.Errorf("%s has no reason", got[i].ID)
		}
		got[i].Reason = ""
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("context %+v, want %+v", got, want)
	}
	cites := map[string][]string{}
	for _, o := range p.Operations {
		for _, c := range o.Citations {
			cites[o.ID] = append(cites[o.ID], c.Ref)
		}
	}
	g := cites["sel.settings.show_global"]
	if len(g) != 3 || g[1] != "Table 4.90 p.4.230 (UTC_OFF, DST_BEGM..DST_ENDH)" || !strings.HasPrefix(g[2], "Table 4.84 p.4.225 (DATE_F") {
		t.Errorf("SHO G citations %q", g)
	}
	// Everything else is revision 3 as it was.
	q := *p
	q.Contract, q.Revision, q.Issued, q.Context, q.Notes = old.Contract, old.Revision, old.Issued, nil, p.Notes[1:]
	q.Operations = slices.Clone(p.Operations)
	for i := range q.Operations {
		if q.Operations[i].ID == "sel.settings.show_global" {
			q.Operations[i].Citations = old.Operations[i].Citations
		}
	}
	if !reflect.DeepEqual(&q, old) {
		t.Error("revision 4 changes more than its contract, revision, date, context, notes and SHO G's citation")
	}
	if !strings.HasPrefix(p.Notes[0], "Revision 4 by A2") {
		t.Errorf("first note %q", p.Notes[0])
	}
}

// TestContentDenyRulesOnlyGrow: revision 3 keeps every revision 2 deny rule,
// in the same order, with its classification, access level and citations.
// Only the listed rules gain Spanish forms, and only the listed rules are new.
func TestContentDenyRulesOnlyGrow(t *testing.T) {
	old, p := loadRev2(t), loadRev3(t)
	if p.Revision != 3 {
		t.Fatalf("revision %d, want 3", p.Revision)
	}
	extended := map[string]bool{
		"sel.disconnect": true, "sel.breaker.ope": true, "sel.settings.set": true, "sel.clock.set": true,
		"sel.tar.reset": true, "sel.sta.args": true, "sel.breaker.data": true, "sel.his.clear": true,
		"sel.ldp.clear": true, "sel.ser.clear": true,
	}
	added := map[string]bool{
		"sel.breaker.clo.es": true, "sel.settings.group.es": true, "sel.met.reset.es": true,
		"sel.unapproved.command": true,
	}
	byID := map[string]DenyRule{}
	var order []string
	for _, d := range p.Denied {
		byID[d.ID] = d
		if !added[d.ID] {
			order = append(order, d.ID)
		}
		if added[d.ID] && d.Evidence.Class != DocumentedUntested {
			t.Errorf("%s: evidence %s, want documented-untested", d.ID, d.Evidence.Class)
		}
	}
	if len(p.Denied) != len(old.Denied)+len(added) {
		t.Errorf("%d deny rules, want %d", len(p.Denied), len(old.Denied)+len(added))
	}
	if p.Denied[len(p.Denied)-1].ID != "sel.unapproved.command" {
		t.Error("sel.unapproved.command is not last, so a state-changing form could report it")
	}
	for i, o := range old.Denied {
		d, ok := byID[o.ID]
		if !ok || order[i] != o.ID {
			t.Errorf("deny rule %s is gone or moved", o.ID)
			continue
		}
		if d.Classification != o.Classification || d.AccessLevel != o.AccessLevel || d.SideEffects != o.SideEffects ||
			d.Evidence != o.Evidence {
			t.Errorf("deny rule %s reclassified", o.ID)
		}
		if !reflect.DeepEqual(d.Citations[:len(o.Citations)], o.Citations) {
			t.Errorf("deny rule %s lost a citation", o.ID)
		}
		if (d.Pattern != o.Pattern) != extended[o.ID] {
			t.Errorf("deny rule %s: pattern %q, was %q", o.ID, d.Pattern, o.Pattern)
		}
	}
	for id := range added {
		if _, ok := byID[id]; !ok {
			t.Errorf("deny rule %s missing", id)
		}
	}
	// Every line revision 2 refuses, revision 3 refuses.
	m2, _ := NewMatcher(old)
	m3, err := NewMatcher(p)
	if err != nil {
		t.Fatal(err)
	}
	lines := corpus(t, "sel-deny-corpus.txt")
	for _, w := range commandForms {
		lines = append(lines, w.form)
	}
	for _, l := range lines {
		v2, _ := m2.Match(l)
		v3, id := m3.Match(l)
		if v2 == VerdictDenied && v3 != VerdictDenied {
			t.Errorf("%q: revision 2 denies it, revision 3 gives %s %s", l, v3, id)
		}
	}
}

// formKind says what the register must make of a documented form.
type formKind int

const (
	approved formKind = iota // an approved line: operation or session line
	changes                  // changes state: denied by a state-changing rule
	other                    // any other form: denied, or for a word with an approved line, at least not permitted
)

// commandForms is every documented form of S22 that the tests check: the
// Relay Command Summary (pages 1 to 9 at the end of the manual, English and
// Spanish columns) and Table C.2 (Compressed ASCII). Placeholders in the
// manual (n, m, k, date, filename) are filled with sample values. A form is
// listed once even where English and Spanish print it alike.
var commandForms = []struct {
	form, lang, page string
	kind             formKind
}{
	// Access Level 0.
	{"ACC", "en es", "1", approved}, {"ID", "en es", "1", approved}, {"QUI", "en", "1", approved},
	{"QUIT", "en", "1", other}, {"SAL", "es", "1", other},
	// Access Level 1.
	{"2AC", "en es", "1", changes},
	{"BRE", "en", "1", other}, {"INT", "es", "1", other},
	{"CEV", "en es", "1", other}, {"CEV 1", "en es", "1", other}, {"CEV 1 R", "en es", "1", other},
	{"CEV HIF 1", "en es", "1", other},
	{"COM A", "en es", "1", other}, {"COM B", "en es", "1", other},
	{"COM C", "en es", "2", changes}, {"COM C A", "en es", "2", changes}, {"COM C B", "en es", "2", changes},
	{"COM L A", "en es", "2", other}, {"COM PTP", "en es", "2", other},
	{"COM PTP C", "en es", "2", changes}, {"COM PTP R", "en es", "2", changes},
	{"COM S A", "en es", "2", other}, {"COM S B", "en es", "2", other},
	{"COU", "en es", "2", other}, {"COU 5", "en es", "2", other},
	{"DATE", "en", "2", other}, {"DATE 10/25/2026", "en", "2", changes},
	{"FEC", "es", "2", other}, {"FEC 25/10/2026", "es", "2", changes},
	{"ETH", "en es", "2", other},
	{"EVE", "en es", "2", other}, {"EVE 1", "en es", "2", other}, {"EVE 1 R", "en es", "2", other},
	{"FIL DIR", "en es", "2", changes}, {"FIL READ SET_1.TXT", "en es", "2", changes},
	{"FIL SHOW SET_1.TXT", "en es", "3", changes},
	{"FGS", "en es", "3", other}, {"FGS 1", "en es", "3", other}, {"FGS S", "en es", "3", other},
	{"FGS S 1 L", "en es", "3", other}, {"FGS S 1 C", "en es", "3", changes}, {"FGS S ALL C", "en es", "3", changes},
	{"GOOSE", "en es", "3", other}, {"GOOSE S ALL L", "en es", "3", other},
	{"GOOSE S 1 C", "en es", "3", changes}, {"GOOSE S ALL C", "en es", "3", changes},
	{"GROUP", "en", "3", other}, {"GRUPO", "es", "3", other},
	{"HELP", "en", "3", other}, {"AYUDA", "es", "3", other},
	{"HIS", "en es", "4", other}, {"HIS 5", "en es", "4", other}, {"HIS 50INC", "en es", "4", other},
	{"HIS C", "en", "4", changes}, {"HIS R", "en es", "4", changes}, {"HIS D", "es", "4", changes},
	{"HIS HIF 1", "en es", "4", other}, {"HIS HIF C", "en", "4", changes}, {"HIS HIF R", "en es", "4", changes},
	{"HIS HIF D", "es", "4", changes}, {"HIS HIF CA", "en", "4", changes}, {"HIS HIF RA", "en", "4", changes},
	{"HIS HIF DT", "es", "4", changes}, {"HIS HIF RT", "es", "4", changes},
	{"HIS IGF", "en es", "4", other}, {"HIS IGF C", "en es", "4", changes},
	{"HSG", "en es", "4", other}, {"HSR", "en es", "4", other}, {"IRIG", "en es", "4", changes},
	{"LDP", "en es", "4", other}, {"LDP 1 10", "en es", "4", other},
	{"LDP C", "en", "4", changes}, {"LDP D", "es", "4", changes},
	{"LOG HIF 1", "en es", "4", other}, {"MAC", "en es", "4", other},
	{"MET", "en", "4", other}, {"MET F", "en", "4", other}, {"MET 5", "en", "4", other}, {"MET AI", "en", "4", other},
	{"MED", "es", "4", other}, {"MED EA", "es", "4", other},
	{"MET DE", "en", "5", other}, {"MET T", "en", "5", other}, {"MED A", "es", "5", other}, {"MED V", "es", "5", other},
	{"MET RD", "en", "5", changes}, {"MET RE", "en", "5", changes}, {"MET RM", "en", "5", changes},
	{"MET RP", "en", "5", changes},
	{"MED RD", "es", "5", changes}, {"MED RE", "es", "5", changes}, {"MED RM", "es", "5", changes},
	{"MED RP", "es", "5", changes},
	{"PING 192.0.2.1 5", "en es", "5", changes},
	{"PRP", "en es", "5", other}, {"RSTP", "en es", "5", other},
	{"SER", "en es", "5", approved}, {"SER 10/01/2026", "en es", "5", other},
	{"SER 10/01/2026 10/25/2026", "en es", "6", other}, {"SER 5", "en es", "6", other},
	{"SER 1 10", "en es", "6", other},
	{"SER C", "en", "6", changes}, {"SER R", "en es", "6", changes}, {"SER D", "en es", "6", changes},
	{"SER B", "es", "6", other},
	// Revision 5 approves the 24 forms of Table 7.67 without a setting name.
	{"SHO 1", "en", "6", approved}, {"SHO 4", "en", "6", approved}, {"SHO G", "en", "6", approved},
	{"SHO L 1", "en", "6", approved}, {"SHO L 4", "en", "6", approved},
	{"SHO P 1", "en", "6", approved}, {"SHO P 2", "en", "6", approved}, {"SHO P F", "en", "6", approved},
	{"SHO R", "en", "6", approved}, {"SHO F", "en", "6", approved}, {"SHO M", "en", "6", approved},
	{"SHO I", "en", "6", approved}, {"SHO E 3", "en", "6", approved}, {"SHO DNP 3", "en", "6", approved},
	// The "s" argument names a setting to jump to; a bare SHO P shows the
	// active port; neither is approved.
	{"SHO 1 CTR", "en", "6", other}, {"SHO L 1 SV1", "en", "6", other}, {"SHO G DATE_F", "en", "6", other},
	{"SHO P", "en", "6", other}, {"SHO P 1 LANG", "en", "6", other}, {"SHO R SER1", "en", "6", other},
	{"SHO", "en", "6", other}, {"SHO 5", "en", "6", other}, {"SHO P 5", "en", "6", other},
	{"SHO E 4", "en", "6", other}, {"SHO DNP 4", "en", "6", other}, {"SHO E", "en", "6", other},
	{"MOS 1", "es", "6", other}, {"MOS G", "es", "6", other}, {"MOS P 1", "es", "6", other},
	{"STA", "en", "6", other}, {"STA S", "en", "6", changes}, {"EST", "es", "6", other}, {"EST S", "es", "6", changes},
	{"SUM", "en es", "6", other}, {"SUM 1", "en es", "6", other}, {"SUM HIF 1", "en es", "6", other},
	{"SUM C", "en es", "6", changes}, {"SUM R", "en es", "6", changes},
	{"TAR", "en", "6", other}, {"TAR 1", "en", "6", other}, {"BAN", "es", "6", other}, {"BAN 1", "es", "6", other},
	{"TAR R", "en", "7", changes}, {"BAN R", "es", "7", changes},
	{"TIME", "en", "7", other}, {"TIME 12:00:00", "en", "7", changes},
	{"HORA", "es", "7", other}, {"HORA 12:00:00", "es", "7", changes},
	{"TRI", "en es", "7", changes}, {"TRI HIF", "en es", "7", changes},
	// Access Level 2.
	{"89C 1", "en es", "7", changes}, {"89C 1 2", "en es", "7", changes},
	{"89O 1", "en", "7", changes}, {"89O 1 2", "en", "7", changes},
	{"89A 1", "es", "7", changes}, {"89A 1 2", "es", "7", changes},
	{"AFT", "en es", "7", changes}, {"ANA 1 50 10", "en es", "7", changes},
	{"BRE R", "en", "7", changes}, {"BRE W", "en", "7", changes},
	{"INT R", "es", "7", changes}, {"INT W", "es", "7", changes},
	{"CAL", "en es", "7", changes}, {"CLO", "en", "7", changes}, {"CER", "es", "7", changes},
	{"CON RB01 1", "en es", "7", changes},
	{"COPY 1 2", "en es", "8", changes}, {"FIL WRITE SET_1.TXT", "en es", "8", changes},
	{"GROUP 2", "en", "8", changes}, {"GRUPO 2", "es", "8", changes},
	{"HSR C", "en es", "8", changes}, {"INI HIF", "en es", "8", changes}, {"L_D", "en es", "8", changes},
	{"LOO", "en es", "8", changes}, {"LOO A", "en es", "8", changes}, {"LOO R", "en es", "8", changes},
	{"OPE", "en", "8", changes}, {"ABR", "es", "8", changes},
	{"PARTNO", "en es", "8", changes}, {"PAS 1", "en es", "8", changes}, {"PAS 2", "en es", "8", changes},
	{"PUL OUT101", "en es", "8", changes}, {"PUL OUT101 5", "en es", "8", changes}, {"R_S", "en es", "8", changes},
	{"SET 1", "en", "8", changes}, {"SET P 1", "en", "9", changes}, {"SET G TERSE", "en", "9", changes},
	{"AJU 1", "es", "8", changes}, {"AJU P 1", "es", "9", changes}, {"AJU G TERSO", "es", "9", changes},
	{"STA C", "en", "9", changes}, {"STA R", "en", "9", changes}, {"EST C", "es", "9", changes},
	{"EST R", "es", "9", changes},
	{"TEST DB A 1", "en es", "9", changes}, {"THE P", "en es", "9", changes}, {"THE R", "en es", "9", changes},
	{"VEC D", "en es", "9", other}, {"VEC E", "en es", "9", other},
	// Access Level C.
	{"PAS C", "en es", "9", changes},
	// Compressed ASCII (Table C.2).
	{"BNAME", "en", "C.2", other}, {"CASCII", "en", "C.2", changes}, {"CBRE", "en", "C.2", other},
	{"CEVENT", "en", "C.2", other}, {"CHISTORY", "en", "C.2", other}, {"CLDP", "en", "C.2", other},
	{"CMETER", "en", "C.2", other}, {"CSE", "en", "C.2", changes}, {"CSTATUS", "en", "C.2", other},
	{"CSUMMARY", "en", "C.2", other}, {"DNAME", "en", "C.2", other}, {"SNS", "en", "C.2", other},
}

// TestContentCommandForms: no documented form is permitted except the
// approved lines; every form that changes state, English or Spanish, is
// denied by a state-changing rule; and every other form is denied, except
// the other forms of a word that has an approved line, which stay unlisted.
// Lower-case forms decide the same way, since the relay accepts both.
func TestContentCommandForms(t *testing.T) {
	p := loadContent(t)
	m, err := NewMatcher(p)
	if err != nil {
		t.Fatal(err)
	}
	class := map[string]Classification{}
	for _, d := range p.Denied {
		class[d.ID] = d.Classification
	}
	hasApproved := map[string]bool{"ACC": true, "ID": true, "QUI": true, "SHO": true, "SER": true}
	for _, w := range commandForms {
		v, id := m.Match(w.form)
		switch w.kind {
		case approved:
			if v != VerdictOperation && v != VerdictSessionControl {
				t.Errorf("%s (p.%s): %s %s, want an approved line", w.form, w.page, v, id)
			}
			continue
		case changes:
			if v != VerdictDenied || class[id] != StateChanging {
				t.Errorf("%s (%s p.%s): %s %s, want a state-changing deny rule", w.form, w.lang, w.page, v, id)
			}
		case other:
			word := strings.Fields(w.form)[0]
			if len(word) > 3 {
				word = word[:3]
			}
			if v != VerdictDenied && !(hasApproved[word] && v == VerdictUnlisted) {
				t.Errorf("%s (%s p.%s): %s %s, want denied", w.form, w.lang, w.page, v, id)
			}
		}
		if lv, lid := m.Match(strings.ToLower(w.form)); lv != v || lid != id {
			t.Errorf("%s in lower case: %s %s, upper case %s %s", w.form, lv, lid, v, id)
		}
	}
}

// TestContentApprovedLinesPermitted: every line the SEL-751 dialogue sends is
// still permitted in its phase and matches no deny rule: the wake (an empty
// line), the QUI probe, ID before ACC, ACC, the operate reads and QUI at the
// close (docs/phase2/A2-sel751.md).
func TestContentApprovedLinesPermitted(t *testing.T) {
	p := loadContent(t)
	m, err := NewMatcher(p)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		ph   Phase
		line string
	}{
		{PhaseProbe, "QUI"}, {PhaseProbe, "ID"}, {PhaseAuth, "ACC"},
		{PhaseOperate, "ID"}, {PhaseOperate, "SHO P 1"}, {PhaseOperate, "SHO G"}, {PhaseOperate, "SER"},
		{PhaseOperate, "SHO 1"}, {PhaseOperate, "SHO L 4"}, {PhaseOperate, "SHO DNP 3"},
		{PhaseClose, "QUI"},
	} {
		if _, id, err := m.Permit(c.ph, c.line); err != nil {
			t.Errorf("%s in %s: %v (%s)", c.line, c.ph, err, id)
		}
		if id := m.denied(c.line); id != "" {
			t.Errorf("%s matches deny rule %s", c.line, id)
		}
	}
	// The wake is not a register line (telnet.Conn.SendWake sends it), but
	// no rule may deny it either.
	if id := m.denied(""); id != "" {
		t.Errorf("the empty wake line matches deny rule %s", id)
	}
}

// rev5Limits is revision 5's counted reply bound for each form
// (docs/phase4/B2-register-rev5.md, count_settings.py): the settings of the
// class on S22's settings sheets at 22 + 64 bytes each, 22 + 384 for an
// equation, and 4,096 for headings, rounded up to a KiB. The numbers are
// bounds on assumptions (documented-untested), not measurements.
var rev5Limits = []struct {
	line  string
	bound int64
}{
	{"SHO P 1", 24576}, {"SHO G", 101376},
	{"SHO 1", 103424}, {"SHO 2", 103424}, {"SHO 3", 103424}, {"SHO 4", 103424},
	{"SHO L 1", 355328}, {"SHO L 2", 355328}, {"SHO L 3", 355328}, {"SHO L 4", 355328},
	{"SHO P F", 7168}, {"SHO P 2", 9216}, {"SHO P 3", 9216}, {"SHO P 4", 9216},
	{"SHO R", 13312}, {"SHO F", 30720}, {"SHO M", 10240}, {"SHO I", 13312},
	{"SHO E 1", 16384}, {"SHO E 2", 16384}, {"SHO E 3", 16384},
	{"SHO DNP 1", 17408}, {"SHO DNP 2", 17408}, {"SHO DNP 3", 17408},
}

// TestContentRev5: revision 5 is revision 4 in format 0.3 plus the 24 SHO
// forms and the run that reads them (P4-A2, D4-13). Every earlier line, deny
// rule, precondition, warning, context read and firmware entry is unchanged.
func TestContentRev5(t *testing.T) {
	old, p := loadRev4(t), loadContent(t)
	if p.Revision != 5 || p.Contract != "otsec.register/0.3" || p.Issued != "2026-10-27" {
		t.Fatalf("revision %d, %s, issued %s", p.Revision, p.Contract, p.Issued)
	}
	m, err := NewMatcher(p)
	if err != nil {
		t.Fatal(err)
	}
	// The run: SHO P 1 and SHO G lead, then the other 22 forms in order, each
	// with the counted reply bound and 10 s.
	if len(p.Runs) != 1 || p.Runs[0].ID != "sel.config.read_all" {
		t.Fatalf("runs %+v", p.Runs)
	}
	r := p.Runs[0]
	lines, err := m.RenderRun(r.ID)
	if err != nil || len(lines) != len(rev5Limits) {
		t.Fatalf("RenderRun: %d lines, %v", len(lines), err)
	}
	for i, want := range rev5Limits {
		if lines[i] != want.line {
			t.Errorf("step %d is %q, want %q", i+1, lines[i], want.line)
		}
		_, id := m.Match(lines[i])
		l, ok := m.Limits(id)
		if !ok || l.MaxReplyBytes != want.bound || l.TimeoutMS != 10_000 {
			t.Errorf("%s: limits %+v, %v, want %d bytes in 10 s", lines[i], l, ok, want.bound)
		}
		if o, _ := m.Operation(id); o.Classification != ReadOnly || o.AccessLevel != "1" || len(o.Params) != 0 ||
			o.Evidence.Class != DocumentedUntested || len(o.Citations) == 0 || o.Citations[0].Source != "S22" {
			t.Errorf("%s: %+v", id, o)
		}
	}
	if r.MaxTotalBytes != 512<<10 || r.DeadlineMS != 300_000 || r.Evidence.Class != DocumentedUntested {
		t.Errorf("run %+v", r)
	}
	// Only the steps have limits, and each form once (no two IDs share a line).
	seen := map[string]bool{}
	for _, o := range p.Operations {
		if o.Limits != nil && !slices.Contains(lines, o.Line) {
			t.Errorf("%s has limits but is no step", o.ID)
		}
		if seen[o.Line] {
			t.Errorf("line %q twice", o.Line)
		}
		seen[o.Line] = true
	}
	// Everything else is revision 4 as it was.
	q := *p
	q.Contract, q.Revision, q.Issued, q.Runs, q.Notes = old.Contract, old.Revision, old.Issued, nil, p.Notes[1:]
	q.Operations = slices.Clone(p.Operations[:len(old.Operations)])
	for i := range q.Operations {
		q.Operations[i].Limits = nil
	}
	if !reflect.DeepEqual(&q, old) {
		t.Error("revision 5 changes more than its contract, revision, date, notes, the new operations, their limits and the run")
	}
	if !strings.HasPrefix(p.Notes[0], "Revision 5 by B2") || !strings.Contains(p.Notes[0], "touchscreen") {
		t.Errorf("first note %q", p.Notes[0])
	}
	// Nothing the run does not send is newly approved: the operations of
	// revision 5 are revision 4's four and the 22 forms.
	if len(p.Operations) != len(old.Operations)+len(rev5Limits)-2 {
		t.Errorf("%d operations", len(p.Operations))
	}
	// The "s" forms and a bare SHO P stay refused, and so does every form
	// the table does not list.
	for _, l := range []string{"SHO 1 CTR", "SHO L 2 SV1", "SHO G UTC_OFF", "SHO P", "SHO P 1 LANG", "SHO 5", "SHO L 5", "SHO P 5", "SHO E 4", "SHO DNP 0", "SHO T", "SHO  1", "sho 1", "SHO 1 "} {
		if v, id := m.Match(l); v == VerdictOperation || v == VerdictSessionControl {
			t.Errorf("%q classified %s (%s)", l, v, id)
		}
	}
}
