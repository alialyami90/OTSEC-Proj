package contract

// C12 0.1 (otsec.finding/0.1, contracts/finding, docs/phase4/C4-matcher.md,
// D4-49 Q5 and Q6, D4-53): C6's own cases. Expected outcomes come from the
// rule text, not from the code. Every value is invented. Ground truth:
// GT-HAND. Evidence class: desk.
//
// What is checked here that C4's per-package tests do not see: a finding
// is built from the other contracts' own values and must agree with them.
// Its sources are C1 0.3's three kinds; it names a set by exactly the
// set_id and issued_at C11 takes; each evidence ID is the form its source's
// contract writes (C2's invocation ID, C4's event ID, C8's audit record on
// a C3 node ID), and no form stands for another source; and a finding at
// every bound fits one configuration record at the node's cap.

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"otsec.local/otsec/contracts/advisory"
	"otsec.local/otsec/contracts/asset"
	"otsec.local/otsec/contracts/event"
	"otsec.local/otsec/contracts/finding"
	cnode "otsec.local/otsec/contracts/node"
	"otsec.local/otsec/platform/node"
)

// c12Inv is an invocation ID of the form C2 writes (a version 4 UUID).
const c12Inv = "3e9d5a71-0b2c-4f86-a1d4-6c8e2f0b9a53"

func c12Finding() finding.Finding {
	return finding.Finding{
		Schema: finding.Identifier, AssetID: "2b7d4e10-8c3f-4a5b-9e21-7c4f0d6a8b13", Advisory: "TEST-ADV-01",
		Set:      finding.Set{ID: "c6-test", Version: 1, IssuedAt: "2026-11-05T00:00:00Z"},
		Revision: 1, Class: finding.ApplicableByVersion, EvaluatedUTC: "2026-11-06T05:00:00.123456Z",
		Matcher: finding.Matcher{Name: "otsec-applicability", Version: "0.1"},
		Identity: finding.Identity{Product: "SEL-751", Version: "R501-V0", Source: finding.DeviceRead,
			Evidence: []finding.Evidence{{Source: finding.DeviceRead, ID: c12Inv}}},
	}
}

// C12's sources are C1 0.3's source kinds, the same three (C12's Source
// comment, R9 classes), so an identity's source in a finding is the kind
// its C1 observation carries.
func TestC12SourcesAreC1s(t *testing.T) {
	c1 := []string{string(asset.DeviceRead), string(asset.Passive), string(asset.Operator)}
	c12 := []string{string(finding.DeviceRead), string(finding.Passive), string(finding.Operator)}
	if strings.Join(c1, ",") != strings.Join(c12, ",") {
		t.Fatalf("C1 0.3 kinds %v, C12 sources %v", c1, c12)
	}
	f := c12Finding()
	f.Identity.Source, f.Identity.Evidence[0].Source = "derived", "derived"
	if f.Validate() == nil {
		t.Error("a source C1 0.3 does not have: accepted")
	}
}

// A finding names its set by C11's set_id, version and issued_at (R9.3), so
// it must take exactly what a C11 set can carry: a set C11 takes that C12
// refused would leave its findings unrecordable, and one C12 took that C11
// never would names no set.
func TestC12NamesAC11SetExactly(t *testing.T) {
	ok := func(id, at string) (inC11, inC12 bool) {
		s := c11Set(1, advisory.PurposeTest)
		s.SetID, s.IssuedAt = id, at
		f := c12Finding()
		f.Set = finding.Set{ID: id, Version: 1, IssuedAt: at}
		return s.Validate() == nil, f.Validate() == nil
	}
	const at = "2026-11-05T00:00:00Z"
	for _, id := range []string{"gt-adv", "c6-test", "a", "0", strings.Repeat("a", 64), strings.Repeat("a", 65),
		"Gt-adv", "-gt", "gt_adv", "gt.adv", "gt adv", ""} {
		if c11, c12 := ok(id, at); c11 != c12 {
			t.Errorf("set_id %q: C11 takes it %v, C12 %v", id, c11, c12)
		}
	}
	for _, ts := range []string{at, "2026-11-05T00:00:00.5Z", "2026-11-05T00:00:00.123456789Z", "2026-11-05T00:00:00+00:00",
		"2026-11-05T00:00:00", "2026-11-05", "2026-13-05T00:00:00Z", ""} {
		if c11, c12 := ok("gt-adv", ts); c11 != c12 {
			t.Errorf("issued_at %q: C11 takes it %v, C12 %v", ts, c11, c12)
		}
	}
}

// Each evidence ID is the form its source's contract writes, and no form
// stands for another source, so an operator's entry can never be cited as a
// device read (C6 on #440) or as passive evidence (F-025, D4-57).
func TestC12EvidenceIsItsSourcesForm(t *testing.T) {
	passive := event.EventID{NodeID: "site-a-node-1", Stream: "syslog/192.0.2.31", Seq: 7}.String()
	audit := "audit:site-a-node-1:12"
	forms := map[finding.Source]string{finding.DeviceRead: c12Inv, finding.Passive: passive, finding.Operator: audit}
	for src := range forms {
		for other, otherID := range forms {
			f := c12Finding()
			f.Class, f.Reason = finding.ApplicableByVersion, ""
			f.Identity.Source = src
			f.Identity.Evidence = []finding.Evidence{{Source: src, ID: otherID}}
			if err := f.Validate(); (err == nil) != (src == other) {
				t.Errorf("%s evidence cited as %q (%s's form): %v", src, otherID, other, err)
			}
		}
	}
	for name, ev := range map[string]finding.Evidence{
		"a device read in upper case":          {Source: finding.DeviceRead, ID: strings.ToUpper(c12Inv)},
		"an audit ref on an invalid node ID":   {Source: finding.Operator, ID: "audit:Site_A:12"},
		"an audit ref at seq 0":                {Source: finding.Operator, ID: "audit:site-a-node-1:0"},
		"an audit ref with a leading zero":     {Source: finding.Operator, ID: "audit:site-a-node-1:012"},
		"an event ID at seq 0":                 {Source: finding.Passive, ID: "site-a-node-1:syslog/192.0.2.31:0"},
		"an event ID on an invalid stream":     {Source: finding.Passive, ID: "site-a-node-1:Syslog:7"},
		"an operator entry cited by free text": {Source: finding.Operator, ID: "operator:commissioning-sheet-07"},
		// F-025, D4-57: an audit ref is also an event ID's shape, of a
		// node named "audit"; C3 reserves that name, so neither reading
		// stands as passive evidence, and no audit ref names that node.
		"an audit ref cited as passive, on node audit": {Source: finding.Passive, ID: "audit:audit:12"},
		"an event ID on node audit":                    {Source: finding.Passive, ID: "audit:syslog/192.0.2.31:7"},
		"an audit ref on node audit":                   {Source: finding.Operator, ID: "audit:audit:12"},
		"a device read of UUID version 0":              {Source: finding.DeviceRead, ID: "3e9d5a71-0b2c-0f86-a1d4-6c8e2f0b9a53"},
		"a device read without the RFC variant":        {Source: finding.DeviceRead, ID: "3e9d5a71-0b2c-4f86-c1d4-6c8e2f0b9a53"},
	} {
		f := c12Finding()
		f.Identity.Source, f.Identity.Evidence = ev.Source, []finding.Evidence{ev}
		if f.Validate() == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// "Bounds on one record, so a finding always fits one store record"
// (contracts/finding): a finding at every bound C12 sets, with its other
// fields at the longest their sources allow (identity values at C1 0.3's
// MaxValueBytes, IDs at C3's node ID and stream bounds and a 20-digit seq),
// validates and fits one configuration record at the node's cap.
func TestC12AFindingAtEveryBoundFitsOneRecord(t *testing.T) {
	nodeID := strings.Repeat("n", 63)
	stream := "s" + strings.Repeat("x", 127)
	evs := func(stale bool) []finding.Evidence {
		out := make([]finding.Evidence, finding.MaxEvidence)
		for i := range out {
			out[i] = finding.Evidence{Source: finding.Passive, Stale: stale,
				ID: event.EventID{NodeID: event.NodeID(nodeID), Stream: event.Stream(stream), Seq: 18446744073709551615 - uint64(i)}.String()}
		}
		return out
	}
	name := func(p string, i int) string {
		s := fmt.Sprintf("%s%d-", p, i)
		return s + strings.Repeat("z", 64-len(s))
	}
	f := c12Finding()
	f.Advisory = "A" + strings.Repeat("9", 127)
	f.Set.ID = strings.Repeat("s", 64)
	f.Revision, f.Previous, f.From = 1<<31-1, "sha256:"+strings.Repeat("f", 64), finding.ApplicableByVersion
	f.Class = finding.Mitigated
	f.Identity = finding.Identity{Product: strings.Repeat("P", asset.MaxValueBytes), Version: strings.Repeat("V", asset.MaxValueBytes),
		Source: finding.Passive, Evidence: evs(true)}
	for i := 0; i < finding.MaxPreconditions; i++ {
		f.Preconditions = append(f.Preconditions, finding.Precondition{Name: name("p", i), State: finding.Evidenced, Evidence: evs(true)})
	}
	for i := 0; i < finding.MaxMitigations; i++ {
		f.Mitigations = append(f.Mitigations, finding.Mitigation{Name: name("m", i), Evidence: evs(false)})
	}
	if err := f.Validate(); err != nil {
		t.Fatalf("the finding at every bound does not validate: %v", err)
	}
	b, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	if int64(len(b)) > node.ConfigRecordBytes {
		t.Fatalf("a finding at every bound is %d bytes, above the node's configuration record cap %d", len(b), node.ConfigRecordBytes)
	}
	t.Logf("a finding at every bound is %d bytes; the node's configuration record cap is %d", len(b), node.ConfigRecordBytes)
}

// D4-57: "audit" is the first part of an operator's audit citation, so it is
// no node ID, and no event ID can be issued on it; a name that only contains
// the word stays a node ID.
func TestC12NodeAuditIsReserved(t *testing.T) {
	if cnode.ID("audit").Valid() || event.NodeID("audit").Valid() {
		t.Error(`node ID "audit": accepted`)
	}
	if _, err := event.ParseEventID("audit:site-a-node-1:12"); err == nil {
		t.Error(`event ID on node "audit": accepted`)
	}
	for _, id := range []string{"audit1", "audit-node", "site-audit", "audits"} {
		if !cnode.ID(id).Valid() {
			t.Errorf("node ID %q: refused", id)
		}
	}
}
