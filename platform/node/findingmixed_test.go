package node

import (
	"bytes"
	"encoding/json"
	"testing"

	"otsec.local/otsec/contracts/advisory"
	"otsec.local/otsec/contracts/finding"
	"otsec.local/otsec/modules/applicability"
)

// A stream that holds a 0.1 finding, stored by a build before C12 0.2, and
// then the 0.2 findings this build stores folds in order, and the chain keeps
// previous across the minor change (P4-H3 §7, D4-61). A set that changes
// only the schema adds no revision; the next revision is 0.2 and names the
// 0.1 record's hash; a restart reads both and adds nothing.
func TestFindingsFoldBothMinors(t *testing.T) {
	k := newAdvKey(t)
	// The 0.1 record is this build's revision 1 as a 0.1 build writes it.
	a := newAdvNode(t, k.anchor("active"))
	a.put(k.sign(findPayload(t, 1)))
	a.step()
	doc01 := asMinor01(t, mustStored(t, a, "adv-in", 1))

	n := newAdvNode(t, k.anchor("active"))
	if err := n.r.Close(); err != nil {
		t.Fatal(err)
	}
	appendUnchecked(t, n.cfg, ConfigStream(relayID), doc01)
	n.startNode()
	n.put(k.sign(findPayload(t, 1)))
	n.step()
	if got := advInRecords(t, n); len(got) != 1 || !bytes.Equal(got[0], doc01) {
		t.Fatalf("the same set added a revision over the 0.1 record: %d records", len(got))
	}

	// adv-in falls out of range under version 2.
	n.put(k.sign(outOfRange(t, findPayload(t, 2))))
	n.step()
	got := advInRecords(t, n)
	if len(got) != 2 {
		t.Fatalf("%d adv-in records, want the 0.1 record and one 0.2 revision", len(got))
	}
	f01, _ := decodeFinding(got[0])
	f, err := decodeFinding(got[1])
	if err != nil {
		t.Fatal(err)
	}
	if f.Schema != finding.Identifier || f.Revision != 2 || f.Previous != finding.Hash(doc01) || f.From != f01.Class || f.Class == f01.Class {
		t.Fatalf("the 0.2 revision %+v over the 0.1 record %+v", f, f01)
	}

	n.restart()
	n.step()
	n.s.evaluate(bg, relayID)
	if again := advInRecords(t, n); len(again) != 2 {
		t.Fatalf("a restart over both minors added %d adv-in records", len(again)-2)
	}
	if fs := n.s.finds[relayID]; fs == nil || fs.newest["adv-in"].Hash != finding.Hash(got[1]) {
		t.Fatalf("the fold's newest adv-in is not the 0.2 revision: %+v", fs)
	}
	for _, al := range n.st.Snapshot("x").Alarms {
		if al.Code == AlarmNotEvaluated {
			t.Fatalf("not evaluated: %s", al.Detail)
		}
	}
}

// asMinor01 is a 0.2 finding with no mismatch as a 0.1 build stores it.
func asMinor01(t *testing.T, doc []byte) []byte {
	t.Helper()
	out := bytes.Replace(doc, []byte(`{"schema":"`+finding.Identifier+`"`), []byte(`{"schema":"otsec.finding/0.1"`), 1)
	out = bytes.Replace(out, []byte(`"version":"`+applicability.Version+`"`), []byte(`"version":"0.1.0"`), 1)
	f, err := decodeFinding(out)
	if err != nil || f.Schema != "otsec.finding/0.1" || f.Matcher.Version != "0.1.0" {
		t.Fatalf("no 0.1 record from %s: %v", doc, err)
	}
	return out
}

// advInRecords are the stored adv-in findings of the asset, in order.
func advInRecords(t *testing.T, n *advNode) [][]byte {
	t.Helper()
	got, err := n.r.Store(ConfigStream(relayID)).Read(bg, ConfigStream(relayID), 0, 1000)
	if err != nil {
		t.Fatal(err)
	}
	var out [][]byte
	for _, st := range got {
		if f, err := decodeFinding(st.Event); err == nil && f.Advisory == "adv-in" {
			out = append(out, st.Event)
		}
	}
	return out
}

// outOfRange is payload with adv-in's range moved off the FID ok.json reads.
func outOfRange(t *testing.T, payload []byte) []byte {
	t.Helper()
	var s advisory.Set
	if err := json.Unmarshal(payload, &s); err != nil {
		t.Fatal(err)
	}
	s.Entries[0].Affected[0].Ranges = []advisory.Range{{Introduced: "R502-V0", Fixed: "R502-V9"}}
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
