package netdetect

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"

	"otsec.local/otsec/contracts/netobs"
)

// lxRestamp re-encodes the learner checkpoint cp stamped schema, in the
// writer's key order and with its top-level keys sorted; each is read
// strictly.
func lxRestamp(t *testing.T, cp []byte, schema string) (ordered, sorted []byte) {
	t.Helper()
	k, err := netobs.DecodeLearnerCheckpoint(cp)
	if err != nil {
		t.Fatal(err)
	}
	k.Schema = schema
	if ordered, err = k.Encode(); err != nil {
		t.Fatal(err)
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(ordered, &top); err != nil {
		t.Fatal(err)
	}
	sorted = must(json.Marshal(top))
	if _, err := netobs.DecodeLearnerCheckpoint(sorted); err != nil {
		t.Fatalf("the sorted %s document is not read strictly: %v", schema, err)
	}
	return ordered, sorted
}

// N3 on #687, as TestDetectorRestores01Checkpoint for the learner: a
// strictly valid 0.1 learner checkpoint, holding starts, restores in
// either key order, and the restored learner's next checkpoint is the 0.2
// one it came from. The control is the check before the fix, which
// compared the writer's 0.2 re-encoding with the 0.1 document: they
// differ, so it refused them all. A document that does not restore to
// itself is still refused at either minor.
func TestLearnerRestores01Checkpoint(t *testing.T) {
	l := mustV(NewLearner(lxConfig()))
	for i, o := range lxStream(t, 20) {
		if err := l.Observe(uint64(i+1), o); err != nil {
			t.Fatal(err)
		}
	}
	cp := checkpoint(t, l)
	if !bytes.Contains(cp, []byte(`"held":[{`)) {
		t.Fatal("the checkpoint holds no start: the test covers no held state")
	}
	// 0.2 too since C13 0.3 (D6's N2 on #689); its control is the round
	// trip narrowed to 0.1 (D6's L1).
	ordered, _ := lxRestamp(t, cp, netobs.CheckpointIdentifier01)
	for _, sch := range []string{netobs.CheckpointIdentifier01, netobs.CheckpointIdentifier02} {
		ord, sorted := lxRestamp(t, cp, sch)
		for name, doc := range map[string][]byte{"ordered": ord, "sorted": sorted} {
			r, err := RestoreLearner(lxConfig(), doc)
			if err != nil {
				t.Fatalf("%s %s: %v", name, sch, err)
			}
			again := checkpoint(t, r)
			if bytes.Equal(again, doc) {
				t.Fatalf("%s %s: the writer's re-encoding equals the earlier document, so the control shows nothing", name, sch)
			}
			if !bytes.Equal(again, cp) {
				t.Fatalf("%s %s: the next checkpoint is not this code's one restored from\n got %s\nwant %s", name, sch, again, cp)
			}
		}
	}
	if _, err := RestoreLearner(lxConfig(), cp); err != nil {
		t.Fatalf("0.2 control: %v", err)
	}
	// Not itself: a space inside the draft, at either minor, and a byte
	// past the writer's 0.2 encoding.
	space := func(b []byte) []byte { return bytes.Replace(b, []byte(`"pairs":[`), []byte(`"pairs": [`), 1) }
	docs := map[string][]byte{
		"0.1 draft with a space": space(slices.Clone(ordered)),
		"0.2 draft with a space": space(slices.Clone(cp)),
		"0.2 trailing space":     append(slices.Clone(cp), ' '),
	}
	for name, doc := range docs {
		if _, err := RestoreLearner(lxConfig(), doc); err == nil {
			t.Errorf("%s: restored", name)
		}
	}
}

// N2 on #687: the detector builds the alerts a stored 0.2 observation
// raises. dxStream's six observations, made 0.2 stored records with
// made_utc and the coverage's config_digest and prp_window_ms, raise seven
// alerts; each is stamped otsec.netobs/0.2 and builds its health body. The
// control is the stamp before the fix, otsec.netobs/0.1: with that
// coverage, the body is refused, so no alert would be stored.
func TestDetectorAlerts02Observations(t *testing.T) {
	d := dxDetector(t, dxBaseline(t))
	var alerts []netobs.Alert
	for i, o := range dxStream(t, 6) {
		o.Schema, o.MadeUTC = netobs.Identifier02, o.LastUTC
		o.Coverage.ConfigDigest = "sha256:" + strings.Repeat("0f", 32)
		o.Coverage.Settings.PRPWindowMS = netobs.DefaultPRPWindowMS
		stored := mustV(netobs.DecodeStored(mustJSON(t, o)))
		out, err := d.Observe(dxID(uint64(i+1)), stored)
		if err != nil {
			t.Fatal(err)
		}
		alerts = append(alerts, out...)
	}
	if len(alerts) != 7 {
		t.Fatalf("%d alerts, want 7", len(alerts))
	}
	for i, a := range alerts {
		if a.Rule != netobs.RuleOwnSessionUnseen {
			a.Capture = fmt.Sprintf("%064x", i+1)
		}
		if a.Schema != netobs.Identifier02 {
			t.Errorf("alert %d (%s): %s, want %s", i, a.Rule, a.Schema, netobs.Identifier02)
		}
		if _, err := a.Health(); err != nil {
			t.Errorf("alert %d (%s): %v", i, a.Rule, err)
		}
		a.Schema = netobs.Identifier
		if _, err := a.Health(); err == nil {
			t.Errorf("alert %d (%s): the 0.1 stamp builds too, so the control shows nothing", i, a.Rule)
		}
	}
}
