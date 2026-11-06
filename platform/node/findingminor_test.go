package node

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"otsec.local/otsec/contracts/finding"
	c5 "otsec.local/otsec/contracts/store"
	"otsec.local/otsec/platform/store"
)

// appendUnchecked commits doc to stream with the node stopped, as a build
// that knows a newer finding minor would have, past the configuration
// document check of this build (the rollback case of D4-61).
func appendUnchecked(t *testing.T, c *Config, stream c5.StreamID, doc []byte) {
	t.Helper()
	layout, err := c.Layout()
	if err != nil {
		t.Fatal(err)
	}
	var spec c5.Database
	for _, d := range layout.Databases {
		for _, s := range d.Streams {
			if s.ID == stream {
				spec = d
			}
		}
	}
	env, err := store.NewEnv(store.Options{Dir: c.Store.Dir, Node: c.NodeID, Database: spec, Now: time.Now,
		Documents: func([]byte, *c5.Capture) (c5.DocumentInfo, error) {
			return c5.DocumentInfo{Kind: c5.DocumentEvidence, Series: c5.SeriesFinding}, nil
		}})
	if err != nil {
		t.Fatal(err)
	}
	unlock, err := env.Lock(bg)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	rs, err := env.Open(bg)
	if err != nil {
		t.Fatal(err)
	}
	db, _ := store.AsDB(rs)
	defer db.Close()
	if err := db.CheckSettings(bg); err != nil {
		t.Fatal(err)
	}
	last, err := db.LastCommitted(bg, stream)
	if err != nil {
		t.Fatal(err)
	}
	log, err := c5.NewLogFor(db, c.NodeID, spec, groupFor(spec, c5.DefaultGroup), map[c5.StreamID]c5.Seq{stream: last})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := log.AppendBatch(bg, []c5.Record{{Stream: stream, Class: c5.ClassConfiguration, Event: doc}}); err != nil {
		t.Fatal(err)
	}
}

// A finding of a minor this build does not know stops the asset's
// applicability evaluation, never is skipped (D4-61, P4-H3 step 1). Its
// evaluation is not completed and nothing is appended, so no revision names
// an older finding as previous; the not-evaluated alarm names the schema,
// at most 64 bytes of printable ASCII, quoted. Finding.Validate accepts any
// 0.x minor, so the refusal must come from finding.Known.
func TestFindingsRefuseAnUnknownMinor(t *testing.T) {
	for name, tc := range map[string]struct{ schema, shown string }{
		"0.2":       {"otsec.finding/0.2", `"otsec.finding/0.2"`},
		"0.10":      {"otsec.finding/0.10", `"otsec.finding/0.10"`},
		"oversized": {"otsec.finding/0." + strings.Repeat("9", 200), `"otsec.finding/0.` + strings.Repeat("9", 64-len("otsec.finding/0.")) + `"`},
		"control":   {"otsec.finding/0.2\n\x1b[2Jforged", `"otsec.finding/0.2??[2Jforged"`},
	} {
		t.Run(name, func(t *testing.T) {
			k := newAdvKey(t)
			n := newAdvNode(t, k.anchor("active"))
			n.put(k.sign(findPayload(t, 1)))
			n.step()
			doc := mustStored(t, n, "adv-in", 1)
			newer := bytes.Replace(doc, []byte(`"schema":"`+finding.Identifier+`"`), []byte(`"schema":"`+jsonString(tc.schema)+`"`), 1)
			if bytes.Equal(newer, doc) {
				t.Fatal("the schema was not replaced")
			}
			// This build's write check refuses the record too.
			if _, err := ConfigDocuments(newer, nil); err == nil {
				t.Fatal("ConfigDocuments accepted a finding of an unknown minor")
			}
			if _, err := ConfigDocuments(doc, nil); err != nil {
				t.Fatalf("ConfigDocuments refused the 0.1 finding: %v", err)
			}
			if err := n.r.Close(); err != nil {
				t.Fatal(err)
			}
			appendUnchecked(t, n.cfg, ConfigStream(relayID), newer)
			n.startNode()
			stream := ConfigStream(relayID)
			before, _ := n.r.Store(stream).LastCommitted(bg, stream)
			n.step()
			n.s.evaluate(bg, relayID)
			if after, _ := n.r.Store(stream).LastCommitted(bg, stream); after != before {
				t.Fatalf("%d records appended after a finding of an unknown minor", after-before)
			}
			var details []string
			for _, a := range n.st.Snapshot("x").Alarms {
				if a.Code == AlarmNotEvaluated && a.Asset == relayID {
					details = append(details, a.Detail)
				}
			}
			want := "finding schema " + tc.shown + " is not known to this build"
			if len(details) != 1 || !strings.Contains(details[0], want) {
				t.Fatalf("not-evaluated alarms %q, want one naming %s", details, want)
			}
			if strings.ContainsAny(details[0], "\n\x1b") {
				t.Fatalf("control characters in the alarm: %q", details[0])
			}
		})
	}
}

// jsonString is s as it lies inside a JSON string.
func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b[1 : len(b)-1])
}
