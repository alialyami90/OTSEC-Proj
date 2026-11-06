package node

import (
	"bytes"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"otsec.local/otsec/contracts/advisory"
	"otsec.local/otsec/contracts/finding"
	c5 "otsec.local/otsec/contracts/store"
	"otsec.local/otsec/platform/node/nodeconfigtest"
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
// 0.x minor, so the refusal must come from finding.Known. The refusal is
// per asset, and collection goes on (D3 on #509): a second asset still gets
// its findings under a new set, and a run of the refused asset is still
// accepted and its events committed.
func TestFindingsRefuseAnUnknownMinor(t *testing.T) {
	const secondID = "3c8e5f21-9d40-4b6c-8f32-8d5a1e7b9c24"
	for name, tc := range map[string]struct{ schema, shown string }{
		"0.2":       {"otsec.finding/0.2", `"otsec.finding/0.2"`},
		"0.10":      {"otsec.finding/0.10", `"otsec.finding/0.10"`},
		"oversized": {"otsec.finding/0." + strings.Repeat("9", 200), `"otsec.finding/0.` + strings.Repeat("9", 64-len("otsec.finding/0.")) + `"`},
		"control":   {"otsec.finding/0.2\n\x1b[2Jforged", `"otsec.finding/0.2??[2Jforged"`},
		// A quote, a backslash and a two-byte character (D6 on #509).
		"quoted": {"otsec.finding/0.2\"\\\u00e9x", `"otsec.finding/0.2????x"`},
	} {
		t.Run(name, func(t *testing.T) {
			k := newAdvKey(t)
			n := newAdvNodeWith(t, func(nc *nodeconfigtest.Config) {
				nc.AddSEL751(secondID, "", 2324, 300)
				nc.Store.Quotas["configuration"] = 8 << 20 // the item 3 floor for two assets
			}, k.anchor("active"))
			n.put(k.sign(findPayload(t, 1)))
			n.step()
			doc := mustStored(t, n, "adv-in", 1)
			if got := advisoriesOf(t, n, secondID); !slices.Contains(got, "adv-in") {
				t.Fatalf("the second asset's findings %q, want adv-in", got)
			}
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
			n.r, n.st, _ = start(t, n.cfg, n.dir)
			n.s = newScheduler(t, n.r, answering(okRun(t, invA, nil)))
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

			// Per asset: a set with a new advisory gives the second asset
			// its finding, and the refused asset none.
			n.put(k.sign(withEntry(t, findPayload(t, 2), "adv-new")))
			n.step()
			if got := advisoriesOf(t, n, secondID); !slices.Contains(got, "adv-new") {
				t.Fatalf("the second asset's findings %q after the refusal, want adv-new", got)
			}
			if got := advisoriesOf(t, n, relayID); slices.Contains(got, "adv-new") {
				t.Fatalf("the refused asset got a finding: %q", got)
			}
			for _, a := range n.st.Snapshot("x").Alarms {
				if a.Code == AlarmNotEvaluated && a.Asset == secondID {
					t.Fatalf("the second asset is not evaluated: %s", a.Detail)
				}
			}
			// Collection goes on for the refused asset.
			ran := false
			for i, e := range n.cfg.Schedule {
				if e.AssetID == relayID {
					if rep := n.s.RunOnce(bg, i); rep.Outcome != "ok" || rep.Events == 0 {
						t.Fatalf("a run of the refused asset: %+v", rep)
					}
					ran = true
				}
			}
			if !ran {
				t.Fatal("no schedule entry for the refused asset")
			}
		})
	}
}

// advisoriesOf are the advisories of the asset's stored findings.
func advisoriesOf(t *testing.T, n *advNode, assetID string) []string {
	t.Helper()
	got, err := n.r.Store(ConfigStream(assetID)).Read(bg, ConfigStream(assetID), 0, 1000)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, st := range got {
		if f, err := decodeFinding(st.Event); err == nil {
			out = append(out, f.Advisory)
		}
	}
	return out
}

// withEntry is payload with one more entry, id, whose range holds the
// SEL-751 FID ok.json reads.
func withEntry(t *testing.T, payload []byte, id string) []byte {
	t.Helper()
	var s advisory.Set
	if err := json.Unmarshal(payload, &s); err != nil {
		t.Fatal(err)
	}
	e := advEntry(id, "a new advisory")
	e.Affected[0].Ranges = []advisory.Range{{Introduced: "R501-V0", Fixed: "R501-V9"}}
	s.Entries = append(s.Entries, e)
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// jsonString is s as it lies inside a JSON string.
func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b[1 : len(b)-1])
}
