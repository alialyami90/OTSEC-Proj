package node

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"otsec.local/otsec/contracts/adapter"
	"otsec.local/otsec/contracts/advisory"
	"otsec.local/otsec/contracts/audit"
	"otsec.local/otsec/contracts/finding"
	c5 "otsec.local/otsec/contracts/store"
	"otsec.local/otsec/modules/security/collectorclient"
)

// mismatchFID is the FID the tests' mismatch read reports: another
// product, as long as the declared FID, so it replaces it byte for byte.
const mismatchFID = "SEL-311-R100-V0-Z001001-D20260101"

// findPayload is a set of three entries for the SEL-751 whose FID ok.json
// reads (R501-V0): one with it in range, one with it out of range, and one
// for the product the mismatch read reports.
func findPayload(t *testing.T, version uint64) []byte {
	t.Helper()
	in := advEntry("adv-in", "in range")
	in.Affected[0].Ranges = []advisory.Range{{Introduced: "R501-V0", Fixed: "R501-V9"}}
	other := advEntry("adv-other", "another product")
	other.Affected[0].Product = "SEL-311"
	s := advisory.Set{Contract: advisory.Identifier, SetID: "otsec-sel", Version: version, IssuedAt: "2026-11-05T00:00:00Z",
		Purpose: advisory.PurposeRelease, Publisher: "node tests",
		Entries: []advisory.Entry{in, advEntry("adv-out", "out of range"), other}}
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := advisory.Decode(b); err != nil {
		t.Fatalf("the test's own set is invalid: %v", err)
	}
	return b
}

// startWith restarts the node on the same store with collector c.
func (n *advNode) startWith(c Collector) {
	n.t.Helper()
	if err := n.r.Close(); err != nil {
		n.t.Fatal(err)
	}
	n.r, n.st, _ = start(n.t, n.cfg, n.dir)
	n.s = newScheduler(n.t, n.r, c)
	n.t.Cleanup(func() { n.r.Close() })
}

// findings are the finding records of the asset, in order.
func (n *advNode) findings() []finding.Finding {
	n.t.Helper()
	got, err := n.r.Store(ConfigStream(relayID)).Read(bg, ConfigStream(relayID), 0, 1000)
	if err != nil {
		n.t.Fatal(err)
	}
	var out []finding.Finding
	for _, st := range got {
		if bytes.HasPrefix(st.Event, []byte(`{"schema":"`+finding.Identifier)) {
			f, err := decodeFinding(st.Event)
			if err != nil {
				n.t.Fatal(err)
			}
			out = append(out, f)
		}
	}
	return out
}

// assetFindings is the asset's line in status.applicability.assets.
func (n *advNode) assetFindings() AssetFindingsStatus {
	a := n.st.Snapshot("x").Applicability
	if a == nil {
		n.t.Fatal("no applicability section in status")
	}
	return a.Assets[relayID]
}

// mismatchRun is the mismatch fixture as run inv, reporting mismatchFID.
func mismatchRun(t *testing.T, inv string) *collectorclient.Outcome {
	t.Helper()
	res, err := adapter.DecodeResult(readFile(t, "../../contracts/adapter/testdata/results/valid/refused.identity_mismatch.json"))
	if err != nil {
		t.Fatal(err)
	}
	// After ok.json's run, which ended at 09:15:01.8.
	res.InvocationID, res.StartedAt, res.EndedAt = inv, "2026-10-24T09:20:00.0Z", "2026-10-24T09:20:00.6Z"
	sp := res.Identity.Items[0].Span
	data := bytes.Clone(res.Transcript.Data)
	copy(data[sp.Offset:], mismatchFID)
	res.Transcript.Data = data
	sum := sha256.Sum256(data)
	res.Transcript.SHA256 = hex.EncodeToString(sum[:])
	res.Identity.Items[0].Observed = mismatchFID
	res.Observations[0].Value = mismatchFID
	b, _ := json.Marshal(res)
	o := &collectorclient.Outcome{InvocationID: inv, Result: res, ResultJSON: b}
	return o
}

// Findings follow the identity: at start the declared identity is cited by
// its policy.apply record, a run's device-read identity revises each stored
// finding, an unchanged run and a restart store nothing, and a
// product-not-named finding with no stored one is not stored. Status shows
// the last completed evaluation and the classes.
func TestFindingsFollowTheIdentity(t *testing.T) {
	k := newAdvKey(t)
	n := newAdvNode(t, k.anchor("active"))
	n.startWith(answering(okRun(t, invA, nil), okRun(t, invB, nil)))
	n.put(k.sign(findPayload(t, 1)))
	n.step()

	// Operator: the declared FID, in range, is applicable-by-version and
	// out of range is not-applicable-operator.
	decl := n.records(audit.ActionPolicyApply)
	if len(decl) != 1 || decl[0].ReasonCode != ReasonAssetIdentityDeclared || !strings.Contains(decl[0].Detail, relayID) {
		t.Fatalf("declared-identity records %+v", decl)
	}
	fs := n.findings()
	if len(fs) != 2 || fs[0].Advisory != "adv-in" || fs[0].Class != finding.ApplicableByVersion || fs[1].Class != finding.NotApplicableOperator ||
		fs[0].Identity.Source != finding.Operator || !strings.HasPrefix(fs[0].Identity.Evidence[0].ID, "audit:site-a-node1:") {
		t.Fatalf("operator findings %+v", fs)
	}
	st := n.assetFindings()
	if l := st.LastEvaluation; l == nil || l.Version != 1 || l.SetID != "otsec-sel" || l.IdentityEvidenceID != fs[0].Identity.Evidence[0].ID {
		t.Fatalf("last evaluation %+v", l)
	}

	// A run reads the identity: both findings are revised to device-read.
	n.s.RunOnce(bg, 0)
	fs = n.findings()
	if len(fs) != 4 {
		t.Fatalf("%d findings after the first read", len(fs))
	}
	in, out := fs[2], fs[3]
	if in.Class != finding.Confirmed || in.Revision != 2 || in.From != finding.ApplicableByVersion || in.Identity.Source != finding.DeviceRead ||
		in.Identity.Evidence[0].ID != invA || in.Identity.LatestRead == nil || in.Identity.LatestRead.ID != invA {
		t.Fatalf("in range after a read: %+v", in)
	}
	if out.Class != finding.NotApplicable || out.Reason != finding.OutsideRange || out.Revision != 2 {
		t.Fatalf("out of range after a read: %+v", out)
	}
	ids, _ := identityRecords(t, n.r, relayID)
	if in.Previous != finding.Hash(mustStored(t, n, "adv-in", 1)) {
		t.Fatal("revision 2 does not name revision 1's hash")
	}
	st = n.assetFindings()
	if l := st.LastEvaluation; l == nil || l.IdentityEvidenceID != storedIdentity(t, n.r, ids[0]).InvocationID ||
		st.Classes[finding.Confirmed] != 1 || st.Classes[finding.NotApplicable] != 1 || len(st.Classes) != 2 {
		t.Fatalf("status after a read %+v %+v", st.LastEvaluation, st.Classes)
	}
	if n.alarms(AlarmFindingChanged) != 2 || count(healthTypes(t, n.r), HealthFindingChanged) != 4 {
		t.Fatalf("finding-changed %d, health %d", n.alarms(AlarmFindingChanged), count(healthTypes(t, n.r), HealthFindingChanged))
	}

	// The same identity again, and a restart: nothing new is stored, and
	// the declaration is not recorded again.
	n.s.RunOnce(bg, 0)
	n.startWith(answering(okRun(t, invC, nil)))
	if got := len(n.findings()); got != 4 {
		t.Fatalf("%d findings after an unchanged run and a restart", got)
	}
	if got := len(n.records(audit.ActionPolicyApply)); got != 1 {
		t.Fatalf("%d declared-identity records after a restart", got)
	}
	if l := n.assetFindings().LastEvaluation; l == nil || l.Version != 1 {
		t.Fatalf("no evaluation at start: %+v", l)
	}
}

func mustStored(t *testing.T, n *advNode, adv string, rev int) []byte {
	t.Helper()
	got, err := n.r.Store(ConfigStream(relayID)).Read(bg, ConfigStream(relayID), 0, 1000)
	if err != nil {
		t.Fatal(err)
	}
	for _, st := range got {
		if f, err := decodeFinding(st.Event); err == nil && f.Advisory == adv && f.Revision == rev {
			return st.Event
		}
	}
	t.Fatalf("no %s revision %d", adv, rev)
	return nil
}

// A mismatch read is kept in identity.read with the last confirming read as
// its latest-read part (D4-54): the findings fall to applicable-by-version,
// stale, citing it, and the entry naming the reported product is stored. A
// restart reads it back, so nothing is downgraded. The next confirming read
// clears it.
func TestFindingsKeepTheMismatch(t *testing.T) {
	k := newAdvKey(t)
	n := newAdvNode(t, k.anchor("active"))
	n.startWith(answering(okRun(t, invA, nil), mismatchRun(t, invB)))
	n.put(k.sign(findPayload(t, 1)))
	n.step()
	n.s.RunOnce(bg, 0)
	if rep := n.s.RunOnce(bg, 0); rep.Outcome != "ok" {
		t.Fatalf("the mismatch run: %+v", rep)
	}

	_, reads := identityRecords(t, n.r, relayID)
	if len(reads) != 1 || reads[0].InvocationID != invA || reads[0].Mismatch == nil || reads[0].Mismatch.InvocationID != invB ||
		reads[0].Mismatch.FID != mismatchFID {
		t.Fatalf("identity reads %+v", reads)
	}
	latest := func() map[string]finding.Finding {
		m := map[string]finding.Finding{}
		for _, f := range n.findings() {
			m[f.Advisory] = f
		}
		return m
	}
	m := latest()
	for _, adv := range []string{"adv-in", "adv-out", "adv-other"} {
		f := m[adv]
		if f.Class != finding.ApplicableByVersion || !f.Identity.Evidence[0].Stale || len(f.Identity.Evidence) != 2 || f.Identity.Evidence[1].ID != invB {
			t.Fatalf("%s after the mismatch: %+v", adv, f)
		}
	}
	before := len(n.findings())

	n.startWith(answering(okRun(t, invC, nil)))
	if got := len(n.findings()); got != before {
		t.Fatalf("a restart stored %d findings over a stored mismatch", got-before)
	}

	// The asset is suspended, so the confirming read is applied directly.
	n.s.storeIdentity(bg, n.cfg.Schedule[0], okRun(t, invC, nil).Result)
	_, reads = identityRecords(t, n.r, relayID)
	if len(reads) != 1 || reads[0].InvocationID != invC || reads[0].Mismatch != nil {
		t.Fatalf("identity reads after a confirming read %+v", reads)
	}
	n.s.evaluate(bg, relayID)
	if f := latest()["adv-other"]; f.Class != finding.NotApplicable || f.Reason != finding.ProductNotNamed {
		t.Fatalf("adv-other once confirmed again: %+v", f)
	}
}

// A finding the ceiling refuses leaves the asset with no completed
// evaluation (D4-54), raises asset-store-full, and pauses the matcher. Once
// the class has room again, whatever freed it, the next evaluation catches
// up.
func TestFindingsAtTheCeiling(t *testing.T) {
	k := newAdvKey(t)
	n := newAdvNode(t, k.anchor("active"))
	file := k.sign(findPayload(t, 1))

	// Fill the class with removable identity.read records until the set
	// fits and no finding does.
	stream := ConfigStream(relayID)
	db := n.r.Store(stream)
	doc, _ := json.Marshal(identityReadDoc{Schema: IdentityReadSchema, AssetID: relayID, InvocationID: invD, ReadAt: "2026-10-24T09:00:00Z"})
	var filler []c5.Seq
	for {
		used, err := db.ClassBytes(bg, c5.ClassConfiguration)
		if err != nil {
			t.Fatal(err)
		}
		if used+int64(len(doc)+len(file))+100 > n.cfg.Item3Ceiling() {
			break
		}
		got, err := n.r.Log(stream).AppendBatch(bg, []c5.Record{{Stream: stream, Class: c5.ClassConfiguration, Event: doc}})
		if err != nil {
			t.Fatal(err)
		}
		filler = append(filler, got[0].Key().Seq)
	}
	n.put(file)
	n.step()
	if n.inUse() == nil {
		t.Fatal("the set did not install")
	}
	snap := n.st.Snapshot("x")
	if l := n.assetFindings().LastEvaluation; l != nil || len(n.findings()) != 0 {
		t.Fatalf("an evaluation whose finding was refused completed: %+v", l)
	}
	if n.alarms(AlarmAssetStoreFull) != 1 || snap.AssetStore == nil || !snap.AssetStore.Full || snap.AssetStore.Refused[c5.SeriesFinding] != 1 {
		t.Fatalf("asset store %+v", snap.AssetStore)
	}
	n.s.evaluate(bg, relayID)
	if got := n.st.Snapshot("x").AssetStore.Refused[c5.SeriesFinding]; got != 1 {
		t.Fatalf("the paused matcher tried again: %d refusals", got)
	}

	// Room returns from a removal that is not an item 3 write.
	for len(filler) > 1 {
		step := filler[:min(len(filler)-1, c5.RemoveConfigStep)]
		if _, err := db.RemoveConfig(bg, stream, c5.SeriesIdentityRead, step); err != nil {
			t.Fatal(err)
		}
		filler = filler[len(step):]
	}
	n.s.evaluate(bg, relayID)
	if l := n.assetFindings().LastEvaluation; l == nil || l.Version != 1 {
		t.Fatalf("the evaluation did not catch up: %+v", l)
	}
	if n.st.Snapshot("x").AssetStore.Full {
		t.Fatal("the crossing did not end")
	}
	if got := len(n.findings()); got != 2 {
		t.Fatalf("%d findings after catching up", got)
	}
}

// A declaration changed in the configuration is recorded again and revises
// every operator finding, since its evidence changed; DeclaredIdentitiesFileName keeps the record so it
// is cited, not written, at the next start.
func TestFindingsDeclaredIdentity(t *testing.T) {
	k := newAdvKey(t)
	n := newAdvNode(t, k.anchor("active"))
	n.put(k.sign(findPayload(t, 1)))
	n.step()
	b, err := os.ReadFile(filepath.Join(n.cfg.Store.Dir, DeclaredIdentitiesFileName))
	if err != nil || !bytes.Contains(b, []byte(relayID)) {
		t.Fatalf("%s: %s, %v", DeclaredIdentitiesFileName, b, err)
	}
	if fs := n.findings(); len(fs) != 2 {
		t.Fatalf("%d findings", len(fs))
	}

	// Another declared FID, out of every range.
	at := n.nc.Assets[0]["attributes"].([]any)[3].(map[string]any)
	at["value"] = "SEL-751-R400-V0-Z104101-D20260910"
	at["observations"].([]any)[0].(map[string]any)["value"] = at["value"]
	c, err := ParseConfig(n.nc.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	n.cfg = c
	n.startWith(nil)
	if got := len(n.records(audit.ActionPolicyApply)); got != 2 {
		t.Fatalf("%d declared-identity records after a change", got)
	}
	fs := n.findings()
	if len(fs) != 4 || fs[2].Advisory != "adv-in" || fs[2].Class != finding.NotApplicableOperator || fs[2].Revision != 2 ||
		fs[3].Advisory != "adv-out" || fs[3].Revision != 2 || fs[2].Identity.Evidence[0].ID == fs[0].Identity.Evidence[0].ID {
		t.Fatalf("findings after the declaration changed %+v", fs)
	}
}

// A finding is classified evidence in its own series, and refused with a
// capture, in bytes the encoder would not write, or when C12 refuses it.
func TestFindingDocuments(t *testing.T) {
	k := newAdvKey(t)
	n := newAdvNode(t, k.anchor("active"))
	n.put(k.sign(findPayload(t, 1)))
	n.step()
	doc := mustStored(t, n, "adv-in", 1)
	info, err := ConfigDocuments(doc, nil)
	if err != nil || info.Kind != c5.DocumentEvidence || info.Series != c5.SeriesFinding {
		t.Fatalf("%+v %v", info, err)
	}
	var f finding.Finding
	_ = json.Unmarshal(doc, &f)
	bad := f
	bad.Class = finding.Confirmed // confirmed on an operator identity
	badDoc, _ := json.Marshal(bad)
	for name, tc := range map[string]struct {
		doc     []byte
		capture *c5.Capture
	}{
		"capture":  {doc, &c5.Capture{SHA256: digest([]byte("x")), Bytes: []byte("x")}},
		"indented": {append([]byte(" "), doc...), nil},
		"invalid":  {badDoc, nil},
	} {
		if _, err := ConfigDocuments(tc.doc, tc.capture); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// A mismatch on an asset no read has confirmed is kept with no latest-read
// part, and the matcher gets it under the operator identity (C1 on #458)
// until the declaration changes (C4 on #459).
func TestFindingsOperatorMismatch(t *testing.T) {
	k := newAdvKey(t)
	n := newAdvNode(t, k.anchor("active"))
	n.startWith(answering(mismatchRun(t, invB)))
	n.put(k.sign(findPayload(t, 1)))
	n.step()
	n.s.RunOnce(bg, 0)
	_, reads := identityRecords(t, n.r, relayID)
	if len(reads) != 1 || reads[0].InvocationID != "" || reads[0].ReadAt != "" || reads[0].Mismatch == nil ||
		reads[0].Mismatch.InvocationID != invB || reads[0].Mismatch.FID != mismatchFID {
		t.Fatalf("identity reads %+v", reads)
	}
	n.startWith(nil)
	fs, err := n.s.findingsOf(bg, relayID)
	if err != nil {
		t.Fatal(err)
	}
	in, _, err := n.s.matcherInput(bg, relayID, fs)
	if err != nil || in.Identity.Source != finding.Operator || in.LatestMismatch == nil || in.LatestMismatch.ID != invB || in.MismatchFID != mismatchFID {
		t.Fatalf("input after a restart %+v, %v", in, err)
	}
	if id := n.st.Snapshot("x").Identity[relayID]; id.LastRead != nil || id.Mismatch == nil || id.Mismatch.InvocationID != invB {
		t.Fatalf("identity status %+v", id)
	}
	// A changed declaration clears it (C4 on #459).
	at := n.nc.Assets[0]["attributes"].([]any)[3].(map[string]any)
	at["value"] = "SEL-751-R400-V0-Z104101-D20260910"
	at["observations"].([]any)[0].(map[string]any)["value"] = at["value"]
	c, err := ParseConfig(n.nc.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	n.cfg = c
	n.startWith(nil)
	fs, _ = n.s.findingsOf(bg, relayID)
	if in, _, err = n.s.matcherInput(bg, relayID, fs); err != nil || in.LatestMismatch != nil || in.MismatchFID != "" {
		t.Fatalf("input after the declaration changed %+v, %v", in, err)
	}
	// A document with neither part is refused.
	if _, err := decodeIdentityRead([]byte(`{"schema":"` + IdentityReadSchema + `","asset_id":"` + relayID + `"}`)); err == nil {
		t.Fatal("an identity read with no read and no mismatch was accepted")
	}
}
