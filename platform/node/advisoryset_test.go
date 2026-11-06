package node

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"otsec.local/otsec/contracts/advisory"
	"otsec.local/otsec/contracts/advisory/advisorytest"
	"otsec.local/otsec/contracts/audit"
	c5 "otsec.local/otsec/contracts/store"
	"otsec.local/otsec/platform/node/nodeconfigtest"
	"otsec.local/otsec/platform/store"
)

// advEntry is one valid release entry.
func advEntry(id, title string) advisory.Entry {
	return advisory.Entry{
		ID: id, Title: title,
		Sources: []advisory.Source{{Kind: advisory.SourceOther, Ref: "node test", Published: "2026-11-05"}},
		Affected: []advisory.Affected{{Vendor: "SEL", Product: "SEL-751", Scheme: advisory.SchemeSELFID,
			Ranges: []advisory.Range{{Introduced: "R300-V0", Fixed: "R300-V3"}}}},
	}
}

// advPayload is a set's payload. entries above 1 pads it with distinct
// entries whose titles are at the bound, to make a large set.
func advPayload(t *testing.T, setID string, version uint64, purpose advisory.Purpose, entries int) []byte {
	t.Helper()
	s := advisory.Set{Contract: advisory.Identifier, SetID: setID, Version: version, IssuedAt: "2026-11-05T00:00:00Z",
		Purpose: purpose, Publisher: "node tests"}
	for i := range entries {
		s.Entries = append(s.Entries, advEntry(fmt.Sprintf("adv-%04d", i), strings.Repeat("t", advisory.MaxTitleBytes)))
	}
	if purpose == advisory.PurposeTest {
		for i := range s.Entries {
			s.Entries[i].TestOnly = true
		}
	}
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := advisory.Decode(b); err != nil {
		t.Fatalf("the test's own set is invalid: %v", err)
	}
	return b
}

func (k advKey) sign(payload []byte) []byte { return advisorytest.Sign(k.priv, payload) }

// bigEntries makes a payload of about 1 MB: its envelope is about 1.36 MB,
// under MaxEnvelopeBytes, so three fit under item3Quota and four do not.
const bigEntries = 2040

type advNode struct {
	t   *testing.T
	nc  *nodeconfigtest.Config
	cfg *Config
	dir string
	r   *Runtime
	st  *Status
	s   *Scheduler
}

// newAdvNode starts a node with both switches on and anchors.
func newAdvNode(t *testing.T, anchors ...nodeconfigtest.AdvisoryAnchor) *advNode {
	t.Helper()
	b, dir, nc, err := item3Node(t, func(nc *nodeconfigtest.Config) {
		nc.Asset = &struct{}{}
		nc.Applicability = &nodeconfigtest.Applicability{Anchors: anchors}
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CreateDir(nc.TLSDir, ""); err != nil {
		t.Fatal(err)
	}
	lockTLS(t, nc)
	locked := *nc
	t.Cleanup(func() { locked.UnlockTLS() })
	c, err := ParseConfig(b)
	if err != nil {
		t.Fatal(err)
	}
	n := &advNode{t: t, nc: nc, cfg: c, dir: dir}
	n.startNode()
	return n
}

func (n *advNode) startNode() {
	n.r, n.st, _ = start(n.t, n.cfg, n.dir)
	n.s = newScheduler(n.t, n.r, nil)
	n.t.Cleanup(func() { n.r.Close() })
}

// restart closes the node and starts it on the same store, with anchors if
// any are given.
func (n *advNode) restart(anchors ...nodeconfigtest.AdvisoryAnchor) {
	n.t.Helper()
	if err := n.r.Close(); err != nil {
		n.t.Fatal(err)
	}
	if len(anchors) > 0 {
		n.nc.Applicability.Anchors = anchors
		c, err := ParseConfig(n.nc.Bytes())
		if err != nil {
			n.t.Fatal(err)
		}
		n.cfg = c
	}
	n.startNode()
}

func (n *advNode) put(file []byte) { writeAdminBytes(n.t, n.nc, AdvisorySetFile, file) }

func (n *advNode) step() { n.s.stepAdvisory(bg) }

func (n *advNode) stored() []c5.Stored {
	n.t.Helper()
	got, err := n.r.Store(AdvisoryStream).Read(bg, AdvisoryStream, 0, 100)
	if err != nil {
		n.t.Fatal(err)
	}
	return got
}

func (n *advNode) records(action audit.Action) []*audit.Record {
	var out []*audit.Record
	for _, rec := range auditRecords(n.t, n.r) {
		if rec.Action == action {
			out = append(out, rec)
		}
	}
	return out
}

func (n *advNode) inUse() *AdvisorySetStatus {
	a := n.st.Snapshot("x").Applicability
	if a == nil {
		n.t.Fatal("no applicability section in status")
	}
	return a.SetInUse
}

func (n *advNode) alarms(code string) int {
	k := 0
	for _, a := range n.st.Snapshot("x").Alarms {
		if a.Code == code {
			k++
		}
	}
	return k
}

func sumHex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// A set is stored as the file's exact bytes and comes into use once its
// advisory.set_installed is in the chain; the same set again records
// nothing; a newer one replaces it and names the version it replaced; a
// restart finds the newest from the store and the chain.
func TestAdvisorySetInstalls(t *testing.T) {
	k := newAdvKey(t)
	n := newAdvNode(t, k.anchor("active"))
	if n.inUse() != nil || n.alarms(AlarmApplicabilityNoSet) != 1 {
		t.Fatalf("a new node: set in use %+v, applicability-no-set raised %d times", n.inUse(), n.alarms(AlarmApplicabilityNoSet))
	}
	p1 := advPayload(t, "otsec-sel", 1, advisory.PurposeRelease, 1)
	f1 := k.sign(p1)
	n.put(f1)
	n.step()
	n.step()
	got := n.stored()
	if len(got) != 1 || string(got[0].Event) != string(f1) {
		t.Fatalf("stored %d sets, or not the file's bytes", len(got))
	}
	inst := n.records(audit.ActionAdvisorySetInstalled)
	if len(inst) != 1 {
		t.Fatalf("%d advisory.set_installed records", len(inst))
	}
	a := inst[0].Advisory
	if a.SetID != "otsec-sel" || a.Version != 1 || a.KeyID != k.id || a.PayloadSHA256 != sumHex(p1) || a.PreviousVersion != 0 || a.IssuedAt != "2026-11-05T00:00:00Z" {
		t.Fatalf("installed record %+v", a)
	}
	if u := n.inUse(); u == nil || u.Version != 1 || u.PayloadSHA256 != sumHex(p1) || u.KeyID != k.id {
		t.Fatalf("set in use %+v", u)
	}

	p2 := advPayload(t, "otsec-sel", 2, advisory.PurposeRelease, 2)
	n.put(k.sign(p2))
	n.step()
	inst = n.records(audit.ActionAdvisorySetInstalled)
	if len(n.stored()) != 2 || len(inst) != 2 || inst[1].Advisory.Version != 2 || inst[1].Advisory.PreviousVersion != 1 {
		t.Fatalf("second set: %d stored, records %d", len(n.stored()), len(inst))
	}
	if u := n.inUse(); u == nil || u.Version != 2 {
		t.Fatalf("set in use %+v", u)
	}

	n.restart()
	if u := n.inUse(); u == nil || u.Version != 2 || u.PayloadSHA256 != sumHex(p2) {
		t.Fatalf("after a restart, set in use %+v", u)
	}
	n.step()
	if len(n.records(audit.ActionAdvisorySetInstalled)) != 2 || len(n.stored()) != 2 || n.alarms(AlarmApplicabilityNoSet) != 0 {
		t.Fatal("a restart wrote a record or stored a set")
	}
}

// Each of C11's refusals stores nothing, leaves the set in use, and is
// recorded and raised once per file hash, across ticks and a restart.
func TestAdvisorySetRefusals(t *testing.T) {
	k, other, revoked := newAdvKey(t), newAdvKey(t), newAdvKey(t)
	n := newAdvNode(t, k.anchor("active"), revoked.anchor("revoked"))
	p3 := advPayload(t, "otsec-sel", 3, advisory.PurposeRelease, 1)
	n.put(k.sign(p3))
	n.step()
	if u := n.inUse(); u == nil || u.Version != 3 {
		t.Fatalf("set in use %+v", u)
	}

	badSig := k.sign(advPayload(t, "otsec-sel", 4, advisory.PurposeRelease, 1))
	var env advisory.Envelope
	if err := json.Unmarshal(badSig, &env); err != nil {
		t.Fatal(err)
	}
	env.Signature[0] ^= 1
	badSig, _ = json.Marshal(env)

	cases := []struct {
		name string
		file []byte
		code advisory.Code
	}{
		{"malformed", []byte("not an envelope"), advisory.Malformed},
		{"unknown key", other.sign(advPayload(t, "otsec-sel", 4, advisory.PurposeRelease, 1)), advisory.UnknownKey},
		{"revoked key", revoked.sign(advPayload(t, "otsec-sel", 4, advisory.PurposeRelease, 1)), advisory.RevokedKey},
		{"bad signature", badSig, advisory.BadSignature},
		{"wrong set", k.sign(advPayload(t, "other-set", 4, advisory.PurposeRelease, 1)), advisory.WrongSet},
		{"older version", k.sign(advPayload(t, "otsec-sel", 2, advisory.PurposeRelease, 1)), advisory.OlderVersion},
		{"same version differs", k.sign(advPayload(t, "otsec-sel", 3, advisory.PurposeRelease, 2)), advisory.SameVersionDiffers},
	}
	if !advisoryTestBuild {
		cases = append(cases, struct {
			name string
			file []byte
			code advisory.Code
		}{"test set", k.sign(advPayload(t, "otsec-sel", 4, advisory.PurposeTest, 1)), advisory.TestSet})
	}
	for _, tc := range cases {
		n.put(tc.file)
		n.step()
		n.step()
	}
	n.restart()
	for _, tc := range cases {
		n.put(tc.file)
		n.step()
	}
	refused := n.records(audit.ActionAdvisorySetRefused)
	if len(refused) != len(cases) {
		t.Fatalf("%d advisory.set_refused records for %d refused files", len(refused), len(cases))
	}
	for i, tc := range cases {
		r := refused[i]
		if r.ReasonCode != string(tc.code) || r.Advisory.FileSHA256 != sumHex(tc.file) {
			t.Errorf("%s: record %s for %s, want %s for %s", tc.name, r.ReasonCode, r.Advisory.FileSHA256, tc.code, sumHex(tc.file))
		}
	}
	if len(n.stored()) != 1 || len(n.records(audit.ActionAdvisorySetInstalled)) != 1 {
		t.Fatal("a refused set was stored or installed")
	}
	if u := n.inUse(); u == nil || u.Version != 3 {
		t.Fatalf("set in use after refusals %+v", u)
	}
	if got := count(healthTypes(t, n.r), HealthAdvisorySetRefused); got != len(cases) {
		t.Fatalf("%d refusal health events, want one per file", got)
	}
}

// At every start the newest stored set is verified again against the anchors
// pinned now (D4-53). A set whose key is revoked is not used, no older set is
// used in its place, and the floor stays, so the next set must be newer.
func TestAdvisorySetReverifiedAtStart(t *testing.T) {
	k, k2 := newAdvKey(t), newAdvKey(t)
	n := newAdvNode(t, k.anchor("active"), k2.anchor("active"))
	n.put(k2.sign(advPayload(t, "otsec-sel", 1, advisory.PurposeRelease, 1)))
	n.step()
	f2 := k.sign(advPayload(t, "otsec-sel", 2, advisory.PurposeRelease, 1))
	n.put(f2)
	n.step()
	if u := n.inUse(); u == nil || u.Version != 2 {
		t.Fatalf("set in use %+v", u)
	}

	n.restart(k.anchor("revoked"), k2.anchor("active"))
	if u := n.inUse(); u != nil {
		t.Fatalf("a set whose key is revoked is in use: %+v", u)
	}
	if n.alarms(AlarmAdvisorySetRefused) != 1 || n.alarms(AlarmApplicabilityNoSet) != 1 {
		t.Fatalf("alarms: refused %d, no set %d", n.alarms(AlarmAdvisorySetRefused), n.alarms(AlarmApplicabilityNoSet))
	}
	if l := n.st.Snapshot("x").Applicability.LastRefusal; l == nil || l.Code != string(advisory.RevokedKey) || l.FileSHA256 != sumHex(f2) {
		t.Fatalf("last refusal %+v", l)
	}
	// The floor is version 2: a set at version 1, validly signed, is older.
	older := k2.sign(advPayload(t, "otsec-sel", 1, advisory.PurposeRelease, 2))
	n.put(older)
	n.step()
	if r := n.records(audit.ActionAdvisorySetRefused); len(r) != 1 || r[0].ReasonCode != string(advisory.OlderVersion) {
		t.Fatalf("refusals %+v", r)
	}
	if n.inUse() != nil {
		t.Fatal("an older set came into use")
	}
	n.put(k2.sign(advPayload(t, "otsec-sel", 3, advisory.PurposeRelease, 1)))
	n.step()
	inst := n.records(audit.ActionAdvisorySetInstalled)
	if u := n.inUse(); u == nil || u.Version != 3 || inst[len(inst)-1].Advisory.PreviousVersion != 2 {
		t.Fatalf("a newer set did not come into use: %+v", u)
	}
}

// A crash between the set's commit and its advisory.set_installed is
// repaired at start: the set is verified, then the record is written, and
// only then is the set in use (the note section 3, D4-26's order). A set
// that no longer verifies gets no record.
func TestAdvisorySetInstallRepairedAtStart(t *testing.T) {
	k := newAdvKey(t)
	n := newAdvNode(t, k.anchor("active"))
	f1 := k.sign(advPayload(t, "otsec-sel", 1, advisory.PurposeRelease, 1))
	if _, err := n.s.storeItem3(bg, AdvisoryStream, f1, nil); err != nil {
		t.Fatal(err)
	}
	if len(n.records(audit.ActionAdvisorySetInstalled)) != 0 {
		t.Fatal("storeItem3 wrote an audit record")
	}
	n.restart()
	inst := n.records(audit.ActionAdvisorySetInstalled)
	if len(inst) != 1 || inst[0].Advisory.Version != 1 || inst[0].Advisory.PreviousVersion != 0 {
		t.Fatalf("installation records %d", len(inst))
	}
	if u := n.inUse(); u == nil || u.Version != 1 {
		t.Fatalf("set in use %+v", u)
	}
	n.restart()
	if len(n.records(audit.ActionAdvisorySetInstalled)) != 1 {
		t.Fatal("a second start wrote the record again")
	}

	// A stored set whose key is no longer pinned is not recorded.
	k2 := newAdvKey(t)
	f2 := k.sign(advPayload(t, "otsec-sel", 2, advisory.PurposeRelease, 1))
	if _, err := n.s.storeItem3(bg, AdvisoryStream, f2, nil); err != nil {
		t.Fatal(err)
	}
	n.restart(k2.anchor("active"))
	if len(n.records(audit.ActionAdvisorySetInstalled)) != 1 || n.inUse() != nil {
		t.Fatalf("an unverified set was recorded or used: %+v", n.inUse())
	}
}

// The item 3 ceiling (C5 0.8 section 5, C1 on #444): a set that would leave
// the configuration class above the ceiling is not installed, the set in use
// stays, no advisory.set_refused is written, and advisory-set-no-room is
// raised once per file hash. asset-store-full is raised once per crossing:
// a write that fits ends it, and the next refusal raises it again. A start
// with more stored sets than the floor counts raises advisory-sets-over-floor
// and still runs.
func TestAdvisoryCeiling(t *testing.T) {
	k := newAdvKey(t)
	n := newAdvNode(t, k.anchor("active"))
	ceiling := n.cfg.Item3Ceiling()
	if ceiling != item3Quota {
		t.Fatalf("ceiling %d, want the quota %d with no configuration read", ceiling, item3Quota)
	}
	var big [][]byte
	for v := uint64(1); v <= 4; v++ {
		f := k.sign(advPayload(t, "otsec-sel", v, advisory.PurposeRelease, bigEntries))
		if len(f) > advisory.MaxEnvelopeBytes || len(f) < 1<<20 {
			t.Fatalf("set %d is %d bytes", v, len(f))
		}
		big = append(big, f)
	}
	for _, f := range big[:3] {
		n.put(f)
		n.step()
	}
	if u := n.inUse(); u == nil || u.Version != 3 {
		t.Fatalf("three large sets fit under %d bytes: in use %+v", ceiling, u)
	}
	n.put(big[3])
	n.step()
	n.step()
	n.step()
	if u := n.inUse(); u == nil || u.Version != 3 || len(n.stored()) != 3 {
		t.Fatalf("a set past the ceiling was installed: in use %+v, %d stored", u, len(n.stored()))
	}
	if len(n.records(audit.ActionAdvisorySetRefused)) != 0 {
		t.Fatal("a storage refusal wrote advisory.set_refused")
	}
	if n.alarms(AlarmAdvisorySetNoRoom) != 1 || n.alarms(AlarmAssetStoreFull) != 1 {
		t.Fatalf("no-room raised %d times, store-full %d", n.alarms(AlarmAdvisorySetNoRoom), n.alarms(AlarmAssetStoreFull))
	}
	snap := n.st.Snapshot("x")
	if l := snap.Applicability.LastRefusal; l == nil || l.Code != AlarmAdvisorySetNoRoom || l.Version != 4 || l.SetID != "otsec-sel" || l.FileSHA256 != sumHex(big[3]) {
		t.Fatalf("last refusal %+v", l)
	}
	if as := snap.AssetStore; as == nil || !as.Full || as.Refused[c5.SeriesAdvisorySet] == 0 || as.CeilingBytes != ceiling {
		t.Fatalf("asset store %+v", as)
	}
	if count(healthTypes(t, n.r), HealthAdvisorySetNoRoom) != 1 || count(healthTypes(t, n.r), HealthAssetStoreFull) != 1 {
		t.Fatal("the health events are not one each")
	}

	// A small set fits: it installs and ends the crossing.
	n.put(k.sign(advPayload(t, "otsec-sel", 5, advisory.PurposeRelease, 1)))
	n.step()
	if u := n.inUse(); u == nil || u.Version != 5 || n.st.Snapshot("x").AssetStore.Full {
		t.Fatalf("a set that fits: in use %+v, store %+v", u, n.st.Snapshot("x").AssetStore)
	}
	n.put(k.sign(advPayload(t, "otsec-sel", 6, advisory.PurposeRelease, bigEntries)))
	n.step()
	if n.alarms(AlarmAssetStoreFull) != 2 {
		t.Fatalf("a second crossing raised asset-store-full %d times in all", n.alarms(AlarmAssetStoreFull))
	}

	// Four sets are stored, two beyond the floor's two.
	n.restart()
	if n.alarms(AlarmAdvisorySetsOverFloor) != 1 {
		t.Fatal("no advisory-sets-over-floor at start")
	}
	if u := n.inUse(); u == nil || u.Version != 5 {
		t.Fatalf("the node did not start with its set: %+v", u)
	}
}

// The floor is the chain's newest installation whatever the store holds
// (C3 on #452): with the configuration database lost and the chain kept, no
// set is in use, a validly signed older set is refused as older_version,
// and only a newer one installs. A refusal record carries only checked
// fields: no detail (C3, the C11 table).
func TestAdvisoryFloorHoldsWithoutTheStoredSet(t *testing.T) {
	k := newAdvKey(t)
	n := newAdvNode(t, k.anchor("active"))
	n.put(k.sign(advPayload(t, "otsec-sel", 1, advisory.PurposeRelease, 1)))
	n.step()
	n.put(k.sign(advPayload(t, "otsec-sel", 2, advisory.PurposeRelease, 1)))
	n.step()
	if err := n.r.Close(); err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []string{"", "-wal", "-shm"} {
		if err := os.Remove(filepath.Join(n.cfg.Store.Dir, string(ConfigDB)+".db"+suffix)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			t.Fatal(err)
		}
	}
	n.startNode()
	if len(n.stored()) != 0 || n.inUse() != nil {
		t.Fatalf("after the loss: %d stored, in use %+v", len(n.stored()), n.inUse())
	}
	older := k.sign(advPayload(t, "otsec-sel", 1, advisory.PurposeRelease, 2))
	n.put(older)
	n.step()
	r := n.records(audit.ActionAdvisorySetRefused)
	if len(r) != 1 || r[0].ReasonCode != string(advisory.OlderVersion) || r[0].Detail != "" {
		t.Fatalf("refusals %+v", r)
	}
	n.put(k.sign(advPayload(t, "otsec-sel", 3, advisory.PurposeRelease, 1)))
	n.step()
	inst := n.records(audit.ActionAdvisorySetInstalled)
	if u := n.inUse(); u == nil || u.Version != 3 || inst[len(inst)-1].Advisory.PreviousVersion != 2 {
		t.Fatalf("in use %+v", u)
	}
}
