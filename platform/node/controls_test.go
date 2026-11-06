package node

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"otsec.local/otsec/contracts/advisory"
	"otsec.local/otsec/contracts/audit"
	"otsec.local/otsec/contracts/finding"
	c5 "otsec.local/otsec/contracts/store"
	"otsec.local/otsec/platform/node/nodeconfigtest"
)

// controlPayload is a set with one entry in the relay's declared range,
// mitigated by a control that blocks tcp/80.
func controlPayload(t *testing.T) []byte {
	t.Helper()
	e := advEntry("adv-ctl", "blocked by a control")
	e.Affected[0].Ranges = []advisory.Range{{Introduced: "R501-V0", Fixed: "R501-V9"}}
	e.Mitigations = []advisory.Item{{Name: "block-http", Kind: advisory.KindControl, Key: "tcp/80", Op: advisory.OpPresent}}
	s := advisory.Set{Contract: advisory.Identifier, SetID: "otsec-sel", Version: 1, IssuedAt: "2026-11-05T00:00:00Z",
		Purpose: advisory.PurposeRelease, Publisher: "node tests", Entries: []advisory.Entry{e}}
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := advisory.Decode(b); err != nil {
		t.Fatalf("the test's own set is invalid: %v", err)
	}
	return b
}

// withControls restarts the node with the relay's controls set to keys (nil
// removes the entry).
func (n *advNode) withControls(keys []string) {
	n.t.Helper()
	n.nc.AssetControls = nil
	if keys != nil {
		n.nc.AssetControls = []nodeconfigtest.AssetControls{{AssetID: relayID, Controls: keys}}
	}
	c, err := ParseConfig(n.nc.Bytes())
	if err != nil {
		n.t.Fatal(err)
	}
	n.cfg = c
	n.startWith(nil)
}

// controlRecords are the asset_controls_declared policy.apply records, with
// their seqs.
func (n *advNode) controlRecords() (details []string, seqs []c5.Seq) {
	n.t.Helper()
	got, err := n.r.Store(AuditStream).Read(bg, AuditStream, 0, 1000)
	if err != nil {
		n.t.Fatal(err)
	}
	for _, st := range got {
		rec, err := audit.ParseRecord(st.Event)
		if err != nil {
			n.t.Fatal(err)
		}
		if rec.Action == audit.ActionPolicyApply && rec.ReasonCode == ReasonAssetControlsDeclared {
			details, seqs = append(details, rec.Detail), append(seqs, st.Key.Seq)
		}
	}
	return details, seqs
}

func sumOf(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// A recorded control is cited by its policy.apply record, with source
// operator, and makes the finding mitigated (D4-56). The record's hash is
// over the keys in byte order, each with an LF, and its detail names the
// keys; it is reused while the list is unchanged, after a prune too, and a
// changed list writes a new one and revises the finding.
func TestControlsRecordedAndCited(t *testing.T) {
	k := newAdvKey(t)
	n := newAdvNode(t, k.anchor("active"))
	n.withControls([]string{"udp/161", "tcp/80"})
	n.put(k.sign(controlPayload(t)))
	n.step()

	details, seqs := n.controlRecords()
	want := fmt.Sprintf("asset %s controls sha256:%s keys tcp/80,udp/161", relayID, sumOf("tcp/80\nudp/161\n"))
	if len(details) != 1 || details[0] != want {
		t.Fatalf("controls records %q, want one %q", details, want)
	}
	ref := fmt.Sprintf("audit:%s:%d", n.cfg.NodeID, seqs[0])
	fs := n.findings()
	if len(fs) != 1 || fs[0].Class != finding.Mitigated || len(fs[0].Mitigations) != 1 {
		t.Fatalf("findings %+v", fs)
	}
	m := fs[0].Mitigations[0]
	if !m.OperatorAttested || len(m.Evidence) != 1 || m.Evidence[0].Source != finding.Operator || m.Evidence[0].ID != ref {
		t.Fatalf("mitigation %+v, want operator evidence %s", m, ref)
	}

	// Unchanged, through a restart and a prune of the chain: reused.
	n.pruneThrough(n.lastAuditSeq())
	n.withControls([]string{"tcp/80", "udp/161"})
	n.step()
	if d, _ := n.controlRecords(); len(d) != 0 {
		t.Fatalf("the unchanged list was recorded again: %q", d)
	}
	if fs := n.findings(); len(fs) != 1 {
		t.Fatalf("an unchanged list revised the finding: %+v", fs)
	}
	b, err := os.ReadFile(filepath.Join(n.cfg.Store.Dir, DeclaredIdentitiesFileName))
	if err != nil || !strings.Contains(string(b), `"controls"`) {
		t.Fatalf("%s: %s, %v", DeclaredIdentitiesFileName, b, err)
	}

	// Emptied: a new record naming no keys, and the finding is no longer
	// mitigated.
	n.withControls([]string{})
	n.step()
	details, _ = n.controlRecords()
	want = fmt.Sprintf("asset %s controls sha256:%s keys none", relayID, sumOf(""))
	if len(details) != 1 || details[0] != want {
		t.Fatalf("controls records %q, want one %q", details, want)
	}
	if fs := n.findings(); len(fs) != 2 || fs[1].Class == finding.Mitigated || fs[1].Revision != 2 {
		t.Fatalf("findings after the list was emptied %+v", fs)
	}
}

// A list withdrawn from the file is recorded as none, so the chain shows it.
func TestControlsWithdrawn(t *testing.T) {
	k := newAdvKey(t)
	n := newAdvNode(t, k.anchor("active"))
	n.withControls([]string{"tcp/80"})
	n.withControls(nil)
	details, _ := n.controlRecords()
	if len(details) != 2 || !strings.HasSuffix(details[1], " keys none") {
		t.Fatalf("controls records %q", details)
	}
}

// A record that cannot be written raises asset-controls-not-recorded, and
// the asset is evaluated with no controls: an unrecorded control is never
// cited.
func TestControlsNotRecorded(t *testing.T) {
	k := newAdvKey(t)
	n := newAdvNode(t, k.anchor("active"))
	n.withControls([]string{})
	n.put(k.sign(controlPayload(t)))
	n.step()
	used, err := n.r.Store(AuditStream).ClassBytes(bg, c5.ClassAudit)
	if err != nil {
		t.Fatal(err)
	}
	n.nc.Store.Quotas["audit"] = used + 1
	n.withControls([]string{"tcp/80"})
	n.step()
	if countAlarms(n.st, AlarmControlsNotRecorded) != 1 {
		t.Fatalf("alarms %+v", n.st.Snapshot("x").Alarms)
	}
	for _, f := range n.findings() {
		if f.Class == finding.Mitigated || len(f.Mitigations) != 0 {
			t.Fatalf("an unrecorded control was cited: %+v", f)
		}
	}
}

// asset_controls is checked at load (D4-56).
func TestControlsRefused(t *testing.T) {
	many := make([]string, MaxAssetControls+1)
	for i := range many {
		many[i] = fmt.Sprintf("tcp/%d", i+1)
	}
	for _, tc := range []struct {
		name, want string
		entries    []nodeconfigtest.AssetControls
	}{
		{"an unknown asset", "is not a configured asset", []nodeconfigtest.AssetControls{{AssetID: "00000000-0000-4000-8000-000000000000", Controls: []string{"tcp/80"}}}},
		{"an asset twice", "is listed twice", []nodeconfigtest.AssetControls{{AssetID: relayID, Controls: []string{"tcp/80"}}, {AssetID: relayID, Controls: []string{"udp/161"}}}},
		{"port 0", `"tcp/0" is not`, []nodeconfigtest.AssetControls{{AssetID: relayID, Controls: []string{"tcp/0"}}}},
		{"port 65536", `"udp/65536" is not`, []nodeconfigtest.AssetControls{{AssetID: relayID, Controls: []string{"udp/65536"}}}},
		{"another protocol", `"sctp/80" is not`, []nodeconfigtest.AssetControls{{AssetID: relayID, Controls: []string{"sctp/80"}}}},
		{"a key twice", "tcp/80 is listed twice", []nodeconfigtest.AssetControls{{AssetID: relayID, Controls: []string{"tcp/80", "tcp/80"}}}},
		{"17 keys", "17 controls, at most 16", []nodeconfigtest.AssetControls{{AssetID: relayID, Controls: many}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := item3Config(t, func(nc *nodeconfigtest.Config) { nc.AssetControls = tc.entries })
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want %q, got %v", tc.want, err)
			}
		})
	}
	if _, err := item3Config(t, func(nc *nodeconfigtest.Config) {
		nc.AssetControls = []nodeconfigtest.AssetControls{{AssetID: relayID, Controls: many[:MaxAssetControls]}}
	}); err != nil {
		t.Fatalf("16 keys refused: %v", err)
	}
}
