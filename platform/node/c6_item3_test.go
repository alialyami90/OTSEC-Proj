package node

// C6's cases for item 3 part 1 (#452): the ceiling with configuration
// monitoring on, and a refusal that depends on the anchors pinned. Evidence
// class: simulated (the node on a temporary store, a fake collector, no
// device).

import (
	"testing"

	"otsec.local/otsec/contracts/adapter"
	"otsec.local/otsec/contracts/advisory"
	"otsec.local/otsec/contracts/audit"
	"otsec.local/otsec/contracts/config"
	c5 "otsec.local/otsec/contracts/store"
	"otsec.local/otsec/platform/node/nodeconfigtest"
	"otsec.local/otsec/platform/store"
)

// c6CeilingNode starts a node that reads the relay's configuration, with
// asset and applicability on and the configuration quota at exactly the
// floor: the configuration module's 16 records plus item 3's terms.
func c6CeilingNode(t *testing.T, k advKey) *advNode {
	t.Helper()
	mod := func(quota int64) func(*nodeconfigtest.Config) {
		return func(nc *nodeconfigtest.Config) {
			withConfigRead(t, nil)(nc)
			nc.Asset = &struct{}{}
			nc.Applicability = &nodeconfigtest.Applicability{Anchors: []nodeconfigtest.AdvisoryAnchor{k.anchor("active")}}
			nc.Store.Quotas["configuration"] = quota
		}
	}
	b, _, _, err := item3Node(t, mod(1<<30))
	if err != nil {
		t.Fatal(err)
	}
	c, err := ParseConfig(b)
	if err != nil {
		t.Fatal(err)
	}
	floor := c.configModuleFloor() + c.item3Floor()
	b, dir, nc, err := item3Node(t, mod(floor))
	if err != nil {
		t.Fatalf("a quota at the floor (%d bytes) is refused: %v", floor, err)
	}
	if err := store.CreateDir(nc.TLSDir, ""); err != nil {
		t.Fatal(err)
	}
	lockTLS(t, nc)
	locked := *nc
	t.Cleanup(func() { locked.UnlockTLS() })
	if c, err = ParseConfig(b); err != nil {
		t.Fatal(err)
	}
	n := &advNode{t: t, nc: nc, cfg: c, dir: dir}
	n.startNode()
	return n
}

// configSnapshot is the relay's configuration snapshot from the fixture
// "ok", with its transcript as the capture, as the configuration read
// stores it.
func (n *advNode) configSnapshot() ([]byte, *c5.Capture) {
	n.t.Helper()
	res, err := adapter.DecodeResult(contractFile(n.t, "adapter/testdata/config/results/valid/ok.json"))
	if err != nil {
		n.t.Fatal(err)
	}
	inv := adapter.Invocation{InvocationID: okInvocation, PrincipalRef: "sch-cfg", AssetID: relayID, EndpointID: "port1-telnet",
		ProfileID: "sel-751-ascii", OperationID: "sel.config.read_all", CredentialRef: nodeconfigtest.TestCredentialRef}
	s, err := config.FromResult(config.RuleSEL751SHO.ID, n.r.commands, inv, res)
	if err != nil {
		n.t.Fatal(err)
	}
	doc, err := s.Encode()
	if err != nil {
		n.t.Fatal(err)
	}
	return doc, &c5.Capture{SHA256: res.Transcript.SHA256, Bytes: res.Transcript.Data}
}

func (n *advNode) classBytes() int64 {
	n.t.Helper()
	b, err := n.r.Store(AdvisoryStream).ClassBytes(bg, c5.ClassConfiguration)
	if err != nil {
		n.t.Fatal(err)
	}
	return b
}

// The ceiling leaves configuration monitoring its room (C1 on #444, C5 0.8
// section 5). It is the quota less the configuration module's own floor
// terms. Configuration snapshots count against it, and are not refused by
// it: they go on to the full quota while every item 3 write is refused.
func TestC6Item3CeilingLeavesConfigurationItsRoom(t *testing.T) {
	k := newAdvKey(t)
	n := c6CeilingNode(t, k)
	quota := n.cfg.Store.Quotas[string(c5.ClassConfiguration)]
	ceiling := n.cfg.Item3Ceiling()
	if want := quota - ConfigQuotaFloorRecords*ConfigRecordBytes; ceiling != want {
		t.Fatalf("ceiling %d, want the quota %d less 16 configuration records: %d", ceiling, quota, want)
	}

	// Item 3 fills to near its ceiling: three large sets fit, a fourth
	// does not.
	for v := uint64(1); v <= 4; v++ {
		n.put(k.sign(advPayload(t, "otsec-sel", v, advisory.PurposeRelease, bigEntries)))
		n.step()
	}
	if u := n.inUse(); u == nil || u.Version != 3 || n.alarms(AlarmAssetStoreFull) != 1 {
		t.Fatalf("in use %+v, asset-store-full %d", u, n.alarms(AlarmAssetStoreFull))
	}

	// Configuration snapshots go past the ceiling: none is refused.
	doc, capture := n.configSnapshot()
	writes := 0
	for n.classBytes() <= ceiling+(1<<20) {
		if writes++; writes > 2000 {
			t.Fatal("the configuration class did not grow")
		}
		if _, err := n.s.storeConfig(bg, ConfigStream(relayID), doc, capture); err != nil {
			t.Fatalf("configuration snapshot %d refused with the class at %d bytes, ceiling %d, quota %d: %v", writes, n.classBytes(), ceiling, quota, err)
		}
	}
	if used := n.classBytes(); used > quota {
		t.Fatalf("the class holds %d bytes, over the quota %d", used, quota)
	}

	// The class is now above the ceiling, so even a small set is refused,
	// in the same crossing.
	small := k.sign(advPayload(t, "otsec-sel", 5, advisory.PurposeRelease, 1))
	n.put(small)
	n.step()
	if u := n.inUse(); u == nil || u.Version != 3 {
		t.Fatalf("a set was installed above the ceiling: %+v", u)
	}
	if len(n.records(audit.ActionAdvisorySetRefused)) != 0 {
		t.Fatal("a storage refusal wrote advisory.set_refused")
	}
	if l := n.st.Snapshot("x").Applicability.LastRefusal; l == nil || l.Code != AlarmAdvisorySetNoRoom || l.FileSHA256 != sumHex(small) {
		t.Fatalf("last refusal %+v", l)
	}
	if n.alarms(AlarmAssetStoreFull) != 1 {
		t.Fatalf("asset-store-full raised %d times in one crossing", n.alarms(AlarmAssetStoreFull))
	}
	// And configuration monitoring still stores.
	if _, err := n.s.storeConfig(bg, ConfigStream(relayID), doc, capture); err != nil {
		t.Fatalf("a configuration snapshot was refused with item 3 full: %v", err)
	}
}

// A refusal that depends on the anchors pinned must not outlive them. A set
// signed by a key that is not pinned is refused as unknown_key. Once the key
// is pinned and the node restarted, the same file, still in place, must be
// verified again and installed: the once-per-hash rule is for the record and
// the alarm, not for the verdict.
func TestC6RefusalByAnchorsIsReverified(t *testing.T) {
	k, k2 := newAdvKey(t), newAdvKey(t)
	n := newAdvNode(t, k.anchor("active"))
	f := k2.sign(advPayload(t, "otsec-sel", 1, advisory.PurposeRelease, 1))
	n.put(f)
	n.step()
	if r := n.records(audit.ActionAdvisorySetRefused); len(r) != 1 || r[0].ReasonCode != string(advisory.UnknownKey) {
		t.Fatalf("refusals %+v", r)
	}
	n.step()
	if len(n.records(audit.ActionAdvisorySetRefused)) != 1 {
		t.Fatal("the same file was refused twice under the same anchors")
	}

	n.restart(k.anchor("active"), k2.anchor("active"))
	n.step()
	if u := n.inUse(); u == nil || u.Version != 1 || u.PayloadSHA256 == "" {
		t.Fatalf("with its key pinned, the set left in place is not in use: %+v; last refusal %+v", u, n.st.Snapshot("x").Applicability.LastRefusal)
	}
	if len(n.records(audit.ActionAdvisorySetInstalled)) != 1 {
		t.Fatal("no installation record")
	}
}
