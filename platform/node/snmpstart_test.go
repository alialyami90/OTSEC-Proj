package node

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"otsec.local/otsec/contracts/adapter"
	c1 "otsec.local/otsec/contracts/asset"
	"otsec.local/otsec/modules/security/collectorclient"
	"otsec.local/otsec/platform/node/nodeconfigtest"
	"otsec.local/otsec/platform/store"
)

// nodeconfigtest.AddSEL2731M gives a node whose schedule is one SNMP entry,
// for C6's GT-MIB runner (P4-3-C5 deliverable 3): it loads with nothing
// else, declares what C1's example declares, and its poll stores the
// identity.
func TestAddSEL2731M(t *testing.T) {
	var example map[string]any
	if err := json.Unmarshal(readFile(t, "../../contracts/asset/testdata/valid/sel-2731m-snmpv3.json"), &example); err != nil {
		t.Fatal(err)
	}
	id := example["asset_id"].(string)
	dir := t.TempDir()
	storeDir := filepath.Join(dir, "store")
	if err := store.CreateDir(storeDir, ""); err != nil {
		t.Fatal(err)
	}
	nc := nodeconfigtest.New("site-a-node1", storeDir).AddSEL2731M(id, "", 1161, 60)
	nc.Store.Quotas["configuration"] = 8 << 20
	if err := nc.WriteInstallKey(testInstallKey); err != nil {
		t.Fatal(err)
	}
	c, err := ParseConfig(nc.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Schedule) != 1 || !c.snmpEntry(c.Schedule[0]) || c.Schedule[0].CredentialRef != nodeconfigtest.TestSNMPCredentialRef {
		t.Fatalf("schedule %+v", c.Schedule)
	}

	// Every attribute the helper declares, C1's example declares with the
	// same operator value.
	got, _ := c.Asset(id)
	b, _ := json.Marshal(example)
	want, err := c1.Decode(b)
	if err != nil {
		t.Fatal(err)
	}
	declared := func(a c1.Asset, name string) string {
		at, _ := a.Attribute(name)
		for _, ob := range at.Observations {
			if ob.EffectiveKind() == c1.Operator {
				return ob.Value
			}
		}
		return ""
	}
	for _, at := range got.Attributes {
		if v := declared(got, at.Name); v == "" || v != declared(want, at.Name) {
			t.Errorf("%s: %q, and C1's example declares %q", at.Name, v, declared(want, at.Name))
		}
	}
	if v := declared(got, c1.AttrSNMPEngineID); v != nodeconfigtest.TestSNMPEngineID {
		t.Errorf("snmp_engine_id %q", v)
	}

	r, _, _ := start(t, c, dir)
	defer r.Close()
	res, err := adapter.DecodeResult(readFile(t, "../../contracts/adapter/testdata/snmp/results/valid/ok.json"))
	if err != nil {
		t.Fatal(err)
	}
	rb, _ := json.Marshal(res)
	s := newScheduler(t, r, answering(&collectorclient.Outcome{InvocationID: res.InvocationID, Result: res, ResultJSON: rb}))
	if rep := s.RunOnce(bg, 0); rep.Outcome != "ok" || rep.Alarm != "" {
		t.Fatalf("%+v", rep)
	}
	if st := s.identityOf(bg, id); st == nil || st.doc == nil {
		t.Fatal("the poll stored no identity record")
	}
}
