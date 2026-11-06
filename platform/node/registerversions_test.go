package node

import (
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"otsec.local/otsec/contracts/audit"
	"otsec.local/otsec/contracts/authz"
	"otsec.local/otsec/modules/security/collectorclient"
	"otsec.local/otsec/platform/node/nodeconfigtest"
	"otsec.local/otsec/platform/store"
)

// snmpID is the SEL-2731M of the register-revision tests.
const snmpID = "5d2e8f14-7a3b-4c69-b0e1-9f4a6c2d8e75"

// mixedNode is a node with the SEL-751 (register_version 4) and a SEL-2731M
// whose profile names revision 1 in register_versions (the C5 note "a
// register revision per family", #464).
func mixedNode(t *testing.T, mod func(*nodeconfigtest.Config)) (*nodeconfigtest.Config, string, error) {
	t.Helper()
	dir := t.TempDir()
	storeDir := filepath.Join(dir, "store")
	if err := store.CreateDir(storeDir, ""); err != nil {
		t.Fatal(err)
	}
	nc := nodeconfigtest.New("site-a-node1", storeDir).AddSEL751(relayID, "", 2323, 300).AddSEL2731M(snmpID, "", 1161, 300)
	nc.Store.Quotas["configuration"] = 8 << 20
	if err := nc.WriteInstallKey(testInstallKey); err != nil {
		t.Fatal(err)
	}
	if mod != nil {
		mod(nc)
	}
	_, err := ParseConfig(nc.Bytes())
	return nc, dir, err
}

// Each run names its asset's profile's revision, in the request and in its
// collector.request audit record, and a refusal naming another revision is
// never adopted: the next run names the configured one again (C3 on #464).
func TestRegisterVersionPerProfile(t *testing.T) {
	nc, dir, err := mixedNode(t, nil)
	if err != nil {
		t.Fatal(err)
	}
	c, err := ParseConfig(nc.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	r, _, _ := start(t, c, dir)
	defer r.Close()
	var (
		mu   sync.Mutex
		sent = map[string]uint64{} // asset -> the newest request's revision
		seq  uint64
	)
	refuse := &fakeCollector{answer: func(req *authz.CollectorRequest) (collectorclient.Response, error) {
		mu.Lock()
		sent[req.Run.AssetID] = req.Run.RegisterVersion
		seq++
		n := seq
		mu.Unlock()
		return collectorclient.Response{Reply: authz.CollectorReply{Contract: authz.ContractID, RequestID: req.RequestID, Status: authz.ReplyRefused,
			Refusal: &authz.Refusal{Code: authz.RefuseRegisterVersion, Detail: "the active package is revision 7"}, CollectorSeq: n}}, nil
	}}
	s := newScheduler(t, r, refuse)
	want := map[string]uint64{relayID: 4, snmpID: 1}
	for round := range 2 {
		for i, col := range c.Schedule {
			rep := s.RunOnce(bg, i)
			if !rep.Sent || rep.Decision != authz.ReplyRefused {
				t.Fatalf("round %d, %s: %+v", round, col.ID, rep)
			}
			if got := sent[col.AssetID]; got != want[col.AssetID] {
				t.Fatalf("round %d: the run on %s named register revision %d, want %d", round, col.AssetID, got, want[col.AssetID])
			}
			recs := requestRecords(auditRecords(t, r), rep.RequestID)
			if len(recs) == 0 {
				t.Fatalf("round %d: no collector.request record for %s", round, rep.RequestID)
			}
			for _, rec := range recs {
				if rec.Action != audit.ActionCollectorRequest || rec.RegisterRevision != want[col.AssetID] {
					t.Fatalf("round %d: %s's audit record names register revision %d, want %d", round, col.AssetID, rec.RegisterRevision, want[col.AssetID])
				}
			}
		}
	}
}

// register_versions is checked at load.
func TestRegisterVersionsRefused(t *testing.T) {
	for _, tc := range []struct {
		name, want string
		mod        func(*nodeconfigtest.Config)
	}{
		{"a profile no scheduled asset uses", `names profile "sel-751-asci"`, func(nc *nodeconfigtest.Config) {
			nc.RegisterVersions["sel-751-asci"] = 4
		}},
		{"a revision of 0", `register_versions["sel-27x1-rstp"] must be at least 1`, func(nc *nodeconfigtest.Config) {
			nc.RegisterVersions[nodeconfigtest.TestSNMPProfile] = 0
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := mixedNode(t, tc.mod); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want %q, got %v", tc.want, err)
			}
		})
	}
}

// The register copy is held to the revision of the assets whose
// configuration the node reads: their profile's in register_versions when
// it is listed, not register_version.
func TestRegisterCopyFollowsItsProfile(t *testing.T) {
	c, dir := schedConfig(t, withConfigRead(t, func(nc *nodeconfigtest.Config) {
		nc.RegisterVersions = map[string]uint64{"sel-751-ascii": nc.RegisterVersion}
		nc.RegisterVersion++
	}))
	r, st, _ := start(t, c, dir)
	defer r.Close()
	if r.commands == nil || countAlarms(st, AlarmRegisterRefused) != 0 {
		t.Fatalf("the copy at its profile's revision was refused: %+v", st.Snapshot("x").Alarms)
	}

	c, dir = schedConfig(t, withConfigRead(t, func(nc *nodeconfigtest.Config) {
		nc.RegisterVersions = map[string]uint64{"sel-751-ascii": nc.RegisterVersion + 1}
	}))
	r2, st2, _ := start(t, c, dir)
	defer r2.Close()
	if r2.commands != nil || countAlarms(st2, AlarmRegisterRefused) != 1 {
		t.Fatalf("a copy not at its profile's revision loaded: %+v", st2.Snapshot("x").Alarms)
	}
}
