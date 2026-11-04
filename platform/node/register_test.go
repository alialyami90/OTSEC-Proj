package node

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"path/filepath"
	"strings"
	"testing"

	"otsec.local/otsec/contracts/authz"
	"otsec.local/otsec/modules/security/collectorclient"
	"otsec.local/otsec/platform/node/nodeconfigtest"
)

// withConfigRead schedules a configuration read of the relay as collection 1,
// gives the node the signed register and room for the configuration floor,
// then applies mod.
func withConfigRead(t *testing.T, mod func(nc *nodeconfigtest.Config)) func(nc *nodeconfigtest.Config) {
	return func(nc *nodeconfigtest.Config) {
		nc.Store.Quotas["configuration"] = 32 << 20
		nc.Schedule = append(nc.Schedule, nodeconfigtest.Collection{ID: "sch-cfg", AssetID: relayID, Endpoint: "port1-telnet",
			Operation: "sel.config.read_all", CredentialRef: nodeconfigtest.TestCredentialRef, EverySeconds: 3600})
		addRegister(t, nc)
		if mod != nil {
			mod(nc)
		}
	}
}

func anchor(nc *nodeconfigtest.Config) map[string]any {
	return nc.Register["trust_anchors"].([]any)[0].(map[string]any)
}

// The register copy that verifies against the node's anchors, matches its
// pin and is register_version loads at start, with no alarm, and the
// configuration read is sent.
func TestRegisterCopyLoads(t *testing.T) {
	c, dir := schedConfig(t, withConfigRead(t, nil))
	r, st, _ := start(t, c, dir)
	defer r.Close()
	if r.commands == nil || countAlarms(st, AlarmRegisterRefused) != 0 {
		t.Fatalf("commands %v, alarms %+v", r.commands, st.Snapshot("x").Alarms)
	}
	if _, ok := r.commands.Run("sel.config.read_all"); !ok {
		t.Fatal("the loaded register has no sel.config.read_all run")
	}
	f := &fakeCollector{answer: func(req *authz.CollectorRequest) (collectorclient.Response, error) {
		return collectorclient.Response{Reply: authz.CollectorReply{Contract: authz.ContractID, RequestID: req.RequestID, Status: authz.ReplyRefused,
			Refusal: &authz.Refusal{Code: authz.RefuseRateLimited, Detail: "inside the floor"}, CollectorSeq: 1}}, nil
	}}
	if rep := newScheduler(t, r, f).RunOnce(bg, 1); !rep.Sent || f.n() != 1 {
		t.Fatalf("configuration read not sent: %+v", rep)
	}
}

// D4-40 item 7, conditions 1, 4 and 6: a register copy the node cannot
// load raises config-register-refused once at start, and every
// configuration read is then held without reaching the collector, while the
// asset's SER read still runs.
func TestRegisterCopyRefusedHoldsConfigurationReads(t *testing.T) {
	other := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	for name, tc := range map[string]struct {
		mod  func(nc *nodeconfigtest.Config)
		want string
	}{
		"unreadable": {func(nc *nodeconfigtest.Config) {
			nc.Register["envelope"] = filepath.Join(t.TempDir(), "missing.json")
		}, "register envelope"},
		"another payload": {func(nc *nodeconfigtest.Config) {
			sum := sha256.Sum256([]byte("another register"))
			nc.Register["payload_sha256"] = hex.EncodeToString(sum[:])
		}, "is not the pinned"},
		"signed by another key": {func(nc *nodeconfigtest.Config) {
			anchor(nc)["public_key"] = base64.StdEncoding.EncodeToString(other.Public().(ed25519.PublicKey))
		}, "signature"},
		"signing key revoked": {func(nc *nodeconfigtest.Config) {
			anchor(nc)["status"] = "revoked"
		}, "revoked"},
		"another revision": {func(nc *nodeconfigtest.Config) {
			nc.RegisterVersion = 4
		}, "is not register_version 4"},
	} {
		t.Run(name, func(t *testing.T) {
			c, dir := schedConfig(t, withConfigRead(t, tc.mod))
			r, st, _ := start(t, c, dir)
			defer r.Close()
			if r.commands != nil || countAlarms(st, AlarmRegisterRefused) != 1 {
				t.Fatalf("commands %v, alarms %+v", r.commands, st.Snapshot("x").Alarms)
			}
			for _, a := range st.Snapshot("x").Alarms {
				if a.Code == AlarmRegisterRefused && !strings.Contains(a.Detail, tc.want) {
					t.Fatalf("detail %q does not name %q", a.Detail, tc.want)
				}
			}
			f := &fakeCollector{answer: func(req *authz.CollectorRequest) (collectorclient.Response, error) {
				return collectorclient.Response{Reply: authz.CollectorReply{Contract: authz.ContractID, RequestID: req.RequestID, Status: authz.ReplyRefused,
					Refusal: &authz.Refusal{Code: authz.RefuseRateLimited, Detail: "inside the floor"}, CollectorSeq: 1}}, nil
			}}
			s := newScheduler(t, r, f)
			if rep := s.RunOnce(bg, 1); rep.Sent || rep.Alarm != AlarmRegisterRefused || f.n() != 0 {
				t.Fatalf("configuration read: %+v, %d sent", rep, f.n())
			}
			if rep := s.RunOnce(bg, 0); !rep.Sent || f.n() != 1 {
				t.Fatalf("SER read held too: %+v", rep)
			}
		})
	}
}

// The register section is required when a configuration read is scheduled,
// and its fields' forms are checked at load.
func TestRegisterCopyChecks(t *testing.T) {
	for name, tc := range map[string]struct {
		mod  func(nc *nodeconfigtest.Config)
		want string
	}{
		"missing":           {func(nc *nodeconfigtest.Config) { nc.Register = nil }, "register is required"},
		"relative envelope": {func(nc *nodeconfigtest.Config) { nc.Register["envelope"] = "register.json" }, "not an absolute path"},
		"pin in upper case": {func(nc *nodeconfigtest.Config) {
			nc.Register["payload_sha256"] = strings.ToUpper(nc.Register["payload_sha256"].(string))
		}, "64 lowercase hex"},
		"no anchors":         {func(nc *nodeconfigtest.Config) { nc.Register["trust_anchors"] = []any{} }, "trust_anchors is empty"},
		"short public key":   {func(nc *nodeconfigtest.Config) { anchor(nc)["public_key"] = "AAAA" }, "not 32 bytes"},
		"unknown key status": {func(nc *nodeconfigtest.Config) { anchor(nc)["status"] = "retired" }, `status "retired"`},
	} {
		t.Run(name, func(t *testing.T) {
			nc := nodeconfigtest.New("site-a-node1", t.TempDir()).AddSEL751(relayID, "", 2323, 300)
			withConfigRead(t, tc.mod)(nc)
			if _, err := ParseConfig(nc.Bytes()); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want an error naming %q", err, tc.want)
			}
		})
	}
	// Without a configuration read the section is optional.
	nc := nodeconfigtest.New("site-a-node1", t.TempDir()).AddSEL751(relayID, "", 2323, 300)
	if _, err := ParseConfig(nc.Bytes()); err != nil {
		t.Fatal(err)
	}
}
