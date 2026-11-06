package collector

// C6's cases for #461 (P4-3-C3 deliverable 5). Evidence class: simulated
// (a loopback UDP socket as the agent, test keys only, no device).

import (
	"bytes"
	"testing"
	"time"

	"otsec.local/otsec/contracts/adapter"
)

// The client's Permit is wired to the run's own session: the authPriv
// request the agent saw passes egressPermit only for the step it was sent
// for, with the credential's engine ID, user and AES key. Another engine,
// user, key or step refuses it. A Permit wired to the wrong session (or to
// nothing) would let a message through that the check is there to stop.
func TestC6EgressPermitIsTheRunsSession(t *testing.T) {
	r := &SNMPRunner{Adapter: adapter.AdapterRef{ID: "sel-27x1-snmpv3", Version: "0.1.0"}, Now: func() time.Time { return time.Now().Add(-2 * time.Second) }}
	f := newSNMPPipeline(t, r)
	engine := mustHexT(t, snmpEngine)
	first := true
	ch := f.serve(func(req []byte) []byte {
		if !first {
			return nil
		}
		first = false
		return discoveryReport(t, req, engine)
	})
	if reply, _ := f.run(t, f.runReq(f.ref.ID)); !reply.Accepted() {
		t.Fatalf("refused: %+v", reply)
	}
	got := received(t, ch, 3)
	authPriv := got[1]

	pkg, _, _ := f.registers.Active("sel-27x1-rstp")
	user, priv := f.ref.USM.UserName, usmKeys()[32:]
	if err := egressPermit(pkg, engine, user, priv)("sel27x1.snmp.system", true, authPriv); err != nil {
		t.Fatalf("the run's own request is refused: %v", err)
	}
	if err := egressPermit(pkg, engine, user, priv)("sel27x1.snmp.system", false, got[0]); err != nil {
		t.Fatalf("the run's own discovery is refused: %v", err)
	}
	otherEngine := append(bytes.Clone(engine[:len(engine)-1]), engine[len(engine)-1]^1)
	otherKey := bytes.Clone(priv)
	otherKey[0] ^= 0xff
	for name, permit := range map[string]func(string, bool, []byte) error{
		"another engine ID": egressPermit(pkg, otherEngine, user, priv),
		"another user":      egressPermit(pkg, engine, user+"x", priv),
		"another AES key":   egressPermit(pkg, engine, user, otherKey),
	} {
		if err := permit("sel27x1.snmp.system", true, authPriv); err == nil {
			t.Errorf("%s: the request passed", name)
		}
	}
	if err := egressPermit(pkg, engine, user, priv)("sel27x1.snmp.entity", true, authPriv); err == nil {
		t.Error("a get for sel27x1.snmp.system passed as sel27x1.snmp.entity's getbulk")
	}
	if err := egressPermit(pkg, engine, user, priv)("sel27x1.snmp.identity", true, authPriv); err == nil {
		t.Error("a run's ID passed as a step")
	}
	if err := egressPermit(pkg, engine, user, priv)("sel27x1.snmp.system", true, got[0]); err == nil {
		t.Error("an unauthenticated discovery passed once the engine is known")
	}
}
