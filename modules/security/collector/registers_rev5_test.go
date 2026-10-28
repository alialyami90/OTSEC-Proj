package collector

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"testing"

	"otsec.local/otsec/contracts/authz"
	"otsec.local/otsec/contracts/register"
)

// B3 on #301 (D4-13 condition 3): Registers.Activate takes the SEL-751
// revision 5 package, with its run, only from a verified signature; a package
// changed after signing, or one with a run that breaks C3 0.3's rules, is
// refused and leaves the active package alone; and revision 4 cannot be put
// back over it, also after a restart.
func TestActivateRevision5(t *testing.T) {
	f := newPipeline(t)
	const keyID = "release-2026"
	rev5 := readFixtureFrom(t, "../../../contracts/register/testdata/sel-751.json")
	rev4 := readFixtureFrom(t, "../../../contracts/register/testdata/sel-751-rev4.json")
	before, _, ok := f.registers.Active("sel-751")
	if !ok {
		t.Fatal("no active register")
	}

	// Refused: changed after signing, signed by another key, and a signed
	// package whose run has a step that is not an operation, a step twice, or
	// a step above Level 1. Each leaves the active package as it was.
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	var env register.Envelope
	if err := json.Unmarshal(signedRegister(t, rev5, f.release, keyID), &env); err != nil {
		t.Fatal(err)
	}
	env.Payload = bytes.Replace(env.Payload, []byte(`"sel.settings.show_global",`), []byte(`"sel.settings.show_group_1",`), 1)
	changed, _ := json.Marshal(env)
	// withStep signs rev5 with its run's second step replaced by step.
	withStep := func(step string) []byte {
		var m map[string]any
		if err := json.Unmarshal(rev5, &m); err != nil {
			t.Fatal(err)
		}
		m["runs"].([]any)[0].(map[string]any)["steps"].([]any)[1] = step
		b, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		return signedRegister(t, b, f.release, keyID)
	}
	bad := map[string][]byte{
		"changed after signing":           changed,
		"another key":                     signedRegister(t, rev5, other, keyID),
		"a step that is not an operation": withStep("sel.ser.clear"),
		"a step twice":                    withStep("sel.settings.show_port1"),
	}
	for name, b := range bad {
		if _, err := f.registers.Activate(b); !errors.Is(err, authz.ErrRegisterRejected) {
			t.Errorf("%s: %v", name, err)
		}
		if now, _, _ := f.registers.Active("sel-751"); now != before {
			t.Fatalf("%s changed the active package", name)
		}
	}

	// Accepted: the real package. Its run is the 24 forms, led by SHO P 1,
	// and the matcher permits each line in operate and nothing else.
	pkg, err := f.registers.Activate(signedRegister(t, rev5, f.release, keyID))
	if err != nil || pkg.Revision != 5 {
		t.Fatalf("revision 5: %v", err)
	}
	_, m, ok := f.registers.Active("sel-751")
	if !ok {
		t.Fatal("revision 5 is not active")
	}
	lines, err := m.RenderRun("sel.config.read_all")
	if err != nil || len(lines) != 24 || lines[0] != "SHO P 1" || lines[1] != "SHO G" {
		t.Fatalf("run lines %q: %v", lines, err)
	}
	for _, l := range lines {
		if _, _, err := m.Permit(register.PhaseOperate, l); err != nil {
			t.Errorf("%q in operate: %v", l, err)
		}
	}
	for _, l := range []string{"SHO G s", "SHO P", "SHO P 2 LANG", "SHO G;SET P 1", "SET P 1", "FIL SHO", "2AC"} {
		if _, _, err := m.Permit(register.PhaseOperate, l); err == nil {
			t.Errorf("%q may be sent in operate", l)
		}
	}

	// Revision 4 is a rollback now, also after a restart; so is the same
	// revision 5 under a revoked key.
	reopened, err := OpenState(f.state.path, f.clock.now)
	if err != nil {
		t.Fatal(err)
	}
	pub := f.release.Public().(ed25519.PublicKey)
	fresh := NewRegisters(reopened, []authz.TrustAnchor{{KeyID: keyID, PublicKey: pub, Status: authz.KeyActive}})
	if _, err := fresh.Activate(signedRegister(t, rev4, f.release, keyID)); !errors.Is(err, authz.ErrRegisterRejected) {
		t.Errorf("revision 4 after revision 5 and a restart: %v", err)
	}
	revoked := NewRegisters(reopened, []authz.TrustAnchor{{KeyID: keyID, PublicKey: pub, Status: authz.KeyRevoked}})
	if _, err := revoked.Activate(signedRegister(t, rev5, f.release, keyID)); !errors.Is(err, authz.ErrRegisterRejected) {
		t.Errorf("revision 5 under a revoked key: %v", err)
	}
}
