package authz

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// B3's condition 3 on C3 0.3 (D4-13): the runs are inside the signed payload,
// so a run cannot be changed without breaking the signature, and one invalid
// step makes the whole package invalid, so a signed package with a bad run is
// refused and never activated.
func TestRegisterRunsAreSigned(t *testing.T) {
	rev5, pkg := readSEL751Content(t, "sel-751.json")
	if pkg.Revision != 5 || len(pkg.Runs) != 1 || pkg.Contract != "otsec.register/0.3" {
		t.Fatalf("sel-751.json is revision %d, %s, %d runs", pkg.Revision, pkg.Contract, len(pkg.Runs))
	}
	rel := newSigner(t, "release-2026-1", 1)
	anchors := []TrustAnchor{{KeyID: rel.id, PublicKey: rel.pub, Status: KeyActive}}
	if got, floor, err := VerifyRegisterPackage(rel.seal(rev5), anchors, map[string]FamilyFloor{}); err != nil || got.Revision != 5 || floor.Revision != 5 {
		t.Fatalf("revision 5: %v", err)
	}
	// The run's steps are in the signed bytes: moving one after signing fails.
	env := rel.seal(rev5)
	env.Payload = bytes.Replace(env.Payload, []byte(`"sel.settings.show_global",`), []byte(`"sel.settings.show_group_1",`), 1)
	if bytes.Equal(env.Payload, rev5) {
		t.Fatal("the edit did not apply")
	}
	if _, _, err := VerifyRegisterPackage(env, anchors, map[string]FamilyFloor{}); !errors.Is(err, ErrRegisterRejected) {
		t.Errorf("a step changed after signing: %v", err)
	}
	// A signed package whose run holds one invalid step is refused whole.
	for name, edit := range map[string]func(m map[string]any){
		"a step that is not an operation": func(m map[string]any) {
			r := m["runs"].([]any)[0].(map[string]any)
			r["steps"] = append(r["steps"].([]any), "sel.ser.clear")
		},
		"a step twice": func(m map[string]any) {
			r := m["runs"].([]any)[0].(map[string]any)
			r["steps"] = append(r["steps"].([]any), r["steps"].([]any)[2])
		},
		"a total over C2's ceiling": func(m map[string]any) {
			m["runs"].([]any)[0].(map[string]any)["max_total_bytes"] = 1<<20 + 1
		},
		"a step above Level 1": func(m map[string]any) {
			for _, o := range m["operations"].([]any) {
				if o.(map[string]any)["id"] == "sel.settings.show_group_1" {
					o.(map[string]any)["access_level"] = "2"
				}
			}
		},
	} {
		var m map[string]any
		if err := json.Unmarshal(rev5, &m); err != nil {
			t.Fatal(err)
		}
		edit(m)
		bad, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := VerifyRegisterPackage(rel.seal(bad), anchors, map[string]FamilyFloor{}); !errors.Is(err, ErrRegisterRejected) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Anti-rollback applies as before: with revision 5 as the floor, revision 4
	// is refused.
	rev4, _ := readSEL751Content(t, "sel-751-rev4.json")
	_, floor, err := VerifyRegisterPackage(rel.seal(rev5), anchors, map[string]FamilyFloor{})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := VerifyRegisterPackage(rel.seal(rev4), anchors, map[string]FamilyFloor{"sel-751": floor}); !errors.Is(err, ErrRegisterRejected) || !strings.Contains(err.Error(), "below") {
		t.Errorf("revision 4 over a revision 5 floor: %v", err)
	}
}
