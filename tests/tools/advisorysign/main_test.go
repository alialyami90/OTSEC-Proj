package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"otsec.local/otsec/contracts/advisory"
	"otsec.local/otsec/contracts/advisory/advisorytest"
)

// TestSignsAVerifiableSet runs the tool on a minimal test set and checks that
// the envelope verifies under test key 0, and under no other anchor.
func TestSignsAVerifiableSet(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "advisorysign")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	set := `{"contract":"otsec.advisory/0.1","set_id":"otsec-test","version":1,"issued_at":"2026-11-05T00:00:00Z","purpose":"test","publisher":"advisorysign test","entries":[]}`
	cmd := exec.Command(bin, "-key", "0")
	cmd.Stdin = strings.NewReader(set)
	cmd.Stderr = os.Stderr
	file, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	v, r := advisory.Verify(file, []advisory.Anchor{advisorytest.Anchor(0)})
	if r != nil || v.Set.SetID != "otsec-test" {
		t.Fatalf("Verify: %v", r)
	}
	if _, r := advisory.Verify(file, []advisory.Anchor{advisorytest.Anchor(1)}); r == nil || r.Code != advisory.UnknownKey {
		t.Fatalf("verified under another key: %v", r)
	}
}

// TestRefusesAReleaseSet: the tool will not put a test key on a release set.
func TestRefusesAReleaseSet(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "advisorysign")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	set := `{"contract":"otsec.advisory/0.1","set_id":"otsec-test","version":1,"issued_at":"2026-11-05T00:00:00Z","purpose":"release","publisher":"advisorysign test","entries":[]}`
	cmd := exec.Command(bin, "-key", "0")
	cmd.Stdin = strings.NewReader(set)
	out, err := cmd.Output()
	if err == nil || len(out) != 0 {
		t.Fatalf("signed a release set: err %v, %d bytes out", err, len(out))
	}
}

// TestNotInEitherBinary: neither product binary links the test keys or this
// tool.
func TestNotInEitherBinary(t *testing.T) {
	cmd := exec.Command("go", "list", "-deps", "./cmd/otsec", "./cmd/otsec-collector")
	cmd.Dir = filepath.Join("..", "..", "..")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	for _, dep := range strings.Fields(string(out)) {
		if strings.HasSuffix(dep, "/advisorytest") || strings.Contains(dep, "/tests/") {
			t.Errorf("a product binary links %s", dep)
		}
	}
}
