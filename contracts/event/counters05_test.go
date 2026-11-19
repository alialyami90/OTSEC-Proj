package event

import (
	"os"
	"testing"
)

// folded05 is the E5-3 fixture: a folded 0.5 sensor.counters event with
// runs_folded, diff.packets, a 0.4 capture counter that rose and its
// capture_loss (docs/phase4/D4-c4-0.5-proposal.md §5).
const folded05 = "testdata/valid/health-sensor-counters-folded.json"

// E5-3: an earlier reader accepts a folded 0.5 event, so 0.5 needs no
// reader floor. This test was committed with the fixture before the 0.5
// code, and passed there against the C4 0.4 code of main at 067d2a62.
//
// The 0.3 leg is a one-time desk run, not repeated in CI: the repository
// at c9d4d6c8 (C4 0.3, #566; Identifier otsec.event/0.3, self minor 3),
// exported by git archive into a scratch directory, with this fixture
// copied to its contracts/event/testdata and a test, TestD4C405OldReader,
// that runs Decode and then Validate on it and fails on either error. Run
// on the owner's PC (Go 1.27.3, windows/amd64) on 2026-11-19 with
// "go test ./contracts/event -run TestD4C405OldReader -v -count=1":
//
//	=== RUN   TestD4C405OldReader
//	--- PASS: TestD4C405OldReader (0.01s)
//	PASS
//	ok  	otsec.local/otsec/contracts/event	0.538s
//
// Evidence class desk.
func TestCounters05OldReader(t *testing.T) {
	b, err := os.ReadFile(folded05)
	if err != nil {
		t.Fatal(err)
	}
	e, err := Decode(b)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if err := e.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if e.Health.Details["runs_folded"] != "2" || e.Health.Details[DetailCaptureLoss] != "drops_holder" {
		t.Fatalf("fixture details changed: %v", e.Health.Details)
	}
}
