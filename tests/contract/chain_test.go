package contract

import "testing"

// The chain (P1-A6): one SEL-751 `ID` plus `SER` collection built end to end
// from contract types only, checked against groundtruth_test.go with nothing
// lost and no gaps. Each link was filled in as its contract merged (C2 was
// the last, #51); the Phase 1 exit gate needs every link to run, so an
// unbuilt link fails. Once filled in, a link also pins the shape of each shared
// concept it uses (asset ID, node ID, event ID, timestamp, operation ID,
// principal, CredentialRef), so the chain fails if any contract changes it.
var chain = []struct {
	link, contract, checks string
	run                    func(t *testing.T) // nil until the contract merges
}{
	{"C3 lookup", "C3",
		"`ID` and `SER` resolve to operations; `ACC` and `QUI` do not; Figure 7.38's FID (R301, a denied branch) is refused, and the positive path needs an allowed FID (C3-A6 review, question 3)",
		chainC3},
	{"C7 IPC request", "C7",
		"a strict collector request naming the operation, the asset and a CredentialRef validates; one with an unknown field or a raw secret is rejected",
		chainC7},
	{"C2 invocation", "C2",
		"the invocation for the SER read carries the C3 operation ID, the asset, the declared identity and limits within the profile; it passes the register lookup and CheckAgainst",
		chainC2Invocation},
	{"C2 result with transcript", "C2",
		"the result keeps the device bytes exactly (base64), passes Validate and CheckLines, and its record spans are exactly the ground-truth rows",
		chainC2Result},
	{"C1 identity check", "C1",
		"identity from the ID result equals gtID field by field, each attribute with its source, and nothing the output does not contain; no credential for an asset whose binding compares nothing first",
		chainC1},
	{"C4 events", "C2 (C4 is merged; the events come from the C2 result)",
		"8 events from the SER result in device order, native time strings byte for byte, millisecond precision, offset unknown, marked simulated",
		chainC4},
	{"C5 commit and acknowledgement", "C5",
		"each event is acknowledged only after its commit; the acknowledged set equals the 8 events with no gaps, event IDs contiguous",
		chainC5},
	{"C6 rendering", "C6",
		"each event renders to one Syslog message that carries its event ID, native time, row, element, state and evc; nothing invented",
		chainC6},
	{"C8 audit", "C2 (C8 is merged; one record per C2 invocation)",
		"the invocation's audit records (session open, credential use, operation, close) verify as a chain, share C4's timestamp model, name principal, operation and asset, and carry no secret or device output",
		chainC8},
}

func TestChain(t *testing.T) {
	if len(gtID) == 0 || len(gtSER) != 8 {
		t.Fatal("ground truth not loaded")
	}
	for _, l := range chain {
		t.Run(l.link, func(t *testing.T) {
			// Every contract has merged (C2 last, #51), so a link without a
			// run is a failure, not a skip (the Phase 1 exit gate).
			if l.run == nil {
				t.Fatalf("link not built (%s): %s", l.contract, l.checks)
			}
			l.run(t)
		})
	}
}
