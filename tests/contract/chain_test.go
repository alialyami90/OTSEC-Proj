package contract

import "testing"

// The chain (P1-A6): one SEL-751 `ID` plus `SER` collection built end to end
// from contract types only, checked against groundtruth_test.go with nothing
// lost and no gaps. Each link is filled in when its contract merges (merge
// order C4, C1, C3, C7, C2, C8, C5, C6). Until then the link skips with the
// contract it waits for.
//
// A skip is "not built yet", never a pass: the Phase 1 exit gate needs every
// link to run. Once filled in, a link also pins the shape of each shared
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
		"the invocation envelope for each operation carries the C3 operation ID and its limits", nil},
	{"C2 result with transcript", "C2",
		"each result keeps the device bytes exactly (base64), with byte spans that cover the ground-truth lines", nil},
	{"C1 identity check", "C1",
		"identity from the ID result equals gtID field by field, each attribute with its source, and nothing the output does not contain; no credential for an asset whose binding compares nothing first",
		chainC1},
	{"C4 events", "C2 (C4 is merged; the events come from the C2 result)",
		"8 events from the SER result in device order, native time strings byte for byte, millisecond precision, offset unknown, event IDs contiguous", nil},
	{"C5 commit and acknowledgement", "C5",
		"each event is acknowledged only after its commit; the acknowledged set equals the 8 events with no gaps", nil},
	{"C6 rendering", "C6",
		"each event renders to one Syslog message that carries its event ID and native time; nothing invented", nil},
	{"C8 audit", "C2 (C8 is merged; one record per C2 invocation)",
		"one audit record per invocation, sharing C4's timestamp model, naming principal, operation and asset, with no secret", nil},
}

func TestChain(t *testing.T) {
	if len(gtID) == 0 || len(gtSER) != 8 {
		t.Fatal("ground truth not loaded")
	}
	for _, l := range chain {
		t.Run(l.link, func(t *testing.T) {
			if l.run == nil {
				t.Skipf("waiting for %s to merge; will check: %s", l.contract, l.checks)
			}
			l.run(t)
		})
	}
}
