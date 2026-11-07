package contract

// C12 0.2 (otsec.finding/0.2, docs/phase4/D4-c12-0.2.md section 4, D4-61):
// D6's own cases for identity.mismatch. Expected outcomes come from the
// rule text, not from the code: the field is the device read that refused
// an operator or passive identity, never that identity's evidence; it holds
// a C2 invocation ID and a UTC time and nothing the device reported; and it
// appears exactly where the matcher puts it (D6's reading of entry() on
// #504). Every value is invented. Ground truth: GT-HAND. Evidence class:
// desk.

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"

	"otsec.local/otsec/contracts/advisory"
	"otsec.local/otsec/contracts/finding"
	"otsec.local/otsec/platform/node"
)

// c12v02Mismatch is the second invocation ID of C2's form, the refusing run.
const c12v02Mismatch = "9b1c7e24-5d3a-4f07-b8e2-1a6c0d4f3e95"

// c12v02Operator is an operator finding under a mismatch, as the matcher
// writes it: applicable-by-version, the version unread, the declaration
// stale, and the refusing read named.
func c12v02Operator() finding.Finding {
	f := c12Finding()
	f.Schema = "otsec.finding/0.2"
	f.Identity.Source = finding.Operator
	f.Identity.Evidence = []finding.Evidence{{Source: finding.Operator, ID: "audit:site-a-node1:7", Stale: true}}
	f.Identity.Mismatch = &finding.Read{ID: c12v02Mismatch, AtUTC: "2026-11-06T05:00:00.123456789Z"}
	f.Preconditions = []finding.Precondition{{Name: advisory.ReservedFirmwareVersion, State: finding.Unread}}
	return f
}

func c12v02Want(t *testing.T, name string, f finding.Finding, want finding.Code) {
	t.Helper()
	err := f.Validate()
	switch {
	case want == "" && err != nil:
		t.Errorf("%s: refused, want accepted: %v", name, err)
	case want != "" && !slices.Contains(finding.Codes(err), want):
		t.Errorf("%s: got %v (codes %v), want a %s refusal", name, err, finding.Codes(err), want)
	}
}

func TestC12V02MismatchRules(t *testing.T) {
	c12v02Want(t, "operator identity under a mismatch", c12v02Operator(), "")
	passive := c12v02Operator()
	passive.Identity.Source = finding.Passive
	passive.Identity.Evidence = []finding.Evidence{{Source: finding.Passive, Stale: true, ID: "site-a-node1:syslog/192.0.2.31:7"}}
	c12v02Want(t, "passive identity under a mismatch", passive, "")

	for _, c := range []struct {
		name string
		edit func(f *finding.Finding)
		want finding.Code
	}{
		// Rule 1: C2's invocation ID form (D4-57) and RFC 3339 UTC with Z.
		{"rule 1: upper-case ID", func(f *finding.Finding) { f.Identity.Mismatch.ID = strings.ToUpper(c12v02Mismatch) }, finding.CodeForm},
		{"rule 1: version 0 UUID", func(f *finding.Finding) { f.Identity.Mismatch.ID = "9b1c7e24-5d3a-0f07-b8e2-1a6c0d4f3e95" }, finding.CodeForm},
		{"rule 1: wrong variant", func(f *finding.Finding) { f.Identity.Mismatch.ID = "9b1c7e24-5d3a-4f07-c8e2-1a6c0d4f3e95" }, finding.CodeForm},
		{"rule 1: an audit reference", func(f *finding.Finding) { f.Identity.Mismatch.ID = "audit:site-a-node1:8" }, finding.CodeForm},
		{"rule 1: an event ID", func(f *finding.Finding) { f.Identity.Mismatch.ID = "site-a-node1:syslog/192.0.2.31:7" }, finding.CodeForm},
		{"rule 1: no ID", func(f *finding.Finding) { f.Identity.Mismatch.ID = "" }, finding.CodeForm},
		{"rule 1: an offset time", func(f *finding.Finding) { f.Identity.Mismatch.AtUTC = "2026-11-06T08:00:00+03:00" }, finding.CodeForm},
		{"rule 1: no time", func(f *finding.Finding) { f.Identity.Mismatch.AtUTC = "" }, finding.CodeMissing},
		// Rule 2: never on a device-read identity.
		{"rule 2: on a device-read identity", func(f *finding.Finding) {
			f.Identity.Source = finding.DeviceRead
			f.Identity.Evidence = []finding.Evidence{{Source: finding.DeviceRead, ID: c12Inv, Stale: true}}
		}, finding.CodeConflict},
		// Rule 3: only where the matcher puts it.
		{"rule 3: the declaration current", func(f *finding.Finding) { f.Identity.Evidence[0].Stale = false }, finding.CodeConflict},
		{"rule 3: not-applicable-operator", func(f *finding.Finding) {
			f.Class, f.Reason, f.Preconditions = finding.NotApplicableOperator, finding.OutsideRange, nil
		}, finding.CodeConflict},
		{"rule 3: the version read", func(f *finding.Finding) { f.Preconditions = nil }, finding.CodeConflict},
		{"rule 3: only another precondition unread", func(f *finding.Finding) {
			f.Preconditions = []finding.Precondition{{Name: "ehttp-enabled", State: finding.Unread}}
		}, finding.CodeConflict},
		// Rule 4: a stale operator identity in 0.2 says why.
		{"rule 4: stale, no mismatch", func(f *finding.Finding) { f.Identity.Mismatch = nil }, finding.CodeConflict},
		// Rule 5: the field does not exist in 0.1.
		{"rule 5: in a 0.1 record", func(f *finding.Finding) { f.Schema = "otsec.finding/0.1" }, finding.CodeSchema},
		// #440's probe at 0.2: the mismatch read is never the identity's
		// own evidence.
		{"the read as the operator identity's evidence", func(f *finding.Finding) {
			f.Identity.Evidence = append(f.Identity.Evidence, finding.Evidence{Source: finding.DeviceRead, ID: c12v02Mismatch, Stale: true})
		}, finding.CodeConflict},
	} {
		f := c12v02Operator()
		c.edit(&f)
		c12v02Want(t, c.name, f, c.want)
	}

	// Rule 3's class alone: mitigated with the version unread is a valid 0.1
	// finding, so only the mismatch rule refuses it.
	mit := c12v02Operator()
	mit.Class = finding.Mitigated
	mit.Mitigations = []finding.Mitigation{{Name: "ehttp-disabled", OperatorAttested: true,
		Evidence: []finding.Evidence{{Source: finding.Operator, ID: "audit:site-a-node1:9"}}}}
	if err := mit.Validate(); err == nil || !strings.Contains(err.Error(), "identity.mismatch") {
		t.Errorf("rule 3: mitigated under a mismatch: got %v, want an identity.mismatch refusal", err)
	}
	mit.Schema, mit.Identity.Mismatch = "otsec.finding/0.1", nil
	c12v02Want(t, "the same finding at 0.1 without the field", mit, "")

	// The 0.1 reader is kept: a stale operator identity with no mismatch,
	// as 0.1 wrote it, still validates.
	old := c12v02Operator()
	old.Schema, old.Identity.Mismatch = "otsec.finding/0.1", nil
	c12v02Want(t, "a 0.1 record without the field", old, "")
}

// The field carries the read's ID and time and nothing else: no FID, no
// model, no other device text (D3 and D1 on #504). A 0.1-shaped record
// marshals with no mismatch key, so its bytes are as 0.1 wrote them.
func TestC12V02MismatchHoldsNoDeviceText(t *testing.T) {
	b, err := json.Marshal(c12v02Operator().Identity.Mismatch)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	if !slices.Equal(keys, []string{"at_utc", "id"}) {
		t.Errorf("identity.mismatch has keys %v, want [at_utc id]", keys)
	}
	old := c12Finding()
	old.Schema = "otsec.finding/0.1"
	if b, _ := json.Marshal(old); strings.Contains(string(b), `"mismatch"`) {
		t.Errorf("a record without the field marshals a mismatch key: %s", b)
	}
}

// The 0.2 bound (D1 on D4-61): a finding at every bound C12 sets, under a
// mismatch, still fits one configuration record. The mismatch forces the
// shape (rule 3): applicable-by-version, so no mitigations; the version
// unread among MaxPreconditions; every identity evidence stale.
func TestC12V02AFindingAtEveryBoundUnderAMismatchFitsOneRecord(t *testing.T) {
	nodeID := strings.Repeat("n", 63)
	ref := func(i int) string { return fmt.Sprintf("audit:%s:%d", nodeID, uint64(18446744073709551615)-uint64(i)) }
	f := c12v02Operator()
	f.Advisory = "A" + strings.Repeat("9", 127)
	f.Set.ID = strings.Repeat("s", 64)
	f.Revision, f.Previous, f.From = 1<<31-1, "sha256:"+strings.Repeat("f", 64), finding.ApplicableByVersion
	f.Identity.Product, f.Identity.Version = strings.Repeat("P", 256), strings.Repeat("V", 256)
	f.Identity.Evidence = nil
	for i := 0; i < finding.MaxEvidence; i++ {
		f.Identity.Evidence = append(f.Identity.Evidence, finding.Evidence{Source: finding.Operator, Stale: true, ID: ref(i)})
	}
	f.Identity.Mismatch.AtUTC = "2026-11-06T05:00:00.123456789Z"
	f.Preconditions = []finding.Precondition{{Name: advisory.ReservedFirmwareVersion, State: finding.Unread}}
	for i := 1; i < finding.MaxPreconditions; i++ {
		name := fmt.Sprintf("p%d-", i)
		name += strings.Repeat("z", 64-len(name))
		f.Preconditions = append(f.Preconditions, finding.Precondition{Name: name, State: finding.Unread})
	}
	if err := f.Validate(); err != nil {
		t.Fatalf("the 0.2 finding at every bound does not validate: %v", err)
	}
	b, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	if int64(len(b)) > node.ConfigRecordBytes {
		t.Fatalf("%d bytes, above the node's configuration record cap %d", len(b), node.ConfigRecordBytes)
	}
	t.Logf("a 0.2 finding at every bound under a mismatch is %d bytes; the cap is %d", len(b), node.ConfigRecordBytes)
}
