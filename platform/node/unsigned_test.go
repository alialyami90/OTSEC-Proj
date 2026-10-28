package node

import (
	"strings"
	"testing"

	"otsec.local/otsec/contracts/asset"
	"otsec.local/otsec/contracts/audit"
)

// setTargets sets the target of every endpoint of every asset. The config
// loader refuses a device-observed target in this phase (D2-4), so a test
// reaches the node that would hold one by changing the loaded config.
func setTargets(t *testing.T, c *Config, class asset.EvidenceClass) {
	t.Helper()
	n := 0
	for i := range c.assets {
		for j := range c.assets[i].Endpoints {
			c.assets[i].Endpoints[j].Target = class
			n++
		}
	}
	if n == 0 {
		t.Fatal("the config holds no endpoint")
	}
}

func TestLabOnly(t *testing.T) {
	q := newQuarantineNode(t)
	cfg := q.s.rt.cfg
	if !cfg.LabOnly() {
		t.Fatal("a simulated config is not lab-only")
	}
	cfg.assets[0].Endpoints[0].Target = asset.DeviceObserved
	if cfg.LabOnly() {
		t.Fatal("a device-observed endpoint left the node lab-only")
	}
	cfg.assets[0].Endpoints[0].Target = ""
	if cfg.LabOnly() {
		t.Fatal("an endpoint with no target left the node lab-only")
	}
	if !(&Config{}).LabOnly() {
		t.Fatal("a node with no asset is not lab-only")
	}
}

// On a node with a device endpoint, clear-quarantine.json is refused in
// code, once, and nothing is removed; on the lab node it is acted on, the
// audit record says the file was unsigned, and an alarm names it.
func TestUnsignedQuarantineClearRefusedOffLab(t *testing.T) {
	q := newQuarantineNode(t)
	q.runs(2, false)
	q.export()
	q.s.QuarantineTick(bg)
	h := q.manifestHash()

	setTargets(t, q.s.rt.cfg, asset.DeviceObserved)
	q.clearFile(h, "")
	for i := 0; i < 2; i++ {
		q.s.QuarantineTick(bg)
	}
	if len(q.records(audit.ActionQuarantineCleared)) != 0 || len(q.seqs()) != 4 {
		t.Fatalf("an unsigned clear was acted on off-lab: %d records, seqs %v", len(q.records(audit.ActionQuarantineCleared)), q.seqs())
	}
	if !q.hasAlarm(AlarmUnsignedAdminFileRefused, "node.quarantine_clear") {
		t.Fatalf("no refusal alarm: %+v", q.st.Snapshot("x").Alarms)
	}
	if q.hasAlarm(AlarmUnsignedAdminFileAccepted, "") {
		t.Fatal("accepted alarm raised for a refused file")
	}

	setTargets(t, q.s.rt.cfg, asset.Simulated)
	q.s.QuarantineTick(bg)
	cl := q.records(audit.ActionQuarantineCleared)
	if len(cl) != 1 || !strings.Contains(cl[0].Detail, ClearQuarantineFileName+unsignedSuffix) {
		t.Fatalf("the lab node's record does not name the file as unsigned: %+v", cl)
	}
	if !q.hasAlarm(AlarmUnsignedAdminFileAccepted, ClearQuarantineFileName) {
		t.Fatalf("no accepted alarm: %+v", q.st.Snapshot("x").Alarms)
	}
}

// Off-lab, the signed request still works, so the administrator has a way.
func TestSignedQuarantineClearWorksOffLab(t *testing.T) {
	q, _, manifest := signedQuarantineNode(t)
	setTargets(t, q.s.rt.cfg, asset.DeviceObserved)
	q.signedClear("admin-request-clear.json", 1, manifest)
	q.s.relayAdmin(bg)
	if cl := clearRecords(q); len(cl) != 1 || strings.Contains(cl[0].Detail, "unsigned") {
		t.Fatalf("cleared records %+v", cl)
	}
}

// A signed request and an unsigned file for the same clear: only the signed
// one is acted on, whichever the node meets first.
func TestSignedQuarantineClearWinsOverTheUnsignedFile(t *testing.T) {
	q, _, manifest := signedQuarantineNode(t)
	q.signedClear("admin-request-clear.json", 1, manifest)
	q.clearFile(manifest, "")
	q.s.relayAdmin(bg) // reads the signed file's payload before anything else
	q.s.QuarantineTick(bg)
	cl := clearRecords(q)
	if len(cl) != 1 || strings.Contains(cl[0].Detail, "unsigned") || !strings.Contains(cl[0].Detail, "admin-request-clear.json") {
		t.Fatalf("cleared records %+v", cl)
	}
	// The unsigned file is not acted on again; it is the same export, now
	// cleared, and it raises nothing but the ignore notice (if it met the
	// signed request before the clear).
	q.s.QuarantineTick(bg)
	if n := len(clearRecords(q)); n != 1 {
		t.Fatalf("%d cleared records, want 1", n)
	}
}

func TestUnsignedFileIgnoredWhileASignedRequestNamesIt(t *testing.T) {
	q, mux, manifest := signedQuarantineNode(t)
	mux.force = 0
	q.signedClear("admin-request-clear.json", 1, manifest)
	// Scan the signed file without relaying it: the collector holds.
	files, _, _ := q.s.scanAdmin()
	q.s.setUnsignedWants(files)
	q.clearFile(manifest, "")
	q.s.QuarantineTick(bg)
	if len(clearRecords(q)) != 0 || !q.hasAlarm(AlarmUnsignedAdminFileIgnored, "signed request") {
		t.Fatalf("the unsigned file was acted on or not noticed: %+v %+v", clearRecords(q), q.st.Snapshot("x").Alarms)
	}
	// A signed request for another export does not shadow it.
	other := strings.Repeat("cd", 32)
	q.s.setUnsignedWants(nil)
	if q.s.supersededQuarantine(relayID, other) || q.s.supersededQuarantine(relayID, manifest) {
		t.Fatal("nothing is named after the wants are cleared")
	}
}

// seq-reset-ack.json: refused off-lab, acted on in the lab with an alarm
// and an audit record that names it unsigned, and the signed acknowledgement
// keeps working.
func TestUnsignedSeqResetAck(t *testing.T) {
	q := newQuarantineNode(t)
	q.runs(1, false)
	if err := q.nc.WriteInstallKey("ik_test_second"); err != nil {
		t.Fatal(err)
	}
	q.s.RunOnce(bg, 0)
	if cs := q.st.Snapshot("x").Collector; cs == nil || cs.OpenResetKey != kid("ik_test_second") {
		t.Fatalf("no reset open: %+v", cs)
	}
	setTargets(t, q.s.rt.cfg, asset.DeviceObserved)
	writeAck(t, q.nc, "ik_test_second")
	q.s.RunOnce(bg, 0)
	if cs := q.st.Snapshot("x").Collector; cs == nil || cs.OpenResetKey == "" {
		t.Fatalf("an unsigned acknowledgement was applied off-lab: %+v", cs)
	}
	if !q.hasAlarm(AlarmUnsignedAdminFileRefused, "node.seq_reset_ack") {
		t.Fatalf("no refusal alarm: %+v", q.st.Snapshot("x").Alarms)
	}
	setTargets(t, q.s.rt.cfg, asset.Simulated)
	q.s.RunOnce(bg, 0)
	if cs := q.st.Snapshot("x").Collector; cs == nil || cs.OpenResetKey != "" {
		t.Fatalf("not acknowledged in the lab: %+v", cs)
	}
	acks := q.records(audit.ActionCollectorSeqResetAck)
	if len(acks) != 1 || !strings.Contains(acks[0].Detail, SeqResetAckFileName+unsignedSuffix) {
		t.Fatalf("ack records %+v", acks)
	}
	if !q.hasAlarm(AlarmUnsignedAdminFileAccepted, SeqResetAckFileName) {
		t.Fatalf("no accepted alarm: %+v", q.st.Snapshot("x").Alarms)
	}
}
