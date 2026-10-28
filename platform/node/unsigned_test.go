package node

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"otsec.local/otsec/contracts/asset"
	"otsec.local/otsec/contracts/audit"
	"otsec.local/otsec/contracts/authz"
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

// The ack twin of the quarantine supersede test (B3 on #347): a signed
// node.seq_reset_ack naming install key X in admin_dir supersedes the
// unsigned seq-reset-ack.json naming X, which is ignored and raises the
// notice; the unsigned file naming another key is not superseded (it is
// refused as any other key is). The signed one is then acted on.
func TestSignedSeqResetAckWinsOverTheUnsignedFile(t *testing.T) {
	c, dir, nc := suspendConfig(t)
	r, st, _ := start(t, c, dir)
	defer r.Close()
	col := newAdminCollector()
	s := newScheduler(t, r, col)
	writeAdminFile(t, nc, "admin-request-first.json", authz.KindCredentialRevoke, signN(t, authz.KindCredentialRevoke, 1, nil))
	s.relayAdmin(bg)
	if err := nc.WriteInstallKey("ik_test_second"); err != nil {
		t.Fatal(err)
	}
	col.mu.Lock()
	col.installKey = kid("ik_test_second")
	col.mu.Unlock()
	writeAdminFile(t, nc, "admin-request-second.json", authz.KindCredentialRevoke, signN(t, authz.KindCredentialRevoke, 2, func(p *authz.AdminRequest) { p.InstallKeyID = kid("ik_test_second") }))
	s.relayAdmin(bg) // finds the new key and opens the reset
	if cs := st.Snapshot("site-a-node1").Collector; cs == nil || cs.OpenResetKey != kid("ik_test_second") {
		t.Fatalf("no reset open: %+v", cs)
	}
	has := func(code string) bool {
		return slices.ContainsFunc(st.Snapshot("site-a-node1").Alarms, func(a StatusAlarm) bool { return a.Code == code })
	}

	// A signed acknowledgement of X is in admin_dir and read, but not yet sent.
	writeAdminFile(t, nc, "admin-request-ack.json", authz.KindNodeSeqResetAck,
		signN(t, authz.KindNodeSeqResetAck, 3, func(p *authz.AdminRequest) { p.InstallKeyID = kid("ik_test_second") }))
	files, _, _ := s.scanAdmin()
	s.setUnsignedWants(files)

	// An unsigned file naming another key is not superseded: refused as
	// any other key is, with no ignore notice.
	writeAck(t, nc, "ik_test_other")
	s.checkAck(bg)
	if has(AlarmUnsignedAdminFileIgnored) || !has(AlarmResetAckRefused) {
		t.Fatalf("the file naming another key was treated as superseded or not refused: %+v", st.Snapshot("site-a-node1").Alarms)
	}
	// The unsigned file naming X is ignored, and nothing is acknowledged.
	writeAck(t, nc, "ik_test_second")
	s.checkAck(bg)
	if !has(AlarmUnsignedAdminFileIgnored) || has(AlarmUnsignedAdminFileAccepted) {
		t.Fatalf("the unsigned file naming X was not ignored: %+v", st.Snapshot("site-a-node1").Alarms)
	}
	if cs := st.Snapshot("site-a-node1").Collector; cs == nil || cs.OpenResetKey != kid("ik_test_second") {
		t.Fatalf("the reset was acknowledged by the unsigned file: %+v", cs)
	}
	if len(actionsOf(t, r, audit.ActionCollectorSeqResetAck)) != 0 {
		t.Fatal("an acknowledgement was recorded from the unsigned file")
	}

	// The signed one is acted on, and only that.
	s.relayAdmin(bg)
	acks := actionsOf(t, r, audit.ActionCollectorSeqResetAck)
	if len(acks) != 1 || strings.Contains(acks[0].Detail, "unsigned") || !strings.Contains(acks[0].Detail, "admin-request-ack.json") {
		t.Fatalf("ack records %+v", acks)
	}
}

// A payload whose own kind is not the file's names nothing: the collector
// would refuse it, and an unverified payload may withhold the unsigned file
// only when it plainly asks for the same clear (B3 on #347).
func TestUnsignedWantsReadOnlyAPayloadOfTheFilesKind(t *testing.T) {
	want := func(kind authz.RequestKind, p authz.AdminRequest) unsignedWants {
		t.Helper()
		b, err := json.Marshal(p)
		if err != nil {
			t.Fatal(err)
		}
		return unsignedWantsOf([]*adminFile{{kind: kind, signed: &authz.AdminSigned{Payload: b}}})
	}
	ack := authz.AdminRequest{Kind: authz.KindNodeSeqResetAck, InstallKeyID: "ik-x", NodeSeqResetAck: &authz.NodeSeqResetAckBody{}}
	if w := want(authz.KindNodeSeqResetAck, ack); !w.ack["ik-x"] {
		t.Fatalf("a matching ack payload names nothing: %+v", w)
	}
	ack.Kind = authz.KindCredentialRevoke
	if w := want(authz.KindNodeSeqResetAck, ack); len(w.ack) != 0 {
		t.Fatalf("a payload of another kind supersedes the unsigned ack: %+v", w)
	}
	clr := authz.AdminRequest{Kind: authz.KindNodeQuarantineClear, NodeQuarantineClear: &authz.NodeQuarantineClearBody{AssetID: relayID, ManifestSHA256: "ab"}}
	if w := want(authz.KindNodeQuarantineClear, clr); !w.quarantine[relayID+" ab"] {
		t.Fatalf("a matching clear payload names nothing: %+v", w)
	}
	clr.Kind = authz.KindCredentialRevoke
	if w := want(authz.KindNodeQuarantineClear, clr); len(w.quarantine) != 0 {
		t.Fatalf("a payload of another kind supersedes the unsigned clear: %+v", w)
	}
}
