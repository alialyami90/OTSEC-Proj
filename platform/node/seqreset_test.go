package node

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"

	"otsec.local/otsec/contracts/audit"
	"otsec.local/otsec/contracts/authz"
	"otsec.local/otsec/modules/security/collectorclient"
	"otsec.local/otsec/modules/security/collectorwire"
	"otsec.local/otsec/platform/node/nodeconfigtest"
)

// numbering is a collector that refuses every run, numbering each reply
// from next (A3's collector numbers a refusal too). before runs first,
// for a test that changes the install key while the request is out.
type numbering struct {
	next   uint64
	before func()
}

func (n *numbering) collector() *fakeCollector {
	return &fakeCollector{answer: func(req *authz.CollectorRequest) (collectorclient.Response, error) {
		if n.before != nil {
			n.before()
		}
		seq := n.next
		n.next++
		return collectorclient.Response{Reply: authz.CollectorReply{Contract: authz.ContractID, RequestID: req.RequestID, Status: authz.ReplyRefused,
			Refusal: &authz.Refusal{Code: authz.RefuseRateLimited, Detail: "test"}, CollectorSeq: seq}}, nil
	}}
}

// withField returns the JSON object b with field set to v.
func withField(t *testing.T, b []byte, field, v string) []byte {
	t.Helper()
	m := map[string]string{}
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	m[field] = v
	out, _ := json.Marshal(m)
	return out
}

// kid is the key ID of the test install key named name.
func kid(name string) string { return nodeconfigtest.InstallKeyID(name) }

// writeAck writes seq-reset-ack.json naming the test install key named
// name, as an administrator who confirmed its fingerprint would.
func writeAck(t *testing.T, nc *nodeconfigtest.Config, name string) {
	t.Helper()
	nc.UnlockTLS()
	b, _ := json.Marshal(map[string]string{"schema": SeqResetAckSchema, "install_key_id": kid(name)})
	if err := os.WriteFile(filepath.Join(nc.AdminDir, SeqResetAckFileName), b, 0o600); err != nil {
		t.Fatal(err)
	}
	lockTLS(t, nc)
}

func actionsOf(t *testing.T, r *Runtime, want audit.Action) []*audit.Record {
	t.Helper()
	var out []*audit.Record
	for _, rec := range auditRecords(t, r) {
		if rec.Action == want {
			out = append(out, rec)
		}
	}
	return out
}

// verifySeq checks the node's whole chain with C8 0.2's collector_seq
// rules, through the current epoch's latest number.
func verifySeq(t *testing.T, r *Runtime, through uint64) {
	t.Helper()
	if err := audit.VerifyCollectorSeq(auditRecords(t, r), 0, through); err != nil {
		t.Fatalf("collector_seq chain: %v", err)
	}
}

// The trusted install key is in the chain before the first request, once
// (A6 on #105), and node status shows it.
func TestInstallKeyBeforeFirstRequest(t *testing.T) {
	c, dir, _ := suspendConfig(t)
	r, st, _ := start(t, c, dir)
	n := &numbering{next: 1}
	s := newScheduler(t, r, n.collector())
	s.RunOnce(bg, 0)
	r.Close()
	r, st, _ = start(t, c, dir)
	defer r.Close()
	s = newScheduler(t, r, n.collector())
	s.RunOnce(bg, 0)
	recs := auditRecords(t, r)
	keys, firstRequest := 0, -1
	for i, rec := range recs {
		switch {
		case rec.Action == audit.ActionCollectorInstallKey:
			keys++
			if rec.InstallKeyID != kid(testInstallKey) || firstRequest >= 0 {
				t.Fatalf("collector.install_key %+v at %d, first request at %d", rec, i, firstRequest)
			}
		case rec.Action == audit.ActionCollectorRequest && firstRequest < 0:
			firstRequest = i
		}
	}
	if keys != 1 || firstRequest < 0 {
		t.Fatalf("%d collector.install_key records, first request at %d", keys, firstRequest)
	}
	verifySeq(t, r, 2)
	s.settle(bg) // applies the last run's records
	if cs := st.Snapshot("site-a-node1").Collector; cs == nil || cs.TrustedKey != kid(testInstallKey) || cs.High != 2 {
		t.Fatalf("status collector %+v", cs)
	}
}

// An install key the node cannot read holds every request: missing,
// malformed, another schema, a link, too large. It resumes once the file
// is good again.
func TestUnreadableInstallKeyHolds(t *testing.T) {
	c, dir, nc := suspendConfig(t)
	r, _, _ := start(t, c, dir)
	defer r.Close()
	n := &numbering{next: 1}
	col := n.collector()
	s := newScheduler(t, r, col)
	path := filepath.Join(nc.CollectorPublicDir, InstallKeyFileName)
	good := readFile(t, path)
	for name, damage := range map[string]func(){
		"missing":  func() { os.Remove(path) },
		"not json": func() { os.WriteFile(path, []byte("{"), 0o600) },
		"schema": func() {
			os.WriteFile(path, []byte(`{"schema":"x","key_id":"k","public_key":"p","fingerprint":"f"}`), 0o600)
		},
		"extra":     func() { os.WriteFile(path, withField(t, good, "x", "1"), 0o600) },
		"trailing":  func() { os.WriteFile(path, append(slices.Clone(good), `{}`...), 0o600) },
		"key case":  func() { os.WriteFile(path, bytes.Replace(good, []byte(`"key_id"`), []byte(`"KEY_ID"`), 1), 0o600) },
		"too large": func() { os.WriteFile(path, make([]byte, maxInstallKeyBytes+1), 0o600) },
		"a link":    func() { os.WriteFile(path+".real", good, 0o600); os.Remove(path); os.Symlink(path+".real", path) },
		"no key id": func() {
			os.WriteFile(path, []byte(`{"schema":"`+InstallKeySchema+`","key_id":"","public_key":"p","fingerprint":"f"}`), 0o600)
		},
		"a dir": func() { os.Remove(path); os.Mkdir(path, 0o700) },
		// The key ID and the fingerprint must both be the public key's
		// (A3 on #109), so an acknowledged key ID is the key whose
		// fingerprint the administrator confirmed.
		"key id of another key": func() { os.WriteFile(path, withField(t, good, "key_id", kid("ik_test_other")), 0o600) },
		"fingerprint of another key": func() {
			_, _, fp := nodeconfigtest.InstallKey("ik_test_other")
			os.WriteFile(path, withField(t, good, "fingerprint", fp), 0o600)
		},
		"public key not 32 bytes": func() { os.WriteFile(path, withField(t, good, "public_key", "AAAA"), 0o600) },
		"empty file":              func() { os.WriteFile(path, nil, 0o600) },
	} {
		damage()
		if rep := s.RunOnce(bg, 0); rep.Alarm != AlarmInstallKeyUnreadable || col.n() != 0 {
			t.Fatalf("%s: run %+v, %d requests", name, rep, col.n())
		}
		os.RemoveAll(path)
		os.WriteFile(path, good, 0o600)
	}
	if rep := s.RunOnce(bg, 0); !rep.Sent || col.n() != 1 {
		t.Fatalf("good key: run %+v, %d requests", rep, col.n())
	}
}

// A changed install key is a reinstall: collector.seq_reset is written and
// nothing is sent, across a restart, until an administrator acknowledges
// the new key. A file naming another key changes nothing. The chain then
// verifies under C8 0.2's rules.
func TestReinstallHoldsUntilAcknowledged(t *testing.T) {
	c, dir, nc := suspendConfig(t)
	r, st, _ := start(t, c, dir)
	n := &numbering{next: 1}
	col := n.collector()
	s := newScheduler(t, r, col)
	s.RunOnce(bg, 0)
	s.RunOnce(bg, 0) // collector_seq 1 and 2
	if err := nc.WriteInstallKey("ik_test_second"); err != nil {
		t.Fatal(err)
	}
	n.next = 1 // the reinstalled collector numbers from 1
	if rep := s.RunOnce(bg, 0); rep.Alarm != AlarmCollectorReset || col.n() != 2 {
		t.Fatalf("after the reinstall: run %+v, %d requests", rep, col.n())
	}
	resets := actionsOf(t, r, audit.ActionCollectorSeqReset)
	if len(resets) != 1 || resets[0].InstallKeyID != kid("ik_test_second") || resets[0].PreviousHigh == nil || *resets[0].PreviousHigh != 2 || resets[0].FirstSeen != 0 {
		t.Fatalf("collector.seq_reset records %+v", resets)
	}
	if cs := st.Snapshot("site-a-node1").Collector; cs == nil || cs.TrustedKey != kid(testInstallKey) || cs.OpenResetKey != kid("ik_test_second") {
		t.Fatalf("status collector %+v", cs)
	}
	r.Close()

	r, st, _ = start(t, c, dir)
	defer r.Close()
	s = newScheduler(t, r, col)
	if rep := s.RunOnce(bg, 0); rep.Alarm != AlarmCollectorReset || col.n() != 2 {
		t.Fatalf("after a restart: run %+v, %d requests", rep, col.n())
	}
	for _, key := range []string{testInstallKey, "ik_test_other"} {
		writeAck(t, nc, key)
		if rep := s.RunOnce(bg, 0); rep.Alarm != AlarmCollectorReset || col.n() != 2 {
			t.Fatalf("ack naming %s: run %+v, %d requests", key, rep, col.n())
		}
	}
	if acks := actionsOf(t, r, audit.ActionCollectorSeqResetAck); len(acks) != 0 {
		t.Fatalf("acks %+v", acks)
	}
	writeAck(t, nc, "ik_test_second")
	// The right key in a directory the node can write is refused (A3 on
	// #107): the node could have written the file itself.
	if err := nc.LoosenTLS(""); err != nil {
		t.Fatal(err)
	}
	if rep := s.RunOnce(bg, 0); rep.Alarm != AlarmCollectorReset || col.n() != 2 {
		t.Fatalf("ack in a writable admin_dir: run %+v, %d requests", rep, col.n())
	}
	lockTLS(t, nc)
	if rep := s.RunOnce(bg, 0); !rep.Sent || col.n() != 3 {
		t.Fatalf("acknowledged: run %+v, %d requests", rep, col.n())
	}
	if acks := actionsOf(t, r, audit.ActionCollectorSeqResetAck); len(acks) != 1 || acks[0].InstallKeyID != kid("ik_test_second") {
		t.Fatalf("acks %+v", acks)
	}
	// The acknowledgement file left in place changes nothing later.
	s.RunOnce(bg, 0)
	if acks := actionsOf(t, r, audit.ActionCollectorSeqResetAck); len(acks) != 1 || col.n() != 4 {
		t.Fatalf("%d acks, %d requests", len(acks), col.n())
	}
	if n := countAlarms(st, AlarmResetAckRefused); n != 3 {
		t.Fatalf("%d ack-refused alarms, want one for each wrong key and one for the writable directory", n)
	}
	verifySeq(t, r, 2)
}

// seq-reset-ack.json in admin_dir as the installer lays it out, shared
// with the collector (A6 on #119): read under the shared-reader rule and
// decoded strictly, as clear-suspension.json is. A key in another case, a
// duplicate key or a trailing value acknowledges nothing, and on Windows
// neither does a file a service outside AdminReaders may read; the right
// file in the shared layout does.
func TestAckFromSharedAdminDir(t *testing.T) {
	c, dir, nc := suspendConfig(t)
	r, _, _ := start(t, c, dir)
	defer r.Close()
	n := &numbering{next: 1}
	col := n.collector()
	s := newScheduler(t, r, col)
	s.RunOnce(bg, 0)
	if err := nc.WriteInstallKey("ik_test_second"); err != nil {
		t.Fatal(err)
	}
	n.next = 1
	if rep := s.RunOnce(bg, 0); rep.Alarm != AlarmCollectorReset || col.n() != 1 {
		t.Fatalf("after the reinstall: run %+v, %d requests", rep, col.n())
	}
	coll := collectorwire.ServiceSID(collectorwire.CollectorService)
	head := `{"schema":"` + SeqResetAckSchema + `",`
	right := kid("ik_test_second")
	held := map[string]string{
		"key case":  head + `"INSTALL_KEY_ID":"` + right + `"}`,
		"duplicate": head + `"install_key_id":"other","install_key_id":"` + right + `"}`,
		"trailing":  head + `"install_key_id":"` + right + `"}{}`,
	}
	for name, body := range held {
		writeShared(t, nc, SeqResetAckFileName, []byte(body), coll)
		if rep := s.RunOnce(bg, 0); rep.Alarm != AlarmCollectorReset || col.n() != 1 {
			t.Fatalf("%s: run %+v, %d requests", name, rep, col.n())
		}
	}
	good, _ := json.Marshal(map[string]string{"schema": SeqResetAckSchema, "install_key_id": right})
	if runtime.GOOS == "windows" {
		writeShared(t, nc, SeqResetAckFileName, good, strangerSID)
		if rep := s.RunOnce(bg, 0); rep.Alarm != AlarmCollectorReset || col.n() != 1 {
			t.Fatalf("a reader not in AdminReaders: run %+v, %d requests", rep, col.n())
		}
	}
	if acks := actionsOf(t, r, audit.ActionCollectorSeqResetAck); len(acks) != 0 {
		t.Fatalf("acks %+v", acks)
	}
	writeShared(t, nc, SeqResetAckFileName, good, coll)
	if rep := s.RunOnce(bg, 0); !rep.Sent || col.n() != 2 {
		t.Fatalf("acknowledged in the shared layout: run %+v, %d requests", rep, col.n())
	}
	if acks := actionsOf(t, r, audit.ActionCollectorSeqResetAck); len(acks) != 1 || acks[0].InstallKeyID != right {
		t.Fatalf("acks %+v", acks)
	}
}

// A reset or an acknowledgement whose append reported an error but was
// committed is found in the stream before the node decides again, so it is
// not written twice: C8 0.2 breaks the chain on a reset repeating a key
// and on a second acknowledgement. Here the run's own settle has not
// applied them, as when its fold could not read the stream.
func TestCommittedResetNotWrittenTwice(t *testing.T) {
	c, dir, nc := suspendConfig(t)
	r, _, _ := start(t, c, dir)
	defer r.Close()
	n := &numbering{next: 1}
	s := newScheduler(t, r, n.collector())
	s.RunOnce(bg, 0)
	if err := nc.WriteInstallKey("ik_test_second"); err != nil {
		t.Fatal(err)
	}
	high := uint64(1)
	rec, err := s.collectorRecord(audit.ActionCollectorSeqReset, kid("ik_test_second"), &high, 0, "test")
	if err == nil {
		err = s.commitAudit(bg, rec)
	}
	if err != nil {
		t.Fatal(err)
	}
	if code, _ := s.collectorHold(bg); code != AlarmCollectorReset {
		t.Fatalf("hold %q", code)
	}
	if resets := actionsOf(t, r, audit.ActionCollectorSeqReset); len(resets) != 1 {
		t.Fatalf("%d collector.seq_reset records", len(resets))
	}
	rec, err = s.collectorRecord(audit.ActionCollectorSeqResetAck, kid("ik_test_second"), nil, 0, "test")
	if err == nil {
		err = s.commitAudit(bg, rec)
	}
	if err != nil {
		t.Fatal(err)
	}
	writeAck(t, nc, "ik_test_second")
	s.checkAck(bg)
	if acks := actionsOf(t, r, audit.ActionCollectorSeqResetAck); len(acks) != 1 {
		t.Fatalf("%d collector.seq_reset_ack records", len(acks))
	}
	if code, _ := s.collectorHold(bg); code != "" {
		t.Fatalf("held after the acknowledgement: %q", code)
	}
	if why := s.Halted("any-other-asset"); why != "" {
		t.Fatalf("node held: %q", why)
	}
}

// A key the node trusted or recorded a reset for before is never a new
// reset (A3, A6 and A1 on #109): a reinstall makes a new key, so it is
// held as restored, no reset is written, and no acknowledgement lifts it. An
// acknowledgement of the open reset is refused while the collector is on
// another key. The chain verifies throughout.
func TestReusedKeyIsNotAReset(t *testing.T) {
	c, dir, nc := suspendConfig(t)
	r, st, _ := start(t, c, dir)
	defer r.Close()
	n := &numbering{next: 1}
	col := n.collector()
	s := newScheduler(t, r, col)
	key := func(k string) {
		t.Helper()
		if err := nc.WriteInstallKey(k); err != nil {
			t.Fatal(err)
		}
	}
	run := func(what, alarm string, sent int) {
		t.Helper()
		if rep := s.RunOnce(bg, 0); rep.Alarm != alarm || col.n() != sent {
			t.Fatalf("%s: run %+v, %d requests; want alarm %q, %d requests", what, rep, col.n(), alarm, sent)
		}
	}
	s.RunOnce(bg, 0) // first key trusted, collector_seq 1
	key("ik_test_second")
	n.next = 1
	run("reinstall", AlarmCollectorReset, 1)
	writeAck(t, nc, "ik_test_second")
	if rep := s.RunOnce(bg, 0); !rep.Sent || col.n() != 2 {
		t.Fatalf("acknowledged: run %+v", rep)
	}

	key(testInstallKey) // the first key, trusted before
	run("back to the first key", AlarmCollectorRestored, 2)
	writeAck(t, nc, testInstallKey)
	run("ack of the first key", AlarmCollectorRestored, 2)

	key("ik_test_third")
	n.next = 1
	run("a new key", AlarmCollectorReset, 2)
	key("ik_test_second") // the trusted key: no new reset, the open one holds
	run("back to the trusted key", AlarmCollectorReset, 2)
	key(testInstallKey)
	run("back to the first key with a reset open", AlarmCollectorRestored, 2)
	writeAck(t, nc, "ik_test_third")
	run("ack while the collector is on another key", AlarmCollectorRestored, 2)

	if resets := actionsOf(t, r, audit.ActionCollectorSeqReset); len(resets) != 2 {
		t.Fatalf("%d collector.seq_reset records, want 2", len(resets))
	}
	if acks := actionsOf(t, r, audit.ActionCollectorSeqResetAck); len(acks) != 1 {
		t.Fatalf("%d collector.seq_reset_ack records, want 1", len(acks))
	}
	// One for the file naming the first key once the third key's reset is
	// open, one for the third key's file while the collector is elsewhere.
	if n := countAlarms(st, AlarmResetAckRefused); n != 2 {
		t.Fatalf("%d ack-refused alarms, want 2", n)
	}
	key("ik_test_third")
	if rep := s.RunOnce(bg, 0); !rep.Sent || col.n() != 3 {
		t.Fatalf("acknowledged on the third key: run %+v", rep)
	}
	verifySeq(t, r, 1)
}

// A6's probe on #109: K1, a reinstall to K2 acknowledged, a reinstall to
// K3 acknowledged, then an earlier key comes back, an earlier reset's key
// (K2) or the first install key (K1), and an acknowledgement names it.
// Either way it is a restore: held, no reset written for it, nothing sent
// after the acknowledgement, and the chain verifies.
func TestEarlierEpochKeyIsRestore(t *testing.T) {
	for _, back := range []string{"ik_test_second", testInstallKey} {
		t.Run(back, func(t *testing.T) {
			c, dir, nc := suspendConfig(t)
			r, _, _ := start(t, c, dir)
			defer r.Close()
			n := &numbering{next: 1}
			col := n.collector()
			s := newScheduler(t, r, col)
			s.RunOnce(bg, 0)
			for _, k := range []string{"ik_test_second", "ik_test_third"} {
				if err := nc.WriteInstallKey(k); err != nil {
					t.Fatal(err)
				}
				n.next = 1
				s.RunOnce(bg, 0)
				writeAck(t, nc, k)
				if rep := s.RunOnce(bg, 0); !rep.Sent {
					t.Fatalf("reinstall to %s not resumed after its ack: %+v", k, rep)
				}
			}
			sent := col.n()
			if err := nc.WriteInstallKey(back); err != nil {
				t.Fatal(err)
			}
			if rep := s.RunOnce(bg, 0); rep.Alarm != AlarmCollectorRestored || col.n() != sent {
				t.Fatalf("earlier key back: run %+v, %d requests", rep, col.n())
			}
			writeAck(t, nc, back)
			for range 2 {
				if rep := s.RunOnce(bg, 0); rep.Alarm != AlarmCollectorRestored || col.n() != sent {
					t.Fatalf("after an ack naming %s: run %+v, %d requests", back, rep, col.n())
				}
			}
			if resets := actionsOf(t, r, audit.ActionCollectorSeqReset); len(resets) != 2 {
				t.Fatalf("%d collector.seq_reset records, want 2", len(resets))
			}
			if acks := actionsOf(t, r, audit.ActionCollectorSeqResetAck); len(acks) != 2 {
				t.Fatalf("%d collector.seq_reset_ack records, want 2", len(acks))
			}
			verifySeq(t, r, 1)
		})
	}
}

// The backstop writes no reset for an earlier key either: a key that went
// back to the first install key while the request was out leaves the
// reply's records under the trusted key, where they read as a restore.
// A reset record repeating a used key, which the node never writes, is a
// record the state cannot be rebuilt past, so it holds every run.
func TestEarlierKeyAtTheBackstop(t *testing.T) {
	c, dir, nc := suspendConfig(t)
	r, _, _ := start(t, c, dir)
	defer r.Close()
	n := &numbering{next: 1}
	col := n.collector()
	s := newScheduler(t, r, col)
	s.RunOnce(bg, 0)
	if err := nc.WriteInstallKey("ik_test_second"); err != nil {
		t.Fatal(err)
	}
	n.next = 1
	s.RunOnce(bg, 0)
	writeAck(t, nc, "ik_test_second")
	s.RunOnce(bg, 0)
	s.RunOnce(bg, 0) // 1, 2 under the second key
	n.next = 1
	n.before = func() {
		if err := nc.WriteInstallKey(testInstallKey); err != nil {
			t.Error(err)
		}
		n.before = nil
	}
	s.RunOnce(bg, 0)
	if resets := actionsOf(t, r, audit.ActionCollectorSeqReset); len(resets) != 1 {
		t.Fatalf("%d collector.seq_reset records, want 1", len(resets))
	}
	sent := col.n()
	if rep := s.RunOnce(bg, 0); rep.Alarm != AlarmCollectorRestored || col.n() != sent {
		t.Fatalf("after the reply: run %+v, %d requests", rep, col.n())
	}

	high := uint64(2)
	rec, err := s.collectorRecord(audit.ActionCollectorSeqReset, kid(testInstallKey), &high, 0, "test")
	if err == nil {
		err = s.commitAudit(bg, rec)
	}
	if err != nil {
		t.Fatal(err)
	}
	s.settle(bg)
	if why := s.Halted("any-other-asset"); why != AlarmSuspensionsUnknown {
		t.Fatalf("a reset repeating a used key: node %q", why)
	}
}

// A reply numbered at or below the epoch's high under the same install
// key is a restore: nothing more is sent, an acknowledgement does not lift
// it, and it holds across a restart, from the stream alone.
func TestSeqBackUnderSameKeyIsRestore(t *testing.T) {
	c, dir, nc := suspendConfig(t)
	r, _, _ := start(t, c, dir)
	n := &numbering{next: 5}
	col := n.collector()
	s := newScheduler(t, r, col)
	s.RunOnce(bg, 0) // 5
	n.next = 2
	s.RunOnce(bg, 0) // 2: restored stores
	if rep := s.RunOnce(bg, 0); rep.Alarm != AlarmCollectorRestored || col.n() != 2 {
		t.Fatalf("after the restore: run %+v, %d requests", rep, col.n())
	}
	writeAck(t, nc, testInstallKey)
	if rep := s.RunOnce(bg, 0); rep.Alarm != AlarmCollectorRestored || col.n() != 2 {
		t.Fatalf("ack: run %+v, %d requests", rep, col.n())
	}
	r.Close()
	os.Remove(filepath.Join(c.Store.Dir, SuspensionsFileName)) // rebuild from the chain
	r, _, _ = start(t, c, dir)
	defer r.Close()
	s = newScheduler(t, r, col)
	if rep := s.RunOnce(bg, 0); rep.Alarm != AlarmCollectorRestored || col.n() != 2 {
		t.Fatalf("after a restart: run %+v, %d requests", rep, col.n())
	}
	// Reinstalling with a new key turns it into a reset an administrator
	// can acknowledge.
	if err := nc.WriteInstallKey("ik_test_second"); err != nil {
		t.Fatal(err)
	}
	if rep := s.RunOnce(bg, 0); rep.Alarm != AlarmCollectorReset {
		t.Fatalf("after the reinstall: run %+v", rep)
	}
}

// The backstop: the key changes while the request is out, and the reply
// is numbered below the high. The reset goes first in the reply's batch,
// with first_seen, and the chain verifies once acknowledged.
func TestReplyBelowHighWithNewKeyIsReset(t *testing.T) {
	c, dir, nc := suspendConfig(t)
	r, _, _ := start(t, c, dir)
	defer r.Close()
	n := &numbering{next: 1}
	col := n.collector()
	s := newScheduler(t, r, col)
	s.RunOnce(bg, 0)
	s.RunOnce(bg, 0) // 1, 2
	n.next = 1
	n.before = func() {
		if err := nc.WriteInstallKey("ik_test_second"); err != nil {
			t.Error(err)
		}
		n.before = nil
	}
	s.RunOnce(bg, 0)
	recs := auditRecords(t, r)
	var resetAt, requestAt = -1, -1
	for i, rec := range recs {
		switch {
		case rec.Action == audit.ActionCollectorSeqReset:
			resetAt = i
			if rec.FirstSeen != 1 || *rec.PreviousHigh != 2 || rec.InstallKeyID != kid("ik_test_second") {
				t.Fatalf("reset %+v", rec)
			}
		case rec.CollectorSeq == 1 && resetAt >= 0 && requestAt < 0:
			requestAt = i
		}
	}
	if resetAt < 0 || requestAt != resetAt+1 {
		t.Fatalf("reset at %d, the reply's record at %d", resetAt, requestAt)
	}
	if rep := s.RunOnce(bg, 0); rep.Alarm != AlarmCollectorReset || col.n() != 3 {
		t.Fatalf("after the reset: run %+v, %d requests", rep, col.n())
	}
	writeAck(t, nc, "ik_test_second")
	if rep := s.RunOnce(bg, 0); !rep.Sent {
		t.Fatalf("acknowledged: run %+v", rep)
	}
	verifySeq(t, r, 2)
}
