package node

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"otsec.local/otsec/contracts/audit"
	"otsec.local/otsec/contracts/authz"
	"otsec.local/otsec/modules/security/collectorclient"
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

func writeAck(t *testing.T, nc *nodeconfigtest.Config, key string) {
	t.Helper()
	nc.UnlockTLS()
	b, _ := json.Marshal(map[string]string{"schema": SeqResetAckSchema, "install_key_id": key})
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
			if rec.InstallKeyID != testInstallKey || firstRequest >= 0 {
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
	if cs := st.Snapshot("site-a-node1").Collector; cs == nil || cs.TrustedKey != testInstallKey || cs.High != 2 {
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
		"extra":     func() { os.WriteFile(path, append(slices.Clone(good[:len(good)-1]), `,"x":1}`...), 0o600) },
		"too large": func() { os.WriteFile(path, make([]byte, maxInstallKeyBytes+1), 0o600) },
		"a link":    func() { os.WriteFile(path+".real", good, 0o600); os.Remove(path); os.Symlink(path+".real", path) },
		"no key id": func() {
			os.WriteFile(path, []byte(`{"schema":"`+InstallKeySchema+`","key_id":"","public_key":"p","fingerprint":"f"}`), 0o600)
		},
		"a dir":      func() { os.Remove(path); os.Mkdir(path, 0o700) },
		"empty file": func() { os.WriteFile(path, nil, 0o600) },
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
	if len(resets) != 1 || resets[0].InstallKeyID != "ik_test_second" || resets[0].PreviousHigh == nil || *resets[0].PreviousHigh != 2 || resets[0].FirstSeen != 0 {
		t.Fatalf("collector.seq_reset records %+v", resets)
	}
	if cs := st.Snapshot("site-a-node1").Collector; cs == nil || cs.TrustedKey != testInstallKey || cs.OpenResetKey != "ik_test_second" {
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
	if acks := actionsOf(t, r, audit.ActionCollectorSeqResetAck); len(acks) != 1 || acks[0].InstallKeyID != "ik_test_second" {
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
	rec, err := s.collectorRecord(audit.ActionCollectorSeqReset, "ik_test_second", &high, 0, "test")
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
	rec, err = s.collectorRecord(audit.ActionCollectorSeqResetAck, "ik_test_second", nil, 0, "test")
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
			if rec.FirstSeen != 1 || *rec.PreviousHigh != 2 || rec.InstallKeyID != "ik_test_second" {
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
