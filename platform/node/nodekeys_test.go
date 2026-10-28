package node

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"otsec.local/otsec/contracts/audit"
	"otsec.local/otsec/modules/security/nodekey"
	"otsec.local/otsec/modules/telemetry/forward/relptest"
	"otsec.local/otsec/platform/node/nodeconfigtest"
)

// keyConfig is forwardConfig with the target's references in a node key
// register (lab-files keys in tls_dir) in place of the D2-12 files.
func keyConfig(t *testing.T, listenerHost string, notAfter time.Time) (*nodeconfigtest.Config, *nodeconfigtest.PKI, *nodekey.Register, string) {
	t.Helper()
	nc, p, dir := forwardConfig(t, 1, nil)
	reg, err := nc.WriteKeyRegister(p, listenerHost, notAfter)
	if err != nil {
		t.Fatal(err)
	}
	// The D2-12 files are removed, so nothing can resolve from them.
	for _, name := range []string{"test-ca.pem", "test-client.crt", "test-client.key"} {
		if err := os.Remove(filepath.Join(nc.TLSDir, name)); err != nil {
			t.Fatal(err)
		}
	}
	tlsSec := nc.Targets[0]["tls"].(map[string]any)
	tlsSec["trust_anchor_ref"] = nodeconfigtest.AnchorsRef
	tlsSec["client_credential_ref"] = nodeconfigtest.ClientKeyRef
	return nc, p, reg, dir
}

// keyRecords are the policy.apply records of register entries.
func keyRecords(t *testing.T, r *Runtime) []string {
	t.Helper()
	var out []string
	for _, rec := range auditRecords(t, r) {
		if rec.Action == audit.ActionPolicyApply && rec.ReasonCode == ReasonNodeKeyRegister {
			out = append(out, rec.Detail)
		}
	}
	return out
}

// The node forwards over mutual TLS with its client key and trust anchors
// from the key register, the key used where it lives (lab-files here), and
// records each register entry once as policy.apply: not again on a second
// call or a restart, again when its record of them is lost, and a rotated
// key's new and retired versions when they appear.
func TestKeyRegisterForwardsAndRecords(t *testing.T) {
	nc, p, reg, dir := keyConfig(t, "", time.Now().Add(24*time.Hour))
	srv, err := relptest.Start(p.ServerTLS("site-a-node1"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	nc.Targets[0]["port"] = srv.Addr().Port
	lockTLS(t, nc)
	r, st, _ := start(t, parse(t, nc), dir)
	fw, err := NewForwarding(r)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(bg)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); fw.Run(ctx) }()
	deadline := time.Now().Add(15 * time.Second)
	for len(srv.Acked()) == 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	wg.Wait()
	if len(srv.Acked()) == 0 {
		t.Fatalf("nothing acknowledged over the register's key: %v", srv.Errors())
	}

	if left := r.RecordNodeKeys(bg); left != 0 {
		// Two left means a commit failed for each entry (a register that did
		// not load leaves one). The alarm says which error; B6's Windows
		// trace had none, so the cause is not known (#313 thread).
		alarms := st.Snapshot("n").Alarms
		audit := r.Mode(AuditDB)
		r.Close()
		t.Fatalf("%d entries not recorded; audit database %s; alarms %+v", left, audit, alarms)
	}
	got := keyRecords(t, r)
	var want []string
	for _, e := range reg.Entries {
		want = append(want, "nodekey "+e.Ref+" "+string(e.Kind)+" v1 active sha256:"+e.Fingerprint+" installed by "+nodeconfigtest.KeyAdmin+" at "+e.InstalledAt)
	}
	if !slices.Equal(got, want) {
		t.Fatalf("records:\n%q\nwant\n%q", got, want)
	}
	r.RecordNodeKeys(bg)
	if n := len(keyRecords(t, r)); n != 2 {
		t.Fatalf("%d records after a second call", n)
	}
	r.Close()

	r, _, _ = start(t, parse(t, nc), dir)
	if _, err := NewForwarding(r); err != nil {
		t.Fatal(err)
	}
	r.RecordNodeKeys(bg)
	if n := len(keyRecords(t, r)); n != 2 {
		t.Fatalf("%d records after a restart", n)
	}
	// Losing the node's list records every entry again, never none.
	if err := os.Remove(filepath.Join(nc.Store.Dir, NodeKeysFileName)); err != nil {
		t.Fatal(err)
	}
	r.RecordNodeKeys(bg)
	if n := len(keyRecords(t, r)); n != 4 {
		t.Fatalf("%d records once the list was lost", n)
	}
	r.Close()

	// Rotation: version 2 of the client key is installed and version 1
	// retired. Both changes are recorded at the next start.
	if err := nc.UnlockTLS(); err != nil {
		t.Fatal(err)
	}
	csr, err := reg.Request(nodekey.LabFiles{Dir: nc.TLSDir}, nodeconfigtest.ClientKeyRef, pkix.Name{CommonName: "site-a-node1"}, nodeconfigtest.KeyAdmin, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	cert, err := p.Sign(csr, x509.ExtKeyUsageClientAuth, time.Now().Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if err := reg.Install(nodeconfigtest.ClientKeyRef, [][]byte{cert}, nodeconfigtest.KeyAdmin, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := nc.WriteRegister(reg); err != nil {
		t.Fatal(err)
	}
	lockTLS(t, nc)
	r, _, _ = start(t, parse(t, nc), dir)
	defer r.Close()
	if _, err := NewForwarding(r); err != nil {
		t.Fatal(err)
	}
	r.RecordNodeKeys(bg)
	got = keyRecords(t, r)[4:]
	if len(got) != 2 || !strings.HasPrefix(got[0], "nodekey "+nodeconfigtest.ClientKeyRef+" tls-key v1 retired ") ||
		!strings.HasPrefix(got[1], "nodekey "+nodeconfigtest.ClientKeyRef+" tls-key v2 active ") {
		t.Fatalf("rotation records: %q", got)
	}
}

// A policy.apply record that cannot be committed, here because the audit
// database's open was only busy, leaves its entry unrecorded and alarmed,
// and a later call records it.
func TestKeyRecordRetried(t *testing.T) {
	if testing.Short() {
		t.Skip("waits out busy_timeout")
	}
	nc, _, _, dir := keyConfig(t, "", time.Now().Add(24*time.Hour))
	lockTLS(t, nc)
	c := parse(t, nc)
	r, _, _ := start(t, c, dir)
	r.Close()
	release := holdDB(t, c.Store.Dir, AuditDB)
	r, st, _ := start(t, c, dir)
	defer r.Close()
	if _, err := NewForwarding(r); err != nil {
		t.Fatal(err)
	}
	if left := r.RecordNodeKeys(bg); left != 2 {
		t.Fatalf("%d left with the audit database busy, want 2", left)
	}
	if !slices.ContainsFunc(st.Snapshot("x").Alarms, func(a StatusAlarm) bool { return a.Code == AlarmNodeKeyNotRecorded }) {
		t.Fatal("no node-key-not-recorded alarm")
	}
	if _, err := os.Stat(filepath.Join(nc.Store.Dir, NodeKeysFileName)); err == nil {
		t.Fatal("entries kept as recorded with no record")
	}
	release()
	r.Tick(bg)
	if left := r.RecordNodeKeys(bg); left != 0 || len(keyRecords(t, r)) != 2 {
		t.Fatalf("after the audit database opened: %d left, %d records", left, len(keyRecords(t, r)))
	}
}

// A syslog-tls listener takes its certificate and its senders' CA set from
// the register.
func TestKeyRegisterListener(t *testing.T) {
	nc, p, _, dir := keyConfig(t, "127.0.0.1", time.Now().Add(24*time.Hour))
	nc.AddSyslogSender(relayID, "syslog-tls-out", "syslog-tls", "127.0.0.1", 0)
	nc.AddListener("lab-tls", "syslog-tls", "127.0.0.1:0")
	nc.Listeners[0].TLS.CredentialRef = nodeconfigtest.ListenerKeyRef
	nc.Listeners[0].TLS.SenderCARef = nodeconfigtest.AnchorsRef
	nc.Listeners[0].TLS.RequireSenderCert = true
	lockTLS(t, nc)
	r, st, _ := start(t, parse(t, nc), dir)
	defer r.Close()
	ls := serve(t, r)
	raw := dialFrom(t, "tcp", "127.0.0.1", ls.Addr("lab-tls"))
	c := tls.Client(raw, &tls.Config{RootCAs: p.Roots, ServerName: "127.0.0.1", Certificates: []tls.Certificate{p.Client}, MinVersion: tls.VersionTLS12})
	c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write([]byte("<13>1 - - - - - - from the register\n")); err != nil {
		t.Fatal(err)
	}
	waitStored(t, ls, st, "lab-tls", 1)
	evs := streamEvents(t, r, ListenerStream("lab-tls"))
	if len(evs) != 1 || evs[0].Source.OriginAuth != "tls-mutual" {
		t.Fatalf("stored: %+v", evs)
	}
	if got := st.Snapshot("x").Listeners["lab-tls"]; got.CertNotAfter.IsZero() {
		t.Fatalf("listener certificate expiry not shown: %+v", got)
	}
}

// What the node refuses, at load or at resolution, and never falls back
// from: a register that does not verify, one for another node, a lab-files
// key without the lab flag, and references that are not node key
// references.
func TestKeyRegisterRefusals(t *testing.T) {
	t.Run("tampered register", func(t *testing.T) {
		nc, _, reg, dir := keyConfig(t, "", time.Now().Add(24*time.Hour))
		b, err := reg.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		fp := reg.Entries[0].Fingerprint
		b = []byte(strings.Replace(string(b), fp, strings.Repeat("0", len(fp)), 1))
		if err := os.WriteFile(nc.KeyRegister, b, 0o600); err != nil {
			t.Fatal(err)
		}
		lockTLS(t, nc)
		r, _, _ := start(t, parse(t, nc), dir)
		defer r.Close()
		if _, err := NewForwarding(r); err == nil || !strings.Contains(err.Error(), "key_register") {
			t.Fatalf("a tampered register was used: %v", err)
		}
	})
	t.Run("another node's register", func(t *testing.T) {
		nc, p, _, dir := keyConfig(t, "", time.Now().Add(24*time.Hour))
		other := *nc
		other.NodeID = "site-b-node1"
		if _, err := os.Stat(nc.KeyRegister); err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"otsec-" + nodeconfigtest.ClientKeyRef + "-v1.p8"} {
			os.Remove(filepath.Join(nc.TLSDir, name))
		}
		if _, err := other.WriteKeyRegister(p, "", time.Now().Add(24*time.Hour)); err != nil {
			t.Fatal(err)
		}
		lockTLS(t, nc)
		r, _, _ := start(t, parse(t, nc), dir)
		defer r.Close()
		if _, err := NewForwarding(r); err == nil || !strings.Contains(err.Error(), `not "site-a-node1"`) {
			t.Fatalf("another node's register was used: %v", err)
		}
	})
	t.Run("lab-files key without the lab flag", func(t *testing.T) {
		nc, _, _, dir := keyConfig(t, "", time.Now().Add(24*time.Hour))
		lockTLS(t, nc)
		nc.TLSDir, nc.LabTLSFiles = "", false
		r, _, _ := start(t, parse(t, nc), dir)
		defer r.Close()
		if _, err := NewForwarding(r); err == nil || !strings.Contains(err.Error(), "needs lab_tls_files") {
			t.Fatalf("a file key was used without the lab flag: %v", err)
		}
	})
	for name, tc := range map[string]struct {
		mod  func(nc *nodeconfigtest.Config)
		want string
	}{
		"a file reference with a register": {func(nc *nodeconfigtest.Config) {
			nc.Targets[0]["tls"].(map[string]any)["trust_anchor_ref"] = "test-ca"
		}, `trust_anchor_ref "test-ca" is not a node key reference`},
		"tls_dir without the lab flag": {func(nc *nodeconfigtest.Config) { nc.LabTLSFiles = false }, "tls_dir is set without lab_tls_files"},
		"the lab flag without tls_dir": {func(nc *nodeconfigtest.Config) { nc.TLSDir = "" }, "lab_tls_files is set, so tls_dir is required"},
		"a relative register":          {func(nc *nodeconfigtest.Config) { nc.KeyRegister = "register.json" }, `key_register "register.json" is not an absolute path`},
		"no resolver": {func(nc *nodeconfigtest.Config) {
			nc.KeyRegister, nc.TLSDir, nc.LabTLSFiles = "", "", false
		}, "is set, so key_register, or tls_dir with lab_tls_files, is required"},
	} {
		t.Run(name, func(t *testing.T) {
			nc, _, _, _ := keyConfig(t, "", time.Now().Add(24*time.Hour))
			tc.mod(nc)
			if _, err := ParseConfig(nc.Bytes()); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %v, want %q", err, tc.want)
			}
		})
	}
}

// An entry whose certificate comes within 30 days of expiry is shown in
// status and alarmed once, and alarmed again once it has expired.
func TestNodeKeyExpiry(t *testing.T) {
	notAfter := time.Now().Add(20 * 24 * time.Hour).UTC().Truncate(time.Second)
	nc, _, _, dir := keyConfig(t, "", notAfter)
	lockTLS(t, nc)
	r, st, _ := start(t, parse(t, nc), dir)
	defer r.Close()
	if _, err := NewForwarding(r); err != nil {
		t.Fatal(err)
	}
	alarms := func() []string {
		var out []string
		for _, a := range st.Snapshot("x").Alarms {
			if a.Code == AlarmNodeKeyExpiring && a.Target == "nodekey "+nodeconfigtest.ClientKeyRef {
				out = append(out, a.Detail)
			}
		}
		return out
	}
	at := func(t time.Time) {
		r.opt.Now = func() time.Time { return t }
		r.CheckNodeKeys()
	}
	at(notAfter.Add(-31 * 24 * time.Hour))
	if a := alarms(); len(a) != 0 {
		t.Fatalf("31 days out: %q", a)
	}
	at(notAfter.Add(-20 * 24 * time.Hour))
	at(notAfter.Add(-19 * 24 * time.Hour))
	if a := alarms(); len(a) != 1 || !strings.Contains(a[0], "expires at "+notAfter.Format(time.RFC3339)) {
		t.Fatalf("20 days out: %q", a)
	}
	got := st.Snapshot("x").NodeKeys
	if !slices.ContainsFunc(got, func(k NodeKeyExpiry) bool {
		return k.Ref == nodeconfigtest.ClientKeyRef && k.Kind == "tls-key" && k.NotAfter.Equal(notAfter)
	}) {
		t.Fatalf("status: %+v", got)
	}
	at(notAfter.Add(time.Second))
	if a := alarms(); len(a) != 2 || !strings.Contains(a[1], "expired at") {
		t.Fatalf("expired: %q", a)
	}
}

// postureRecords are the node.posture_change records with reason.
func postureRecords(t *testing.T, r *Runtime, reason string) []string {
	t.Helper()
	var out []string
	for _, rec := range auditRecords(t, r) {
		if rec.Action == audit.ActionNodePostureChange && rec.ReasonCode == reason {
			out = append(out, rec.Detail)
		}
	}
	return out
}

// A node with lab_tls_files says so at every start, in the audit chain and
// in status, naming the references whose private key is in a file, as a
// plaintext listener does (B3 on #176). Without the flag it says nothing.
func TestLabTLSFilesPosture(t *testing.T) {
	nc, _, _, dir := keyConfig(t, "", time.Now().Add(24*time.Hour))
	lockTLS(t, nc)
	for run := 1; run <= 2; run++ {
		r, st, _ := start(t, parse(t, nc), dir)
		if _, err := NewForwarding(r); err != nil {
			t.Fatal(err)
		}
		r.RecordLabTLSFiles(bg)
		got := postureRecords(t, r, ReasonLabTLSFiles)
		if len(got) != run || !strings.HasSuffix(got[run-1], "from files: "+nodeconfigtest.ClientKeyRef) {
			t.Fatalf("start %d: records %q", run, got)
		}
		if s := st.Snapshot("x"); !s.LabTLSFiles || !slices.Equal(s.LabTLSFileRefs, []string{nodeconfigtest.ClientKeyRef}) {
			t.Fatalf("start %d: status %v %q", run, s.LabTLSFiles, s.LabTLSFileRefs)
		}
		r.Close()
	}

	// Without a register, every private key is a tls_dir file.
	fc, _, fdir := forwardConfig(t, 1, nil)
	lockTLS(t, fc)
	r, st, _ := start(t, parse(t, fc), fdir)
	if _, err := NewForwarding(r); err != nil {
		t.Fatal(err)
	}
	r.RecordLabTLSFiles(bg)
	ref := fc.Targets[0]["tls"].(map[string]any)["client_credential_ref"].(string)
	if s := st.Snapshot("x"); !slices.Equal(s.LabTLSFileRefs, []string{ref}) || len(postureRecords(t, r, ReasonLabTLSFiles)) != 1 {
		t.Fatalf("tls_dir files: %q", s.LabTLSFileRefs)
	}
	r.Close()

	nc, dir = listenConfig(t, func(nc *nodeconfigtest.Config) { nc.LabTLSFiles, nc.TLSDir = false, "" })
	r, st, _ = start(t, parse(t, nc), dir)
	defer r.Close()
	r.RecordLabTLSFiles(bg)
	if got := postureRecords(t, r, ReasonLabTLSFiles); len(got) != 0 || st.Snapshot("x").LabTLSFiles {
		t.Fatalf("without the flag: %q", got)
	}
}
