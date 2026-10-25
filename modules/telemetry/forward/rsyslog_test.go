package forward

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"otsec.local/otsec/contracts/store"
	"otsec.local/otsec/contracts/syslog"
)

// These tests run the forwarder against a real rsyslog with imrelp over
// TLS, configured the way D2-9 commissions a collector: tls.authmode
// "name" with one permitted peer, a Direct ruleset queue and omfile
// sync="on". They need rsyslogd with imrelp on PATH and skip without it,
// unless OTSEC_RSYSLOG_REQUIRED=1. The integration job's end-to-end run is
// A6's (tests/integration/slice); this is the forwarder's own evidence.

type rsyslog struct {
	t    *testing.T
	dir  string
	conf string
	out  string
	port int
	cmd  *exec.Cmd
}

func needRsyslog(t *testing.T) string {
	t.Helper()
	path, err := exec.LookPath("rsyslogd")
	if err == nil {
		for _, d := range []string{"/usr/lib/x86_64-linux-gnu/rsyslog", "/usr/lib/rsyslog", "/usr/lib64/rsyslog"} {
			if _, err := os.Stat(filepath.Join(d, "imrelp.so")); err == nil {
				return path
			}
		}
	}
	if os.Getenv("OTSEC_RSYSLOG_REQUIRED") == "1" {
		t.Fatal("rsyslogd with imrelp is required and not found")
	}
	t.Skip("rsyslogd with imrelp not found")
	return ""
}

func writePEM(t *testing.T, path, typ string, der []byte) {
	t.Helper()
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
}

func startRsyslog(t *testing.T, p *pki, permitted string) *rsyslog {
	t.Helper()
	bin := needRsyslog(t)
	dir := t.TempDir()
	writePEM(t, filepath.Join(dir, "ca.pem"), "CERTIFICATE", p.caCert.Raw)
	writePEM(t, filepath.Join(dir, "server.pem"), "CERTIFICATE", p.server.Certificate[0])
	k, err := x509.MarshalPKCS8PrivateKey(p.server.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	writePEM(t, filepath.Join(dir, "server.key"), "PRIVATE KEY", k)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	r := &rsyslog{t: t, dir: dir, conf: filepath.Join(dir, "rsyslog.conf"), out: filepath.Join(dir, "out.log"), port: port}
	conf := fmt.Sprintf(`global(workDirectory=%[1]q)
module(load="imrelp")
template(name="raw" type="string" string="%%rawmsg%%\n")
ruleset(name="relp" queue.type="Direct") {
  action(type="omfile" file=%[2]q template="raw" sync="on")
}
input(type="imrelp" port="%[3]d" address="127.0.0.1" ruleset="relp" tls="on"
  tls.cacert=%[4]q tls.mycert=%[5]q tls.myprivkey=%[6]q
  tls.authmode="name" tls.permittedpeer=[%[7]q])
`, dir, r.out, port, filepath.Join(dir, "ca.pem"), filepath.Join(dir, "server.pem"), filepath.Join(dir, "server.key"), permitted)
	if err := os.WriteFile(r.conf, []byte(conf), 0o600); err != nil {
		t.Fatal(err)
	}
	r.start(bin)
	t.Cleanup(func() {
		r.kill()
		if b, _ := os.ReadFile(filepath.Join(dir, "rsyslogd.log")); t.Failed() && len(b) > 0 {
			t.Logf("rsyslogd output:\n%s", b)
		}
	})
	return r
}

func (r *rsyslog) start(bin string) {
	r.t.Helper()
	r.cmd = exec.Command(bin, "-n", "-f", r.conf, "-i", filepath.Join(r.dir, "pid"))
	logf, err := os.OpenFile(filepath.Join(r.dir, "rsyslogd.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		r.t.Fatal(err)
	}
	defer logf.Close()
	r.cmd.Stdout, r.cmd.Stderr = logf, logf
	if err := r.cmd.Start(); err != nil {
		r.t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", r.port)); err == nil {
			c.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	r.t.Fatal("rsyslogd did not listen")
}

func (r *rsyslog) kill() {
	if r.cmd != nil && r.cmd.Process != nil {
		r.cmd.Process.Kill() // SIGKILL: no flush, no clean shutdown
		r.cmd.Wait()
		r.cmd = nil
	}
}

// eids returns the eid of every line rsyslog wrote, in order.
func (r *rsyslog) eids() []string {
	r.t.Helper()
	f, err := os.Open(r.out)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		r.t.Fatal(err)
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	for sc.Scan() {
		s := sc.Text()
		i := strings.Index(s, ` eid="`)
		if i < 0 {
			r.t.Fatalf("line without eid: %q", s)
		}
		s = s[i+6:]
		out = append(out, s[:strings.IndexByte(s, '"')])
	}
	return out
}

func rsyslogRig(t *testing.T, r *rsyslog, p *pki, client *tls.Certificate) *rig {
	t.Helper()
	m := newStore()
	tg := newTarget(t, r.port, nil)
	tc, err := ClientTLS(tg, p.roots, client)
	if err != nil {
		t.Fatal(err)
	}
	return &rig{t: t, p: p, m: m, tg: tg, cfg: Config{
		Target:          tg,
		Streams:         []Stream{{ID: serStream, Outbox: m, Cursors: m}, {ID: hlStream, Outbox: m, Cursors: m}},
		HealthStream:    hlStream,
		Dial:            DialTLS(tg, tc, 5*time.Second),
		Health:          sink{t: t, m: m},
		ResponseTimeout: 2 * time.Second, Poll: 10 * time.Millisecond,
		RetryMin: 10 * time.Millisecond, RetryMax: 100 * time.Millisecond,
	}}
}

// P2-A4 acceptance: against rsyslog, every event arrives exactly once,
// counting by event_id.
func TestRsyslogExactlyOnce(t *testing.T) {
	p := newPKI(t)
	r := startRsyslog(t, p, string(node))
	g := rsyslogRig(t, r, p, &p.client)
	g.fill(500)
	g.run(func() bool { return g.m.cursor(serStream) == 500 }, nil)
	got := r.eids()
	want := g.m.keys(serStream)
	if len(got) != len(want) {
		t.Fatalf("rsyslog wrote %d lines for %d events", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("line %d is %s, want %s", i, got[i], want[i])
		}
	}
}

// rsyslog killed while events are in flight and started again: every
// event whose cursor was saved before the kill is in the file (the
// acknowledgement was durable), and after the restart every event is
// there. Duplicates are the unconfirmed window, sent again.
func TestRsyslogKilledMidStream(t *testing.T) {
	p := newPKI(t)
	r := startRsyslog(t, p, string(node))
	bin := needRsyslog(t)
	g := rsyslogRig(t, r, p, &p.client)
	g.fill(3000)
	var confirmed store.Seq
	killed := false
	g.run(func() bool {
		if !killed && g.m.cursor(serStream) >= 1000 {
			killed = true
			r.kill()
			confirmed = g.m.cursor(serStream)
			r.start(bin)
		}
		return g.m.cursor(serStream) == 3000
	}, nil)
	seen := map[string]int{}
	for _, id := range r.eids() {
		seen[id]++
	}
	dup := 0
	for i, k := range g.m.keys(serStream) {
		switch {
		case seen[k] == 0 && store.Seq(i+1) <= confirmed:
			t.Errorf("%s was confirmed before the kill and is not in the file", k)
		case seen[k] == 0:
			t.Errorf("%s never arrived", k)
		case seen[k] > 1:
			dup += seen[k] - 1
		}
	}
	t.Logf("confirmed through %d at the kill; %d duplicates after the restart (window %d)", confirmed, dup, g.tg.RELPWindow)
	if dup > g.tg.RELPWindow {
		t.Errorf("%d duplicates, more than one window", dup)
	}
}

// rsyslog permits only site-a-node1: a CA-signed certificate for another
// node is refused and nothing is written (D2-9, V-S6).
func TestRsyslogRefusesAnotherNode(t *testing.T) {
	p := newPKI(t)
	r := startRsyslog(t, p, string(node))
	other := p.issue(t, "site-b-node1", nil, x509.ExtKeyUsageClientAuth)
	// The target says site-b-node1, matching its certificate, so the
	// forwarder's own check passes and the collector is what refuses.
	g := rsyslogRig(t, r, p, &p.client)
	tg := newTarget(t, r.port, func(x *syslog.Target) { x.DurableAck.PermittedPeer = "site-b-node1" })
	tc, err := ClientTLS(tg, p.roots, &other)
	if err != nil {
		t.Fatal(err)
	}
	g.cfg.Target, g.cfg.Dial = tg, DialTLS(tg, tc, 5*time.Second)
	g.fill(5)
	var f *Forwarder
	g.run(func() bool { return f != nil && f.Status().LastErr != nil }, func(x *Forwarder) { f = x })
	t.Logf("session refused: %v", f.Status().LastErr)
	if n := len(r.eids()); n != 0 {
		t.Errorf("rsyslog wrote %d lines from another node", n)
	}
	if c := g.m.cursor(serStream); c != 0 {
		t.Errorf("cursor %d", c)
	}
}
