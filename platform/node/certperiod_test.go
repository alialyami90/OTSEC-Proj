package node

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	c5 "otsec.local/otsec/contracts/store"
	"otsec.local/otsec/modules/telemetry/forward"
	"otsec.local/otsec/modules/telemetry/forward/relptest"
	"otsec.local/otsec/modules/telemetry/receive"
	"otsec.local/otsec/platform/node/nodeconfigtest"
)

// HR-13, D4-11: a TLS certificate outside its validity period stops only
// its own link. Evidence class: simulated (loopback, Linux and Windows CI).

// expired is a period that ended an hour ago.
func expired() nodeconfigtest.Period {
	now := time.Now()
	return nodeconfigtest.Period{NotBefore: now.Add(-3 * time.Hour), NotAfter: now.Add(-time.Hour)}
}

// notYet is a period that starts in a few seconds.
func notYet(d time.Duration) nodeconfigtest.Period {
	now := time.Now()
	return nodeconfigtest.Period{NotBefore: now.Add(d), NotAfter: now.Add(d + time.Hour)}
}

// notYetMargin is how long before its period begins a certificate is first
// made for the tests that watch a link released. The setup and the checks
// made while the link is held must finish inside it, and a Windows runner
// took longer than the 3 s these tests first had (#290: icacls, the store
// and the PKI all run before the node loads the certificate). The
// certificate holds whole seconds, so its NotBefore is also cut down by up
// to one.
const notYetMargin = 6 * time.Second

// window is the stretch before a certificate's period begins, in which the
// link it is for must be held. A check made after the period began shows
// nothing about a held link, and says so.
type window struct {
	t     *testing.T
	begin time.Time
}

func newWindow(t *testing.T, p nodeconfigtest.Period) window {
	return window{t, p.NotBefore.Truncate(time.Second)}
}

func (w window) open() bool { return time.Now().Before(w.begin) }

// fatalf reports a failed check made while the link should be held. If the
// window had closed by then, the check shows nothing, and the failure says
// that.
func (w window) fatalf(format string, args ...any) {
	w.t.Helper()
	if !w.open() {
		w.t.Fatalf("the certificate's period began during the checks, so this shows nothing: "+format, args...)
	}
	w.t.Fatalf(format, args...)
}

// notYetRun calls try with a period that begins notYetMargin from now, and
// again with twice the margin, up to three times in all, while try reports
// that the node loaded the certificate after its period began: a held link
// was then not seen, and nothing about it can be checked.
func notYetRun(t *testing.T, try func(per nodeconfigtest.Period, w window) (late bool)) {
	t.Helper()
	for margin, n := notYetMargin, 1; ; margin, n = margin*2, n+1 {
		per := notYet(margin)
		if !try(per, newWindow(t, per)) {
			return
		}
		if n == 3 {
			t.Fatalf("the node loaded the certificate after its period began in all %d tries, the last with a %s margin", n, margin)
		}
		t.Logf("the node loaded the certificate after its period began (margin %s); trying again with a longer one", margin)
	}
}

func statusAlarms(st *Status, code, target string) []StatusAlarm {
	var out []StatusAlarm
	for _, a := range st.Snapshot("x").Alarms {
		if a.Code == code && a.Target == target {
			out = append(out, a)
		}
	}
	return out
}

// runForwarding runs fw until the test ends.
func runForwarding(t *testing.T, fw *Forwarding) {
	t.Helper()
	ctx, cancel := context.WithCancel(bg)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); fw.Run(ctx) }()
	t.Cleanup(func() { cancel(); wg.Wait() })
}

// A client certificate outside its period holds back its own target: the
// node and its other target start and forward, the held target is not run,
// and no connection is made to its collector (items 1 and 10).
func TestExpiredClientCertHoldsOnlyItsTarget(t *testing.T) {
	nc, p, dir := forwardConfigValid(t, 1, nodeconfigtest.Validity{Client: expired()}, nil)
	if _, err := nc.WriteClientCredential(p, "other-client", nodeconfigtest.Period{}); err != nil {
		t.Fatal(err)
	}
	heldSrv, err := relptest.Start(p.ServerTLS("site-a-node1"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer heldSrv.Close()
	otherSrv, err := relptest.Start(p.ServerTLS("site-a-node1"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer otherSrv.Close()
	nc.Targets[0]["port"] = heldSrv.Addr().Port
	nc.AddRELPTarget("other", "127.0.0.1", otherSrv.Addr().Port, "test-ca", "other-client", "test/durable-ack", false)
	lockTLS(t, nc)
	r, st, _ := start(t, parse(t, nc), dir)
	defer r.Close()
	for i := 0; i < 3; i++ {
		r.health(bg, "test.forwarded", map[string]string{"n": string(rune('a' + i))})
	}
	fw, err := NewForwarding(r)
	if err != nil {
		t.Fatalf("an expired client certificate stopped the node: %v", err)
	}
	runForwarding(t, fw)
	deadline := time.Now().Add(15 * time.Second)
	for len(otherSrv.Acked()) == 0 && time.Now().Before(deadline) {
		fw.Check(bg)
		time.Sleep(20 * time.Millisecond)
	}
	if len(otherSrv.Acked()) == 0 {
		t.Fatalf("the other target forwarded nothing; errors %v", otherSrv.Errors())
	}
	fw.Check(bg)
	snap := st.Snapshot("site-a-node1")
	if e := snap.Targets["central"].LastErr; e != "" {
		// A forwarder that ran would show its dial error here (B6 on #290).
		t.Fatalf("the held target's forwarder ran: %s", e)
	}
	if snap.Targets["central"].HeldBack != "expired" || snap.Targets["other"].HeldBack != "" {
		t.Fatalf("held back: central %q, other %q", snap.Targets["central"].HeldBack, snap.Targets["other"].HeldBack)
	}
	a := statusAlarms(st, AlarmTargetHeldBack, "central")
	if len(a) != 1 || !strings.Contains(a[0].Detail, "expired") || !strings.Contains(a[0].Detail, "test-client.crt") {
		t.Fatalf("held-back alarms %+v", a)
	}
	if len(statusAlarms(st, AlarmTargetHeldBack, "other")) != 0 {
		t.Fatal("the target with a good certificate was held back")
	}
	if n := heldSrv.Conns(); n != 0 || len(heldSrv.Acked()) != 0 {
		t.Fatalf("the held target's collector saw %d connections and %d events", n, len(heldSrv.Acked()))
	}
}

// A held target opens no connection and sends no byte until its
// certificate's period is valid; then the node starts it, from the
// certificate it already loaded, and its events are delivered (items 4 and
// 10).
func TestHeldTargetStartsWhenThePeriodIsValid(t *testing.T) {
	notYetRun(t, func(period nodeconfigtest.Period, w window) bool {
		nc, p, dir := forwardConfigValid(t, 1, nodeconfigtest.Validity{Client: period}, nil)
		srv, err := relptest.Start(p.ServerTLS("site-a-node1"), nil)
		if err != nil {
			t.Fatal(err)
		}
		defer srv.Close()
		nc.Targets[0]["port"] = srv.Addr().Port
		lockTLS(t, nc)
		r, st, _ := start(t, parse(t, nc), dir)
		defer r.Close()
		r.health(bg, "test.forwarded", map[string]string{"n": "a"})
		fw, err := NewForwarding(r)
		if err != nil {
			t.Fatal(err)
		}
		if !w.open() {
			return true
		}
		runForwarding(t, fw)
		end := time.Now().Add(1500 * time.Millisecond)
		for time.Now().Before(end) && w.open() {
			fw.Check(bg)
			if srv.Conns() != 0 {
				w.fatalf("a connection was made while the certificate was not yet valid")
			}
			time.Sleep(50 * time.Millisecond)
		}
		if got := st.Snapshot("x").Targets["central"].HeldBack; got != "not-yet-valid" {
			w.fatalf("held back %q", got)
		}
		deadline := time.Now().Add(20 * time.Second)
		for len(srv.Acked()) == 0 && time.Now().Before(deadline) {
			fw.Check(bg)
			time.Sleep(50 * time.Millisecond)
		}
		if len(srv.Acked()) == 0 {
			t.Fatalf("the target never started; errors %v; status %+v", srv.Errors(), st.Snapshot("x").Targets["central"])
		}
		if got := st.Snapshot("x").Targets["central"].HeldBack; got != "" {
			t.Fatalf("still held back: %q", got)
		}
		return false
	})
}

// The 30-day warning applies to a target's client certificate as to a
// listener's (item 3); a running forwarder is not stopped when the
// certificate passes its end, and the alarm that names the target is raised
// again every CertAlarmRepeat while it runs (item 9).
func TestTargetCertWarningAndRunningPastItsEnd(t *testing.T) {
	if CertAlarmRepeat < time.Minute || CertAlarmRepeat > 24*time.Hour {
		t.Fatalf("CertAlarmRepeat %s: the alarm must be raised again at least daily, and not flood the status", CertAlarmRepeat)
	}
	// Valid for 90 days, so nothing is raised at start.
	long := nodeconfigtest.Period{NotAfter: time.Now().Add(90 * 24 * time.Hour)}
	nc, _, dir := forwardConfigValid(t, 9, nodeconfigtest.Validity{Client: long}, nil) // the forwarder is never run
	lockTLS(t, nc)
	r, st, _ := start(t, parse(t, nc), dir)
	defer r.Close()
	fw, err := NewForwarding(r)
	if err != nil {
		t.Fatal(err)
	}
	tg := fw.targets[0]
	na := tg.notAfter
	if na.IsZero() {
		t.Fatal("no certificate expiry kept")
	}
	at := func(d time.Duration) {
		r.opt.Now = func() time.Time { return na.Add(d) }
		fw.checkCert(tg)
	}
	n := func() int { return len(statusAlarms(st, AlarmTargetCertExpiring, "central")) }
	at(-31 * 24 * time.Hour)
	if n() != 0 {
		t.Fatal("raised 31 days out")
	}
	at(-29 * 24 * time.Hour)
	at(-28 * 24 * time.Hour)
	if a := statusAlarms(st, AlarmTargetCertExpiring, "central"); len(a) != 1 || !strings.Contains(a[0].Detail, "expires at "+na.UTC().Format(time.RFC3339)) || !strings.Contains(a[0].Detail, "test-client.crt") {
		t.Fatalf("29 days out: %+v", a)
	}
	at(time.Second)
	if a := statusAlarms(st, AlarmTargetCertExpiring, "central"); len(a) != 2 || !strings.Contains(a[1].Detail, "expired at") {
		t.Fatalf("expired: %+v", a)
	}
	at(30 * time.Minute)
	if n() != 2 {
		t.Fatalf("%d alarms within CertAlarmRepeat of the last", n())
	}
	at(time.Second + CertAlarmRepeat)
	at(time.Second + 2*CertAlarmRepeat + time.Minute)
	if n() != 4 {
		t.Fatalf("%d alarms, want one at expiry and one each CertAlarmRepeat after", n())
	}
	select {
	case <-tg.ready:
	default:
		t.Fatal("the forwarder of a target past its certificate's end was stopped")
	}
	if tg.heldBack != "" {
		t.Fatalf("held back at %q: a running link is never stopped at expiry", tg.heldBack)
	}
}

// An expired trust anchor is never trusted (item 5): the collector's
// certificate, itself in its period but issued by an expired CA, fails the
// node's verification, so the node's own TLS configuration refuses the
// peer, and the forwarder confirms nothing.
func TestExpiredTrustAnchorIsNeverTrusted(t *testing.T) {
	nc, p, dir := forwardConfigValid(t, 1, nodeconfigtest.Validity{CA: expired()}, nil)
	srv, err := relptest.Start(p.ServerTLS("site-a-node1"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	nc.Targets[0]["port"] = srv.Addr().Port
	lockTLS(t, nc)
	c := parse(t, nc)

	// The node's configuration against a bare server with the same
	// certificate: the handshake fails on the client side, with the
	// expiry named, and no peer is accepted unverified.
	tlsCfg, err := c.TargetTLS(c.targets[0])
	if err != nil {
		t.Fatalf("an expired trust anchor stopped the node at load: %v", err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{p.Server}})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); c.(*tls.Conn).Handshake() }()
		}
	}()
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", ln.Addr().String(), tlsCfg)
	if err == nil {
		conn.Close()
		t.Fatal("the node accepted a collector whose CA has expired")
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Fatalf("handshake error %v", err)
	}

	// And the forwarder: it keeps trying, confirms nothing, and the
	// collector sees no event.
	r, st, _ := start(t, c, dir)
	defer r.Close()
	r.health(bg, "test.forwarded", map[string]string{"n": "a"})
	fw, err := NewForwarding(r)
	if err != nil {
		t.Fatal(err)
	}
	runForwarding(t, fw)
	deadline := time.Now().Add(10 * time.Second)
	for fw.targets[0].f.Status().LastErr == nil && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	fs := fw.targets[0].f.Status()
	if fs.LastErr == nil || !strings.Contains(fs.LastErr.Error(), "expired") {
		t.Fatalf("forwarder error %v", fs.LastErr)
	}
	if !fs.Open.IsZero() || fs.Confirmed != 0 || len(srv.Acked()) != 0 {
		t.Fatalf("the forwarder opened a session with an expired trust anchor: %+v, %d events", fs, len(srv.Acked()))
	}
	fw.Check(bg)
	if st.Snapshot("x").Targets["central"].HeldBack != "" {
		t.Fatal("an expired trust anchor is a refused peer, not a held-back target")
	}
}

// waitOpen publishes until listener id reports itself open: Serve opens its
// side a moment after Run starts.
func waitOpen(t *testing.T, ls *Listening, st *Status, id string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		ls.Publish()
		if st.Snapshot("x").Listeners[id].Open {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("listener %s never opened: %+v", id, st.Snapshot("x").Listeners[id])
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// freeAddr is a loopback address nothing listens on.
func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().String()
}

// A listener certificate outside its period holds back its own listener:
// the node and its other listener start, nothing is bound for the held one,
// so a connection to its address is refused, and the held listener starts
// from the certificate it loaded once the period is valid (items 1, 4 and
// 10).
func TestExpiredListenerCertHoldsOnlyItsListener(t *testing.T) {
	t.Run("expired", func(t *testing.T) {
		listenerHeldCase(t, expired(), window{t, time.Time{}}, "expired", false)
	})
	t.Run("not yet valid", func(t *testing.T) {
		notYetRun(t, func(per nodeconfigtest.Period, w window) bool {
			return listenerHeldCase(t, per, w, "not-yet-valid", true)
		})
	})
}

// listenerHeldCase runs the scenario of TestExpiredListenerCertHoldsOnlyItsListener
// for a listener certificate with period per, which is held for state. For a
// certificate not yet valid (starts), what shows a held listener is checked
// before w's period begins, and late is reported if the node loaded the
// certificate after it.
func listenerHeldCase(t *testing.T, per nodeconfigtest.Period, w window, state string, starts bool) (late bool) {
	addr := freeAddr(t)
	var p *nodeconfigtest.PKI
	nc, dir := listenConfig(t, func(nc *nodeconfigtest.Config) {
		var err error
		if p, err = nc.WritePKI("127.0.0.1", "test-ca", "test-client"); err != nil {
			t.Fatal(err)
		}
		if _, err := nc.WriteListenerCredentialValid(p, "test-listener", "127.0.0.1", per); err != nil {
			t.Fatal(err)
		}
		nc.AddListener("lab-tls", "syslog-tls", addr).AddListener("lab-udp", "syslog-udp", "127.0.0.1:0")
	})
	locked := *nc
	t.Cleanup(func() { locked.UnlockTLS() })
	lockTLS(t, nc)
	r, st, _ := start(t, parse(t, nc), dir)
	defer r.Close()
	fail := func(format string, args ...any) {
		t.Helper()
		if starts {
			w.fatalf(format, args...)
		}
		t.Fatalf(format, args...)
	}
	ls := serve(t, r) // NewListening and Listen succeed with a held listener
	if starts && !w.open() {
		return true
	}
	waitOpen(t, ls, st, "lab-udp")
	if ls.Addr("lab-udp") == nil {
		t.Fatal("the other listener was not bound")
	}
	if ls.Addr("lab-tls") != nil {
		fail("the held listener was bound")
	}
	if c, err := net.DialTimeout("tcp", addr, time.Second); err == nil {
		c.Close()
		fail("something accepted a connection on the held listener's address")
	}
	got := st.Snapshot("x").Listeners
	if got["lab-tls"].HeldBack != state || got["lab-tls"].Open || got["lab-udp"].HeldBack != "" || !got["lab-udp"].Open {
		fail("status %+v", got)
	}
	a := statusAlarms(st, AlarmListenerHeldBack, "listener lab-tls")
	if len(a) != 1 || !strings.Contains(a[0].Detail, state) || !strings.Contains(a[0].Detail, "test-listener.crt") {
		fail("held-back alarms %+v", a)
	}
	if len(statusAlarms(st, AlarmListenerHeldBack, "listener lab-udp")) != 0 {
		t.Fatal("the other listener was held back")
	}
	if !starts {
		ls.Publish()
		if len(statusAlarms(st, AlarmListenerHeldBack, "listener lab-tls")) != 1 || ls.Addr("lab-tls") != nil {
			t.Fatal("the held listener started or its alarm was repeated within CertAlarmRepeat")
		}
		return false
	}
	deadline := time.Now().Add(20 * time.Second)
	for ls.Addr("lab-tls") == nil && time.Now().Before(deadline) {
		ls.Publish()
		time.Sleep(100 * time.Millisecond)
	}
	if ls.Addr("lab-tls") == nil {
		t.Fatal("the listener never started")
	}
	c := tls.Client(dialFrom(t, "tcp", "127.0.0.1", ls.Addr("lab-tls")), &tls.Config{RootCAs: p.Roots, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS12})
	c.SetDeadline(time.Now().Add(5 * time.Second))
	if err := c.Handshake(); err != nil {
		t.Fatalf("handshake with the released listener: %v", err)
	}
	if _, err := c.Write([]byte("<13>1 - - - - - - released\n")); err != nil {
		t.Fatal(err)
	}
	if got := waitStored(t, ls, st, "lab-tls", 1); got.HeldBack != "" || !got.Open {
		t.Fatalf("status after release %+v", got)
	}
	return false
}

// A running listener whose certificate passes its end is not stopped, and
// the alarm that names it is raised again every CertAlarmRepeat (item 9).
func TestListenerPastItsEndKeepsAlarming(t *testing.T) {
	long := nodeconfigtest.Period{NotAfter: time.Now().Add(90 * 24 * time.Hour)}
	nc, dir := listenConfig(t, func(nc *nodeconfigtest.Config) {
		p, err := nc.WritePKI("127.0.0.1", "test-ca", "test-client")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := nc.WriteListenerCredentialValid(p, "test-listener", "127.0.0.1", long); err != nil {
			t.Fatal(err)
		}
		nc.AddListener("lab-tls", "syslog-tls", "127.0.0.1:0")
	})
	locked := *nc
	t.Cleanup(func() { locked.UnlockTLS() })
	lockTLS(t, nc)
	r, st, _ := start(t, parse(t, nc), dir)
	defer r.Close()
	ls := serve(t, r)
	waitOpen(t, ls, st, "lab-tls")
	na := ls.notAfter["lab-tls"]
	at := func(d time.Duration) {
		r.opt.Now = func() time.Time { return na.Add(d) }
		ls.Publish()
	}
	n := func() int { return len(statusAlarms(st, AlarmListenerCertExpiring, "listener lab-tls")) }
	at(-29 * 24 * time.Hour)
	at(time.Second)
	at(30 * time.Minute)
	if n() != 2 {
		t.Fatalf("%d alarms within CertAlarmRepeat of the last", n())
	}
	at(time.Second + CertAlarmRepeat)
	at(time.Second + 2*CertAlarmRepeat + time.Minute)
	if n() != 4 {
		t.Fatalf("%d alarms, want the warning, one at expiry and one each CertAlarmRepeat after", n())
	}
	if ls.Addr("lab-tls") == nil || !st.Snapshot("x").Listeners["lab-tls"].Open || st.Snapshot("x").Listeners["lab-tls"].HeldBack != "" {
		t.Fatalf("a running listener was stopped at expiry: %+v", st.Snapshot("x").Listeners["lab-tls"])
	}
}

// An expired sender CA is never trusted (item 5): a sender whose
// certificate is in its period but issued by an expired CA is refused at the
// handshake of a listener that requires sender certificates, and nothing is
// stored.
func TestExpiredSenderCAIsNeverTrusted(t *testing.T) {
	var p, senders *nodeconfigtest.PKI
	nc, dir := listenConfig(t, func(nc *nodeconfigtest.Config) {
		var err error
		if p, err = nc.WritePKI("127.0.0.1", "test-ca", "test-client"); err != nil {
			t.Fatal(err)
		}
		if _, err := nc.WriteListenerCredential(p, "test-listener", "127.0.0.1"); err != nil {
			t.Fatal(err)
		}
		if senders, err = nc.WritePKIValid("127.0.0.1", "sender-ca", "sender-client", nodeconfigtest.Validity{CA: expired()}); err != nil {
			t.Fatal(err)
		}
		nc.AddListener("lab-tls", "syslog-tls", "127.0.0.1:0")
		nc.Listeners[0].TLS.SenderCARef = "sender-ca"
		nc.Listeners[0].TLS.RequireSenderCert = true
	})
	locked := *nc
	t.Cleanup(func() { locked.UnlockTLS() })
	lockTLS(t, nc)
	r, st, _ := start(t, parse(t, nc), dir)
	defer r.Close()
	ls := serve(t, r)
	if ls.Addr("lab-tls") == nil {
		t.Fatal("an expired sender CA held the listener back: it is a refused peer, not a period fault of the listener")
	}
	raw := dialFrom(t, "tcp", "127.0.0.1", ls.Addr("lab-tls"))
	c := tls.Client(raw, &tls.Config{RootCAs: p.Roots, ServerName: "127.0.0.1", Certificates: []tls.Certificate{senders.Client}, MinVersion: tls.VersionTLS12})
	c.SetDeadline(time.Now().Add(5 * time.Second))
	// With TLS 1.3 the refusal shows on the first read.
	if err := c.Handshake(); err == nil {
		c.Write([]byte("<13>1 - - - - - - from an expired CA\n"))
		if _, err := c.Read(make([]byte, 1)); err == nil {
			t.Fatal("a sender certified by an expired CA was read from")
		}
	}
	// The listener counts the refusal when its own handshake returns, which
	// can be after the sender saw the alert (Windows CI, #290).
	var got ListenerStatus
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		ls.Publish()
		if got = st.Snapshot("x").Listeners["lab-tls"]; got.Refused["tls"] >= 1 {
			break
		}
	}
	if got.Stored != 0 || got.Received != 0 || got.Refused["tls"] < 1 {
		t.Fatalf("status %+v", got)
	}
}

// A required target held back keeps its events: the store never prunes what
// the target has not confirmed, the quota fills, and every alarm is raised
// in order, with no silent prune (item 7). Evidence class: simulated.
func TestHeldRequiredTargetPastItsQuota(t *testing.T) {
	const quota = 64 << 10
	nc, _, _ := forwardConfigValid(t, 9, nodeconfigtest.Validity{Client: expired()}, func(nc *nodeconfigtest.Config) {
		nc.Store.Quotas["platform"] = quota
	})
	lockTLS(t, nc)
	c := parse(t, nc)
	var mu sync.Mutex
	now := time.Now()
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	advance := func(d time.Duration) { mu.Lock(); now = now.Add(d); mu.Unlock() }
	st := NewStatus("", nil, clock)
	r, err := Start(bg, c, RuntimeOptions{Status: st, Now: clock, Group: c5.GroupOptions{MaxEvents: 10, MaxWait: 5 * time.Millisecond}})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	fw, err := NewForwarding(r)
	if err != nil {
		t.Fatal(err)
	}
	db := r.Store(HealthStream)
	firstBefore, _ := db.FirstRetained(bg, HealthStream)
	fw.Check(bg)
	advance(UnreachableAfter + time.Second)
	fw.Check(bg)
	codes := func() (out []string) {
		for _, a := range st.Snapshot("x").Alarms {
			if len(out) == 0 || out[len(out)-1] != a.Code {
				out = append(out, a.Code)
			}
		}
		return out
	}
	for i := 0; i < 2000 && !slices.Contains(codes(), string(c5.AlarmQuotaReached)); i++ {
		r.health(bg, HealthCollectionRun, map[string]string{"n": "filler"})
	}
	full, _ := db.LastCommitted(bg, HealthStream)
	for i := 0; i < 3; i++ {
		advance(time.Minute)
		fw.Check(bg)
		r.Prune(bg)
		r.Tick(bg)
		// One more event each tick: past the quota it must be refused, not
		// stored by pruning something unconfirmed (B6 on #290).
		r.health(bg, HealthCollectionRun, map[string]string{"n": "after the quota"})
	}
	// The alarms come in this order, each once: held back at start, then
	// unreachable once a minute has passed, then the store's own warning
	// and quota alarms as the unconfirmed events fill the class.
	order := []string{AlarmTargetHeldBack, AlarmForwardUnreachable, string(c5.AlarmQuotaWarning), string(c5.AlarmQuotaReached)}
	got := codes()
	at := -1
	for _, want := range order {
		i := slices.Index(got[at+1:], want)
		if i < 0 {
			t.Fatalf("alarm %s missing or out of order: %v", want, got)
		}
		at += 1 + i
	}
	for _, code := range []string{AlarmTargetHeldBack, AlarmForwardUnreachable} {
		var n int
		for _, a := range st.Snapshot("x").Alarms {
			if a.Code == code && a.Target == "central" {
				n++
			}
		}
		if n != 1 {
			t.Fatalf("%d %s alarms for one condition", n, code)
		}
	}
	if slices.Contains(got, string(c5.AlarmPruneFailed)) {
		t.Fatalf("a prune ran and failed: %v", got)
	}
	// Nothing was pruned: the target has confirmed nothing, so every event
	// is still stored, from the first, and the full class took no more.
	last, _ := db.LastCommitted(bg, HealthStream)
	first, _ := db.FirstRetained(bg, HealthStream)
	if first != firstBefore || last != full {
		t.Fatalf("first retained %d (was %d), last %d (was %d when full): events were pruned or stored past the quota", first, firstBefore, last, full)
	}
	if rows, err := db.Read(bg, HealthStream, 0, int(last)+10); err != nil || len(rows) != int(last)-int(first)+1 {
		t.Fatalf("%d events readable, want %d: %v", len(rows), int(last)-int(first)+1, err)
	}
	cur, err := db.LoadCursors(bg, HealthStream)
	if err != nil {
		t.Fatal(err)
	}
	for _, cu := range cur {
		if cu.Through != 0 {
			t.Fatalf("cursor %+v moved: the held target confirmed nothing", cu)
		}
	}
	if st.Snapshot("x").Targets["central"].HeldBack != "expired" {
		t.Fatal("the target left the held-back state")
	}
}

// A period fault does not hide another fault: an expired client certificate
// whose name is not the target's permitted_peer still stops the node (item
// 2), and so does one whose key does not match.
func TestExpiredCertWithAnotherFaultStillStopsTheNode(t *testing.T) {
	nc, _, dir := forwardConfigValid(t, 9, nodeconfigtest.Validity{Client: expired()}, func(nc *nodeconfigtest.Config) {
		nc.Targets[0]["durable_ack"].(map[string]any)["permitted_peer"] = "site-b-node1"
	})
	lockTLS(t, nc)
	r, _, _ := start(t, parse(t, nc), dir)
	defer r.Close()
	if _, err := NewForwarding(r); err == nil || errors.Is(err, forward.ErrCertificatePeriod) {
		t.Fatalf("an expired certificate with the wrong name: %v", err)
	}
}

// The same for a listener: an expired certificate that is also not for
// server authentication is no period fault alone, so the node stops at start
// and does not hold the listener back (B3 on #290).
func TestExpiredListenerCertWithAnotherFaultStillStopsTheNode(t *testing.T) {
	nc, dir := listenConfig(t, func(nc *nodeconfigtest.Config) {
		p, err := nc.WritePKI("127.0.0.1", "test-ca", "test-client")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := nc.WriteListenerCredentialUsage(p, "test-listener", "127.0.0.1", x509.ExtKeyUsageClientAuth, expired()); err != nil {
			t.Fatal(err)
		}
		nc.AddListener("lab-tls", "syslog-tls", "127.0.0.1:0")
	})
	locked := *nc
	t.Cleanup(func() { locked.UnlockTLS() })
	lockTLS(t, nc)
	r, _, _ := start(t, parse(t, nc), dir)
	defer r.Close()
	if _, err := NewListening(r); err == nil || errors.Is(err, receive.ErrCertificatePeriod) {
		t.Fatalf("an expired listener certificate for client authentication: %v", err)
	}
}

// A held listener whose period becomes valid after Run has returned is not
// bound: the node's last Publish at shutdown must not open a socket that
// nothing serves or closes (B6 on #290).
func TestHeldListenerIsNotBoundAfterRun(t *testing.T) {
	notYetRun(t, func(period nodeconfigtest.Period, w window) bool {
		addr := freeAddr(t)
		nc, dir := listenConfig(t, func(nc *nodeconfigtest.Config) {
			p, err := nc.WritePKI("127.0.0.1", "test-ca", "test-client")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := nc.WriteListenerCredentialValid(p, "test-listener", "127.0.0.1", period); err != nil {
				t.Fatal(err)
			}
			nc.AddListener("lab-tls", "syslog-tls", addr)
		})
		locked := *nc
		t.Cleanup(func() { locked.UnlockTLS() })
		lockTLS(t, nc)
		r, _, _ := start(t, parse(t, nc), dir)
		defer r.Close()
		ls, err := NewListening(r)
		if err != nil {
			t.Fatal(err)
		}
		if err := ls.Listen(); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(bg)
		done := make(chan struct{})
		go func() { defer close(done); ls.Run(ctx) }()
		cancel()
		<-done
		// Run returned while the listener was held.
		if !w.open() {
			return true
		}
		// The period becomes valid only now.
		time.Sleep(time.Until(w.begin) + 500*time.Millisecond)
		ls.Publish()
		if ls.Addr("lab-tls") != nil {
			t.Fatal("the held listener was bound after Run returned")
		}
		if c, err := net.DialTimeout("tcp", addr, time.Second); err == nil {
			c.Close()
			t.Fatal("a socket opened after Run returned accepts connections")
		}
		return false
	})
}
