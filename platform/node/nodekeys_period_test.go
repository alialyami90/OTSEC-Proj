package node

import (
	"crypto/tls"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"otsec.local/otsec/modules/security/nodekey"
	"otsec.local/otsec/modules/telemetry/forward/relptest"
	"otsec.local/otsec/platform/node/nodeconfigtest"
)

// D4-17: the node key register takes the same rule as the lab files (HR-13,
// D4-11). A certificate outside its validity period holds back its own link
// only; any other fault of the same certificate still stops the node; an
// expired trust anchor is loaded and never trusted. Evidence class:
// simulated (loopback; lab-files keys in tls_dir).

// keyConfigValid is keyConfig with the test CA's validity set.
func keyConfigValid(t *testing.T, v nodeconfigtest.Validity, host string, notAfter time.Time) (*nodeconfigtest.Config, *nodeconfigtest.PKI, *nodekey.Register, string) {
	t.Helper()
	nc, p, dir := forwardConfigValid(t, 1, v, nil)
	reg, err := nc.WriteKeyRegisterAt(p, host, notAfter, notAfter.Add(-10*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
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

func pastEnd() time.Time { return time.Now().Add(-30 * time.Minute) }

// An expired client key in the register holds back its target: the node
// starts, the forwarder is not run, nothing is dialled, and the alarm names
// the target.
func TestKeyRegisterExpiredClientHoldsItsTarget(t *testing.T) {
	nc, p, _, dir := keyConfigValid(t, nodeconfigtest.Validity{}, "", pastEnd())
	srv, err := relptest.Start(p.ServerTLS("site-a-node1"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	nc.Targets[0]["port"] = srv.Addr().Port
	lockTLS(t, nc)
	r, st, _ := start(t, parse(t, nc), dir)
	defer r.Close()
	fw, err := NewForwarding(r)
	if err != nil {
		t.Fatalf("an expired client key in the register stopped the node: %v", err)
	}
	runForwarding(t, fw)
	fw.Check(bg)
	if got := st.Snapshot("x").Targets["central"]; got.HeldBack != "expired" || got.LastErr != "" {
		t.Fatalf("target: held back %q, last error %q", got.HeldBack, got.LastErr)
	}
	if a := statusAlarms(st, AlarmTargetHeldBack, "central"); len(a) != 1 {
		t.Fatalf("held-back alarms %+v", a)
	}
	time.Sleep(300 * time.Millisecond)
	if n := srv.Conns(); n != 0 {
		t.Fatalf("the held target's collector saw %d connections", n)
	}
}

// An expired listener key holds back its listener: it binds nothing, and
// the node and its other listeners run.
func TestKeyRegisterExpiredListenerKeyHoldsItsListener(t *testing.T) {
	nc, _, _, dir := keyConfigValid(t, nodeconfigtest.Validity{}, "127.0.0.1", pastEnd())
	nc.AddSyslogSender(relayID, "syslog-tls-out", "syslog-tls", "127.0.0.1", 0)
	nc.AddSyslogSender(relayID, "syslog-udp-out", "syslog-udp", "127.0.0.1", 0)
	nc.AddListener("lab-tls", "syslog-tls", "127.0.0.1:0")
	nc.AddListener("lab-udp", "syslog-udp", "127.0.0.1:0")
	nc.Listeners[0].TLS.CredentialRef = nodeconfigtest.ListenerKeyRef
	lockTLS(t, nc)
	r, st, _ := start(t, parse(t, nc), dir)
	defer r.Close()
	ls := serve(t, r)
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if ls.Publish(); st.Snapshot("x").Listeners["lab-udp"].Open {
			break
		}
	}
	snap := st.Snapshot("x")
	if snap.Listeners["lab-tls"].HeldBack != "expired" || snap.Listeners["lab-udp"].HeldBack != "" || !snap.Listeners["lab-udp"].Open {
		t.Fatalf("listeners: %+v", snap.Listeners)
	}
	if ls.Addr("lab-tls") != nil {
		t.Fatalf("the held listener is bound to %v", ls.Addr("lab-tls"))
	}
	if len(statusAlarms(st, AlarmListenerHeldBack, "listener lab-tls")) != 1 {
		t.Fatalf("alarms %+v", snap.Alarms)
	}
}

// An expired key that is also missing its private key is no period fault
// alone: the node stops, as it does for a lab file with another fault.
func TestKeyRegisterExpiredWithAnotherFaultStillStopsTheNode(t *testing.T) {
	nc, _, _, dir := keyConfigValid(t, nodeconfigtest.Validity{}, "", pastEnd())
	if err := os.Remove(filepath.Join(nc.TLSDir, "otsec-"+nodeconfigtest.ClientKeyRef+"-v1.p8")); err != nil {
		t.Fatal(err)
	}
	lockTLS(t, nc)
	r, _, _ := start(t, parse(t, nc), dir)
	defer r.Close()
	_, err := NewForwarding(r)
	if err == nil || errors.Is(err, nodekey.ErrCertificatePeriod) {
		t.Fatalf("an expired key whose private key is gone: %v", err)
	}
}

// An expired trust anchor in the register is loaded and never trusted: the
// node starts, and its TLS configuration refuses a collector that chains to
// it, with the expiry named.
func TestKeyRegisterExpiredAnchorIsNeverTrusted(t *testing.T) {
	nc, p, _, _ := keyConfigValid(t, nodeconfigtest.Validity{CA: expired()}, "", time.Now().Add(time.Hour))
	lockTLS(t, nc)
	c := parse(t, nc)
	tlsCfg, err := c.TargetTLS(c.targets[0])
	if err != nil {
		t.Fatalf("an expired trust anchor in the register stopped the node at load: %v", err)
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
}
