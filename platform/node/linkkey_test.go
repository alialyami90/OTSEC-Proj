package node

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"otsec.local/otsec/modules/security/linkkey"
	"otsec.local/otsec/modules/security/nodekey"
	"otsec.local/otsec/platform/node/nodeconfigtest"
	"otsec.local/otsec/platform/store"
)

// Brief P4-4-F27, deliverable (4), D5's half: F11's wiring of D3's link
// key reader (docs/phase4/D5-sensor-node.md section 1.9 item 11; D3's
// NK-1 to NK-6). Every leg reads a local file and dials nothing: the
// dialer is not built (D4-96), so the "no SYN" and "no dial" legs are owed
// by the dialer-and-enrolment brief. Desk only: no sensor and no device;
// the keys are lab-files keys in a temporary tls_dir.

// linkRef is the link key's reference in these tests.
const linkRef = "nodekey_link0001"

// linkKeyConfig is a node with a scheduled SER read, the network_sensor
// section naming linkRef, and a key register (lab-files keys in tls_dir)
// with a client key, a listener key for 127.0.0.1 and trust anchors. The
// caller writes the link key file, then locks tls_dir.
func linkKeyConfig(t *testing.T, section bool) (*nodeconfigtest.Config, *nodeconfigtest.PKI, *nodekey.Register, string) {
	t.Helper()
	dir := t.TempDir()
	storeDir := filepath.Join(dir, "store")
	if err := store.CreateDir(storeDir, ""); err != nil {
		t.Fatal(err)
	}
	nc := nodeconfigtest.New("site-a-node1", storeDir).AddSEL751(relayID, "", 2323, 300)
	p, err := nc.WritePKI("127.0.0.1", "test-ca", "test-client")
	if err != nil {
		t.Fatal(err)
	}
	locked := *nc
	t.Cleanup(func() { locked.UnlockTLS() })
	reg, err := nc.WriteKeyRegister(p, "127.0.0.1", time.Now().Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if section {
		sensorQuotas(nc)
		nc.NetworkSensor = sensorSection()
		nc.NetworkSensor["link_key_ref"] = linkRef
	}
	if err := nc.WriteInstallKey(testInstallKey); err != nil {
		t.Fatal(err)
	}
	return nc, p, reg, dir
}

// newLinkKey makes a lab-files key for linkRef at version 1 and returns its
// public key (PKIX DER).
func newLinkKey(t *testing.T, nc *nodeconfigtest.Config) []byte {
	t.Helper()
	k, err := nodekey.LabFiles{Dir: nc.TLSDir}.Create(nodekey.KeyName(linkRef, 1))
	if err != nil {
		t.Fatal(err)
	}
	pub, err := x509.MarshalPKIXPublicKey(k.Public())
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

// writeLinkKeyFile writes a link key file with one active lab-files entry
// for linkRef at version 1 with public key pub, and returns its pin.
func writeLinkKeyFile(t *testing.T, nc *nodeconfigtest.Config, pub []byte) string {
	t.Helper()
	h := sha256.Sum256(pub)
	fp := hex.EncodeToString(h[:])
	f := linkkey.File{Format: linkkey.Format, NodeID: nc.NodeID, Entries: []linkkey.Entry{{
		Ref: linkRef, Kind: linkkey.KindLinkKey, Version: 1, State: nodekey.StateActive, Provider: nodekey.ProviderLabFiles,
		PublicKey: pub, Fingerprint: fp, InstalledBy: nodeconfigtest.KeyAdmin, InstalledAt: time.Now().UTC().Format(time.RFC3339)}}}
	b, err := f.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	writeTLSFile(t, nc, LinkKeyFileName, b)
	return "sha256:" + fp
}

func writeTLSFile(t *testing.T, nc *nodeconfigtest.Config, name string, b []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(nc.TLSDir, name), b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// linkKeyAlarms are the details of status's sensor-link-key alarms.
func linkKeyAlarms(st *Status) (out []string) {
	for _, a := range st.Snapshot("x").Alarms {
		if a.Code == AlarmSensorLinkKey {
			out = append(out, a.Detail)
		}
	}
	return out
}

// linkPin is the link key's pin in status, "" without the sensor section.
func linkPin(st *Status) string {
	if s := st.Snapshot("x").Sensor; s != nil {
		return s.LinkKeyPin
	}
	return ""
}

// resolveKeys does what Run does once Start has returned: it records the
// register's entries, which loads the register if no reference has, and
// hands it to the sensor manager, then waits for the manager's step.
func resolveKeys(t *testing.T, r *Runtime) {
	t.Helper()
	r.RecordNodeKeys(bg)
	r.KeysResolved()
	sensorStep(t, r)
}

// TestLinkKeyFaultNodeStarts, its start leg (section 1.9 item 11; NK-5;
// D2's N2 on #672): with the link key file missing, unreadable (a
// directory, or a file the protected-file rule refuses), malformed, naming
// a key the provider does not have, or with link_key_ref unset, read
// through protect.ReadFile, the node starts, a scheduled run is sent and
// stores its rows, sensor-link-key stands once naming the cause, at the
// first step and after more, and status shows no pin. A missing file put
// in place later loads at the next step, with no restart and no second
// alarm. A good file loads and status shows its pin. Control: the file
// read inside Start, which fails the start. The "no SYN" leg needs the
// dialer and is owed by the dialer-and-enrolment brief.
func TestLinkKeyFaultNodeStarts(t *testing.T) {
	cases := []struct {
		name  string
		setup func(t *testing.T, nc *nodeconfigtest.Config)
		after func(t *testing.T, nc *nodeconfigtest.Config) // once tls_dir is locked
		want  string
	}{
		{name: "missing", want: "the link key file is missing"},
		{name: "a directory", want: "cannot be read", setup: func(t *testing.T, nc *nodeconfigtest.Config) {
			if err := os.Mkdir(filepath.Join(nc.TLSDir, LinkKeyFileName), 0o700); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "not protected", want: "cannot be read", setup: func(t *testing.T, nc *nodeconfigtest.Config) {
			writeLinkKeyFile(t, nc, newLinkKey(t, nc))
		}, after: func(t *testing.T, nc *nodeconfigtest.Config) {
			if err := nc.LoosenTLS(LinkKeyFileName); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "malformed", want: "malformed", setup: func(t *testing.T, nc *nodeconfigtest.Config) {
			writeTLSFile(t, nc, LinkKeyFileName, []byte(`{"format":`))
		}},
		{name: "no key in the provider", want: "the provider is not available, has no key", setup: func(t *testing.T, nc *nodeconfigtest.Config) {
			k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			pub, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
			if err != nil {
				t.Fatal(err)
			}
			writeLinkKeyFile(t, nc, pub)
		}},
		{name: "link_key_ref unset", want: "link_key_ref is", setup: func(t *testing.T, nc *nodeconfigtest.Config) {
			delete(nc.NetworkSensor, "link_key_ref")
			writeLinkKeyFile(t, nc, newLinkKey(t, nc))
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			nc, _, _, dir := linkKeyConfig(t, true)
			if tc.setup != nil {
				tc.setup(t, nc)
			}
			lockTLS(t, nc)
			if tc.after != nil {
				tc.after(t, nc)
			}
			r, st := startSeams(t, parse(t, nc), dir, SensorSeams{})
			defer r.Close()
			resolveKeys(t, r)
			got := linkKeyAlarms(st)
			if len(got) != 1 || !strings.Contains(got[0], tc.want) {
				t.Fatalf("sensor-link-key alarms %q; want one naming %q", got, tc.want)
			}
			runSent(t, r)
			sensorStep(t, r)
			if n := len(linkKeyAlarms(st)); n != 1 {
				t.Fatalf("%d sensor-link-key alarms after a second step; want 1", n)
			}
			if pin := linkPin(st); pin != "" {
				t.Fatalf("status shows the pin %s of a link key that did not load", pin)
			}
			if tc.name != "missing" {
				return
			}
			// The file put in place later loads at the next step.
			if err := nc.UnlockTLS(); err != nil {
				t.Fatal(err)
			}
			want := writeLinkKeyFile(t, nc, newLinkKey(t, nc))
			lockTLS(t, nc)
			sensorStep(t, r)
			if pin := linkPin(st); pin != want {
				t.Fatalf("pin %q after the file was put in place; want %q", pin, want)
			}
			if n := len(linkKeyAlarms(st)); n != 1 {
				t.Fatalf("%d sensor-link-key alarms after the key loaded; want 1", n)
			}
		})
	}
	t.Run("loads", func(t *testing.T) {
		nc, _, _, dir := linkKeyConfig(t, true)
		want := writeLinkKeyFile(t, nc, newLinkKey(t, nc))
		lockTLS(t, nc)
		r, st := startSeams(t, parse(t, nc), dir, SensorSeams{})
		defer r.Close()
		if pin := linkPin(st); pin != "" {
			t.Fatalf("the link key was read before KeysResolved: pin %s", pin)
		}
		resolveKeys(t, r)
		runSent(t, r)
		sensorStep(t, r)
		if got := linkKeyAlarms(st); len(got) != 0 {
			t.Fatalf("sensor-link-key alarms %q for a good link key", got)
		}
		if pin := linkPin(st); pin != want {
			t.Fatalf("pin %q; want %q", pin, want)
		}
	})
}

// TestLinkKeyClash, its alarm and listener legs (section 1.9 item 11;
// NK-2, with D4-101 item 4's register states): a link key whose public key
// is the listener's tls-key's is refused, sensor-link-key stands naming
// the clash, status shows no pin, and the tls-key still serves its
// listener, which stores a message sent over mutual TLS and presents that
// key; a scheduled run is stored. With key_register set and the register
// not loaded, the clash cannot be checked: the link key is refused with
// the alarm, and the node runs. Control: a reader with no clash check
// (ReadLinkKey given linkkey.NoRegister() whatever the register), which
// loads the shared key and the not-loaded one. The "no dial" legs need the
// dialer and are owed by the dialer-and-enrolment brief.
func TestLinkKeyClash(t *testing.T) {
	t.Run("a tls-key's public key", func(t *testing.T) {
		nc, p, reg, dir := linkKeyConfig(t, true)
		nc.AddSyslogSender(relayID, "syslog-tls-out", "syslog-tls", "127.0.0.1", 0)
		nc.AddListener("lab-tls", "syslog-tls", "127.0.0.1:0")
		nc.Listeners[0].TLS.CredentialRef = nodeconfigtest.ListenerKeyRef
		nc.Listeners[0].TLS.SenderCARef = nodeconfigtest.AnchorsRef
		nc.Listeners[0].TLS.RequireSenderCert = true
		var listenerPub []byte
		var version uint32
		for _, e := range reg.Entries {
			if e.Ref == nodeconfigtest.ListenerKeyRef && e.State == nodekey.StateActive {
				listenerPub, version = e.PublicKey, e.Version
			}
		}
		if listenerPub == nil {
			t.Fatal("no active listener key in the register")
		}
		// The listener's key under the link key's name too, so that a
		// reader with no clash check opens it (the control).
		der, err := os.ReadFile(filepath.Join(nc.TLSDir, nodekey.KeyName(nodeconfigtest.ListenerKeyRef, version)+".p8"))
		if err != nil {
			t.Fatal(err)
		}
		writeTLSFile(t, nc, nodekey.KeyName(linkRef, 1)+".p8", der)
		writeLinkKeyFile(t, nc, listenerPub)
		lockTLS(t, nc)
		r, st := startSeams(t, parse(t, nc), dir, SensorSeams{})
		defer r.Close()
		ls := serve(t, r)
		resolveKeys(t, r)
		got := linkKeyAlarms(st)
		if len(got) != 1 || !strings.Contains(got[0], "also a key of the node key register") {
			t.Fatalf("sensor-link-key alarms %q; want one naming the clash", got)
		}
		if pin := linkPin(st); pin != "" {
			t.Fatalf("status shows the pin %s of a link key that clashes", pin)
		}
		raw := dialFrom(t, "tcp", "127.0.0.1", ls.Addr("lab-tls"))
		c := tls.Client(raw, &tls.Config{RootCAs: p.Roots, ServerName: "127.0.0.1", Certificates: []tls.Certificate{p.Client}, MinVersion: tls.VersionTLS12})
		c.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := c.Write([]byte("<13>1 - - - - - - the listener's key still serves\n")); err != nil {
			t.Fatal(err)
		}
		leaf := c.ConnectionState().PeerCertificates[0]
		if spki, err := x509.MarshalPKIXPublicKey(leaf.PublicKey); err != nil || string(spki) != string(listenerPub) {
			t.Fatalf("the listener presented another key: %v", err)
		}
		waitStored(t, ls, st, "lab-tls", 1)
		runSent(t, r)
		sensorStep(t, r)
		if n := len(linkKeyAlarms(st)); n != 1 {
			t.Fatalf("%d sensor-link-key alarms after a second step; want 1", n)
		}
	})
	t.Run("register set and not loaded", func(t *testing.T) {
		nc, _, _, dir := linkKeyConfig(t, true)
		writeLinkKeyFile(t, nc, newLinkKey(t, nc))
		writeTLSFile(t, nc, "register.json", []byte(`{"format":`))
		lockTLS(t, nc)
		r, st := startSeams(t, parse(t, nc), dir, SensorSeams{})
		defer r.Close()
		resolveKeys(t, r)
		got := linkKeyAlarms(st)
		if len(got) != 1 || !strings.Contains(got[0], "set and not loaded") {
			t.Fatalf("sensor-link-key alarms %q; want one naming the register not loaded", got)
		}
		if pin := linkPin(st); pin != "" {
			t.Fatalf("status shows the pin %s with the register not loaded", pin)
		}
		runSent(t, r)
	})
}

// NK-6's node leg (D3's NK-6; owed by #672 to this PR): a node without the
// network_sensor section, so with no sensor manager, starts with a key
// register and a link key file beside it that would fail any read; it
// records every register entry, a scheduled run is stored, and nothing
// reads the file: no sensor-link-key alarm and no node-key-not-recorded.
// Control: the register's loader (nodeKeys) also reading the link key file
// beside it and refusing on its fault, the coupling F11 named, which
// leaves the entries unrecorded with the alarm.
func TestLinkKeyFileIgnoredWithoutSensor(t *testing.T) {
	nc, _, reg, dir := linkKeyConfig(t, false)
	writeTLSFile(t, nc, LinkKeyFileName, []byte(`{"format":`))
	lockTLS(t, nc)
	r, st := startSeams(t, parse(t, nc), dir, SensorSeams{})
	defer r.Close()
	if left := r.RecordNodeKeys(bg); left != 0 {
		t.Fatalf("%d register entries not recorded", left)
	}
	r.KeysResolved()
	runSent(t, r)
	if n := len(keyRecords(t, r)); n != len(reg.Entries) {
		t.Fatalf("%d register entries recorded; want %d", n, len(reg.Entries))
	}
	for _, a := range st.Snapshot("x").Alarms {
		if a.Code == AlarmSensorLinkKey || a.Code == AlarmNodeKeyNotRecorded {
			t.Fatalf("alarm %s: %s", a.Code, a.Detail)
		}
	}
}
