package node

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"otsec.local/otsec/modules/security/nodekey"
	"otsec.local/otsec/platform/node/nodeconfigtest"
)

// D6's N2 and N3 on #685: the link key's claims that had no test. Desk
// only, as linkkey_test.go.

// A different fault raises sensor-link-key again, and the same fault does
// not (self-check item 6; D6's N2 and P3 on #685): a malformed file raises
// it once; the file then naming a key the provider lacks raises it a
// second time, naming the new cause; another step raises nothing more.
// Control: the alarm raised for the first fault only (m.linkFault == "").
func TestLinkKeyAnotherFaultAlarms(t *testing.T) {
	nc, _, _, dir := linkKeyConfig(t, true)
	writeTLSFile(t, nc, LinkKeyFileName, []byte(`{"format":`))
	lockTLS(t, nc)
	r, st := startSeams(t, parse(t, nc), dir, SensorSeams{})
	defer r.Close()
	resolveKeys(t, r)
	if got := linkKeyAlarms(st); len(got) != 1 || !strings.Contains(got[0], "malformed") {
		t.Fatalf("sensor-link-key alarms %q; want one naming the malformed file", got)
	}
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	// The manager is held while tls_dir is unlocked and the file rewritten,
	// so no step reads a half-written file or the unlocked directory, each
	// of which is a fault of its own and raises the alarm too.
	heldManager(r, func() {
		if err := nc.UnlockTLS(); err != nil {
			t.Fatal(err)
		}
		writeLinkKeyFile(t, nc, pub)
		lockTLS(t, nc)
	})
	sensorStep(t, r)
	sensorStep(t, r)
	got := linkKeyAlarms(st)
	if len(got) != 2 || !strings.Contains(got[1], "the provider is not available, has no key") {
		t.Fatalf("sensor-link-key alarms %q; want a second one naming the missing key", got)
	}
}

// A loaded link key is kept until a restart (D6's N2 and P5 on #685): with
// the file replaced by one naming another key, more steps keep the first
// key's pin and raise nothing; after a restart the node loads the new key.
// Control: a loaded key read again at each step (the guard on m.linkKey
// removed), which shows the new pin before the restart.
func TestLinkKeyKeptUntilRestart(t *testing.T) {
	nc, _, _, dir := linkKeyConfig(t, true)
	first := writeLinkKeyFile(t, nc, newLinkKey(t, nc))
	lockTLS(t, nc)
	c := parse(t, nc)
	r, st := startSeams(t, c, dir, SensorSeams{})
	resolveKeys(t, r)
	if pin := linkPin(st); pin != first {
		r.Close()
		t.Fatalf("pin %q; want %q", pin, first)
	}
	if err := nc.UnlockTLS(); err != nil {
		r.Close()
		t.Fatal(err)
	}
	// A second key under the same reference and version replaces the first.
	if err := os.Remove(filepath.Join(nc.TLSDir, nodekey.KeyName(linkRef, 1)+".p8")); err != nil {
		r.Close()
		t.Fatal(err)
	}
	second := writeLinkKeyFile(t, nc, newLinkKey(t, nc))
	lockTLS(t, nc)
	sensorStep(t, r)
	sensorStep(t, r)
	pin, alarms := linkPin(st), linkKeyAlarms(st)
	r.Close()
	if pin != first || len(alarms) != 0 {
		t.Fatalf("after the file changed: pin %q, alarms %q; want the first pin %q kept and no alarm", pin, alarms, first)
	}
	r, st = startSeams(t, c, dir, SensorSeams{})
	defer r.Close()
	resolveKeys(t, r)
	if pin := linkPin(st); pin != second {
		t.Fatalf("pin %q after the restart; want the new key's %q", pin, second)
	}
}

// Run hands the sensor manager the register (D6's N3 and P1 on #685): a
// node run through Run with the network_sensor section and no link key
// file raises sensor-link-key, so the manager read the file after Run's
// start. Control: the KeysResolved call removed from RunFrom, after which
// nothing reads the key and no alarm comes.
func TestRunReadsLinkKey(t *testing.T) {
	c, _ := schedConfig(t, func(nc *nodeconfigtest.Config) {
		sensorQuotas(nc)
		nc.NetworkSensor = sensorSection()
		nc.NetworkSensor["link_key_ref"] = linkRef
	})
	ctx, cancel := context.WithCancel(bg)
	defer cancel()
	var mu sync.Mutex
	var oslog []string
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, c, func(l string) { mu.Lock(); oslog = append(oslog, l); mu.Unlock() })
	}()
	alarmed := func() string {
		mu.Lock()
		defer mu.Unlock()
		for _, l := range oslog {
			if strings.Contains(l, AlarmSensorLinkKey) {
				return l
			}
		}
		return ""
	}
	var line string
	for deadline := time.Now().Add(time.Minute); line == "" && time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		line = alarmed()
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if line == "" {
		t.Fatal("no sensor-link-key alarm within a minute of Run: the link key was never read")
	}
}
