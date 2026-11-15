package node

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"strings"
	"testing"
	"time"
)

// D6 scratch probe for the review of #705; never merged. It is
// TestLinkKeyAnotherFaultAlarms with manager steps asked for inside the
// rewrite window, and time for them to run: after the unlock and after the
// rewrite. Fenced (the change under heldManager, as #705 does) it must
// pass; unfenced (the change as before #705) it must fail with an
// intermediate alarm, which shows the probe reaches the window.
func d6Probe705(t *testing.T, fenced bool) {
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
	gap := func() {
		r.kickSensorManager()
		time.Sleep(300 * time.Millisecond)
	}
	change := func() {
		if err := nc.UnlockTLS(); err != nil {
			t.Fatal(err)
		}
		gap()
		writeLinkKeyFile(t, nc, pub)
		gap()
		lockTLS(t, nc)
	}
	if fenced {
		heldManager(r, change)
	} else {
		change()
	}
	sensorStep(t, r)
	sensorStep(t, r)
	got := linkKeyAlarms(st)
	if len(got) != 2 || !strings.Contains(got[1], "the provider is not available, has no key") {
		t.Fatalf("sensor-link-key alarms %q; want a second one naming the missing key", got)
	}
}

func TestD6Probe705Fenced(t *testing.T)   { d6Probe705(t, true) }
func TestD6Probe705Unfenced(t *testing.T) { d6Probe705(t, false) }
