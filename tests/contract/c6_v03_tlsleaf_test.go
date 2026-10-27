package contract

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"otsec.local/otsec/contracts/event"
	"otsec.local/otsec/contracts/syslog"
)

// C6 0.3 tlsleaf (A4, #170): A6's cases. The expected results come from
// the rule text (contracts/syslog/doc.go and render.go): tlsleaf is the C4
// 0.2 fingerprint, written on every event that carries one and on no
// other, it counts against the size limit like every parameter, and it is
// never dropped to fit. The threshold is not searched for: the same
// event rendered with and without its fingerprint (C4 0.1 has none) must
// differ by exactly ` tlsleaf="<64 hex>"`, 75 octets, and the size steps
// are then checked at limits set from those two lengths, and a sweep
// down to the smallest message checks the fingerprint is never dropped.

func c6Target(t *testing.T, name string) *syslog.Target {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "contracts", "syslog", "testdata", "targets", "valid", name))
	if err != nil {
		t.Fatal(err)
	}
	tg, err := syslog.ParseTarget(b)
	if err != nil {
		t.Fatal(err)
	}
	return tg
}

func TestC6V03TLSLeaf(t *testing.T) {
	src := d123Event(t, "constructed-rtac-tls-mutual.json")
	withLeaf, err := event.Decode(src)
	if err != nil {
		t.Fatal(err)
	}
	leaf := withLeaf.Source.Sender.TLSLeafSHA256
	if len(leaf) != 64 || withLeaf.Source.OriginAuth != event.AuthTLSMutual {
		t.Fatalf("input changed: %q %s", leaf, withLeaf.Source.OriginAuth)
	}
	// The same event at C4 0.1, which has no fingerprint; ev keeps its length.
	noLeaf, err := event.Decode(bytes.Replace(bytes.Replace(src, []byte(`"otsec.event/0.2"`), []byte(`"otsec.event/0.1"`), 1),
		[]byte(`,
      "tls_leaf_sha256": "`+leaf+`"`), nil, 1))
	if err != nil || noLeaf.Source.Sender.TLSLeafSHA256 != "" {
		t.Fatalf("the 0.1 form: %v (input changed?)", err)
	}
	param := ` tlsleaf="` + leaf + `"`
	if len(param) != 75 {
		t.Fatalf("parameter is %d octets", len(param))
	}

	for _, name := range []string{"relp-tls-required.json", "relp-plain-best-effort.json", "tls-best-effort.json", "udp-rfc3164.json", "tcp-lf-insecure.json"} {
		t.Run(name, func(t *testing.T) {
			tg := c6Target(t, name)
			for _, n := range []int{syslog.MaxMaxOctets, 8192, 1024} {
				if tg.MaxMessageOctets = n; tg.Validate() == nil {
					break
				}
			}
			a, _, err := syslog.Render(withLeaf, tg)
			if err != nil {
				t.Fatal(err)
			}
			b, _, err := syslog.Render(noLeaf, tg)
			if err != nil {
				t.Fatal(err)
			}
			m, err := syslog.ParseMessage(a)
			if err != nil {
				t.Fatal(err)
			}
			if v, ok := m.Get("tlsleaf"); !ok || v != leaf {
				t.Errorf("tlsleaf %q %v, want the event's fingerprint", v, ok)
			}
			if v, _ := m.Get("v"); v != "otsec.syslog/0.3" {
				t.Errorf("v %q", v)
			}
			if n, _ := syslog.ParseMessage(b); n != nil {
				if _, ok := n.Get("tlsleaf"); ok {
					t.Error("tlsleaf on an event without a fingerprint")
				}
			}
			if strings.Count(string(a), "tlsleaf=") != 1 {
				t.Errorf("tlsleaf written %d times", strings.Count(string(a), "tlsleaf="))
			}
			// Exactly the parameter apart, and only the parameter (ev differs
			// in one digit).
			if len(a)-len(b) != 75 {
				t.Errorf("with and without the fingerprint: %d and %d octets, want 75 apart", len(a), len(b))
			}
			if !bytes.Contains(a, []byte(param)) {
				t.Errorf("tlsleaf is not written as %s", param)
			}

			// The size steps. Text-bearing targets only.
			if !tg.SendsDeviceContent() {
				return
			}
			at := func(limit int) ([]byte, syslog.Outcome, error) {
				t.Helper()
				tl := *tg
				tl.MaxMessageOctets = limit
				if err := tl.Validate(); err != nil {
					t.Skipf("limit %d not valid for this target: %v", limit, err)
				}
				return syslog.Render(withLeaf, &tl)
			}
			// At its own length the message fits whole.
			if msg, out, err := at(len(a)); err != nil || out.TextOmitted || out.SummaryDropped || !bytes.Equal(msg, a) {
				t.Errorf("at %d octets: %v %+v", len(a), err, out)
			}
			// At the length without the fingerprint it no longer fits: the
			// text is omitted, never the fingerprint.
			msg, out, err := at(len(b))
			if err != nil || !out.TextOmitted || len(msg) > len(b) {
				t.Fatalf("at %d octets: %v %+v %d", len(b), err, out, len(msg))
			}
			mm, _ := syslog.ParseMessage(msg)
			if v, _ := mm.Get("tlsleaf"); v != leaf {
				t.Errorf("text omitted: tlsleaf %q", v)
			}
			// Drop the summary too: the smallest message is the one with
			// neither; one octet less is too large, never a message without
			// the fingerprint.
			bare := 0
			for limit := len(msg); limit >= syslog.MinMaxOctets; limit-- {
				m2, out2, err := at(limit)
				if err != nil {
					bare = limit + 1
					if !strings.Contains(err.Error(), "too") {
						t.Errorf("at %d: %v", limit, err)
					}
					break
				}
				p2, _ := syslog.ParseMessage(m2)
				if v, _ := p2.Get("tlsleaf"); v != leaf {
					t.Fatalf("at %d octets (%+v): tlsleaf %q", limit, out2, v)
				}
			}
			t.Logf("whole %d, without the fingerprint %d, text omitted %d, smallest %d", len(a), len(b), len(msg), bare)
		})
	}
}
