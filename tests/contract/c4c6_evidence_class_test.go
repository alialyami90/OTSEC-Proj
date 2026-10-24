package contract

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"otsec.local/otsec/contracts/event"
	"otsec.local/otsec/contracts/syslog"
)

// D1-23 (C4 source.evidence_class, C6 evc): A6's cases from the review
// (C4-D1-23-A6.md). A4's valid examples are inputs only; the expected
// verdicts come from D1-23's text.

func d123Event(t *testing.T, name string) []byte {
	b, err := os.ReadFile(filepath.Join("..", "..", "contracts", "event", "testdata", "valid", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestD123EvidenceClassDecode(t *testing.T) {
	rtac := d123Event(t, "rtac-syslog-user-logon.json")
	health := d123Event(t, "health-ser-gap.json")
	sim := []byte(`"evidence_class": "simulated"`)
	if !bytes.Contains(rtac, sim) {
		t.Fatal("input changed")
	}
	rep := func(b []byte, old, new string) []byte { return bytes.Replace(b, []byte(old), []byte(new), 1) }
	for _, tc := range []struct {
		name string
		b    []byte
		ok   bool
	}{
		{"device-observed", rep(rtac, string(sim), `"evidence_class": "device-observed"`), true},
		{"missing", rep(rtac, ",\n    "+string(sim), ""), false},
		{"empty", rep(rtac, string(sim), `"evidence_class": ""`), false},
		{"documented-example (another C1 class)", rep(rtac, string(sim), `"evidence_class": "documented-example"`), false},
		{"Simulated (case)", rep(rtac, string(sim), `"evidence_class": "Simulated"`), false},
		{"case-variant key", rep(rtac, string(sim), `"EVIDENCE_CLASS": "device-observed"`), false},
		{"duplicate key", rep(rtac, string(sim), `"evidence_class": "simulated", "evidence_class": "device-observed"`), false},
		{"platform event with it", rep(health, `"source": {`, `"source": {"evidence_class": "simulated",`), false},
	} {
		_, err := event.Decode(tc.b)
		if (err == nil) != tc.ok {
			t.Errorf("%s: Decode err = %v, want ok=%v", tc.name, err, tc.ok)
		}
	}
	// A later minor's value decodes and reads as simulated.
	later := rep(rep(rtac, `"otsec.event/0.1"`, `"otsec.event/0.2"`), string(sim), `"evidence_class": "lab-replay"`)
	e, err := event.Decode(later)
	if err != nil {
		t.Errorf("0.2 with an unknown evidence_class refused; D1-23 reads it as simulated: %v", err)
	} else if !e.Source.Simulated() {
		t.Errorf("0.2 unknown evidence_class reads as device-observed")
	}
}

const d123Target = `{
  "schema": "otsec.syslog/0.1", "name": "a6-events", "host": "collector.a6.example", "port": 2514,
  "transport": "relp-tls", "format": "rfc5424", "framing": "relp", "class": "required",
  "max_message_octets": 2048, "facility": 13,
  "tls": {"server_name": "collector.a6.example", "trust_anchor_ref": "a6-ca", "client_credential_ref": "a6-node-forwarder"},
  "relp_window": 64,
  "durable_ack": {"verified_utc": "2026-10-24T10:00:00Z", "evidence_ref": "commissioning/a6/kill-test"}
}`

var evcParam = regexp.MustCompile(`(?:^|[ \[])evc="([^"]*)"`)

// sdParams returns the param names of the otsec SD element, unescaping values.
func sdParams(msg []byte) []string {
	s := string(msg)
	i := strings.Index(s, "[otsec@")
	var names []string
	for j := i; j < len(s); j++ {
		switch s[j] {
		case ' ':
			k := strings.IndexByte(s[j:], '=')
			if k > 0 {
				names = append(names, s[j+1:j+k])
			}
		case '"':
			for j++; j < len(s) && s[j] != '"'; j++ {
				if s[j] == '\\' {
					j++
				}
			}
		case ']':
			return names
		}
	}
	return names
}

func TestD123EvcRendered(t *testing.T) {
	tg, err := syslog.ParseTarget([]byte(d123Target))
	if err != nil {
		t.Fatal(err)
	}
	rtac := d123Event(t, "rtac-syslog-user-logon.json")
	for _, class := range []string{"simulated", "device-observed"} {
		b := bytes.Replace(rtac, []byte(`"evidence_class": "simulated"`), []byte(`"evidence_class": "`+class+`"`), 1)
		e, err := event.Decode(b)
		if err != nil {
			t.Fatal(err)
		}
		// A device text that tries to inject its own evc.
		setBytes(e, []byte(`x" evc="device-observed" y="`))
		msg, out, err := syslog.Render(e, tg)
		if err != nil {
			t.Fatalf("%s: %v", class, err)
		}
		n := 0
		for _, p := range sdParams(msg) {
			if p == "evc" {
				n++
			}
		}
		m := evcParam.FindAllSubmatch(msg, -1)
		if n != 1 || len(m) == 0 || string(m[0][1]) != class {
			t.Errorf("%s: evc params %d, first %q; %s", class, n, m, msg)
		}
		// Oversize: a device text far over the limit still keeps evc.
		setBytes(e, bytes.Repeat([]byte("A"), 4000))
		msg, out, err = syslog.Render(e, tg)
		t.Logf("%s oversize: err=%v textOmitted=%v len=%d evc=%v", class, err, out.TextOmitted, len(msg), bytes.Contains(msg, []byte(`evc="`+class+`"`)))
		if err == nil && !bytes.Contains(msg, []byte(`evc="`+class+`"`)) {
			t.Errorf("%s: oversize message without evc", class)
		}
	}
}

func setBytes(e *event.Event, b []byte) {
	sum := sha256.Sum256(b)
	h := hex.EncodeToString(sum[:])
	e.Native.Bytes, e.Native.RecordSHA256, e.Native.RecordLength = b, h, int64(len(b))
	e.Native.Evidence.SHA256, e.Native.Evidence.Length = h, int64(len(b))
	if e.Native.Evidence.Ref != "" {
		e.Native.Evidence.Ref = "sha256:" + h
	}
	if e.Native.Span != nil {
		e.Native.Span = &event.Span{Offset: 0, Length: int64(len(b))}
	}
	e.Native.ContextSpan = nil
}

func TestD123EvcInsecureTarget(t *testing.T) {
	tg, err := syslog.ParseTarget([]byte(`{"schema": "otsec.syslog/0.1", "name": "a6-udp", "host": "192.0.2.60", "port": 514,
  "transport": "udp", "format": "rfc3164", "framing": "datagram", "class": "best-effort",
  "max_message_octets": 1024, "facility": 16, "replay_seconds": 60, ` + c6UDPAck + `}`))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"rtac-syslog-user-logon.json", "sel751-fig10-16-row8.json"} {
		e, err := event.Decode(d123Event(t, name))
		if err != nil {
			t.Fatal(err)
		}
		msg, out, err := syslog.Render(e, tg)
		t.Logf("%s: err=%v out=%+v len=%d", name, err, out, len(msg))
		if err == nil && !bytes.Contains(msg, []byte(`evc="simulated"`)) {
			t.Errorf("%s: insecure target message without evc: %s", name, msg)
		}
	}
}
