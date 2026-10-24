package syslog

import (
	"bytes"
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"

	"otsec.local/otsec/contracts/audit"
)

// chainNode is the node of C8's chain example.
const chainNode = "site-a-node-1"

// loadChain reads C8's six chained example records as sealed bytes.
func loadChain(t *testing.T) [][]byte {
	t.Helper()
	b, err := os.ReadFile("../audit/testdata/chain/slice-session.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	var out [][]byte
	for _, l := range bytes.Split(bytes.TrimSuffix(b, []byte("\n")), []byte("\n")) {
		out = append(out, l)
	}
	return out
}

// Golden audit renderings: C8 chain records on the audit target, frozen.
var auditGoldens = []struct {
	file  string
	index int
}{
	{"audit-chain-start.rfc5424.txt", 0},
	{"audit-device-refused.rfc5424.txt", 3},
}

func TestGoldenAuditRenderings(t *testing.T) {
	chain := loadChain(t)
	tg := loadTarget(t, "relp-tls-audit")
	for _, g := range auditGoldens {
		got, err := RenderAudit(chain[g.index], tg)
		if err != nil {
			t.Fatalf("%s: %v", g.file, err)
		}
		path := "testdata/rendered/" + g.file
		if *update {
			if err := os.WriteFile(path, got, 0o644); err != nil {
				t.Fatal(err)
			}
			continue
		}
		want, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%s:\n got %s\nwant %s", g.file, got, want)
		}
	}
}

// Acceptance: the sealed bytes cross the forwarder unchanged, so the chain
// verifies over what the receiver read back, and the parameters agree with
// the records.
func TestAuditRoundTripVerifiesChain(t *testing.T) {
	chain := loadChain(t)
	tg := loadTarget(t, "relp-tls-audit")
	var received [][]byte
	for i, sealed := range chain {
		msg, err := RenderAudit(sealed, tg)
		if err != nil {
			t.Fatalf("record %d: %v", i, err)
		}
		if len(msg) > tg.MaxMessageOctets || bytes.ContainsAny(msg, "\r\n\x00") {
			t.Errorf("record %d: %d octets, or a CR, LF or NUL", i, len(msg))
		}
		if !bytes.HasSuffix(msg, sealed) {
			t.Errorf("record %d: MSG is not the sealed bytes", i)
		}
		a, err := ParseAudit(msg)
		if err != nil {
			t.Fatalf("record %d: %v", i, err)
		}
		if !bytes.Equal(a.Sealed, sealed) || a.Node != chainNode || a.Seq != uint64(i+1) || a.Hash != audit.Hash(sealed) {
			t.Errorf("record %d read back as node %s seq %d hash %s", i, a.Node, a.Seq, a.Hash)
		}
		if want := tg.Facility*8 + AuditSeverity(a.Record); a.PRI != want {
			t.Errorf("record %d: PRI %d, want %d", i, a.PRI, want)
		}
		received = append(received, a.Sealed)
	}
	if err := audit.VerifyChain(chainNode, received, nil, nil); err != nil {
		t.Fatalf("chain over the received bytes: %v", err)
	}
}

// Audit goes only to an audit target, and only sealed C8 bytes are rendered.
func TestRenderAuditRefuses(t *testing.T) {
	chain := loadChain(t)
	if _, err := RenderAudit(chain[0], loadTarget(t, "relp-tls-required")); !slices.Contains(Codes(err), CodeAudit) {
		t.Errorf("audit on a target without audit: %v", err)
	}
	tg := loadTarget(t, "relp-tls-audit")
	var indented bytes.Buffer
	if err := json.Indent(&indented, chain[0], "", "  "); err != nil {
		t.Fatal(err)
	}
	for name, b := range map[string][]byte{
		"re-encoded with line breaks": indented.Bytes(),
		"not JSON":                    []byte("audit record"),
		"empty":                       nil,
		"secret-named field":          bytes.Replace(chain[3], []byte(`"detail"`), []byte(`"password"`), 1),
	} {
		if _, err := RenderAudit(b, tg); !slices.Contains(Codes(err), CodeAuditInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// A message is refused when anything in it disagrees with the sealed record
// it carries, or the sealed bytes changed on the way.
func TestParseAuditRefusesDisagreement(t *testing.T) {
	chain := loadChain(t)
	tg := loadTarget(t, "relp-tls-audit")
	msg, err := RenderAudit(chain[3], tg)
	if err != nil {
		t.Fatal(err)
	}
	s := string(msg)
	h := audit.Hash(chain[3])
	for name, m := range map[string]string{
		"seq param":         strings.Replace(s, `seq="4"`, `seq="5"`, 1),
		"seq with a zero":   strings.Replace(s, `seq="4"`, `seq="04"`, 1),
		"node param":        strings.Replace(s, `node="site-a-node-1"`, `node="site-a-node-2"`, 1),
		"hostname":          strings.Replace(s, " site-a-node-1 otsec ", " site-a-node-2 otsec ", 1),
		"hash param":        strings.Replace(s, h, strings.Repeat("0", 64), 1),
		"sealed byte":       strings.Replace(s, `"outcome":"denied"`, `"outcome":"denieD"`, 1),
		"severity":          strings.Replace(s, "<132>", "<133>", 1),
		"timestamp":         strings.Replace(s, "1 2026-10-24T11:40:00.123456Z site-a", "1 2026-10-24T11:40:01.123456Z site-a", 1),
		"msgid":             strings.Replace(s, " AUDIT ", " SER ", 1),
		"extra param":       strings.Replace(s, ` hash="`, ` evc="device-observed" hash="`, 1),
		"param order":       strings.Replace(s, `node="site-a-node-1" seq="4"`, `seq="4" node="site-a-node-1"`, 1),
		"other contract id": strings.Replace(s, `ac="otsec.audit/0.1"`, `ac="otsec.audit/0.2"`, 1),
		"no MSG":            s[:strings.Index(s, "] ")+1],
		"escaped bracket":   strings.Replace(s, `v="`+Identifier+`"`, `v="`+Identifier+`\]"`, 1),
	} {
		if m == s {
			t.Fatalf("%s: the change did not apply", name)
		}
		if _, err := ParseAudit([]byte(m)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// The size bound holds for the largest record C8 allows: MinAuditOctets
// leaves room for the header, the SD element and a sealed record of
// audit.MaxRecordBytes with the longest node ID and seq, so RenderAudit's
// too-large error is unreachable on a valid audit target.
func TestAuditFitsLargestRecord(t *testing.T) {
	node := strings.Repeat("n", 63)
	rec := `{"contract":"otsec.audit/0.9","node_id":"` + node + `","seq":18446744073709551615,"prev_hash":"` + strings.Repeat("a", 64) +
		`","time":{"utc":"2026-10-24T11:40:00.123456789Z","resolution_ns":1,"clock":{"sync":"synchronized","source":"ntp"}},"actor":{"type":"system","id":"collector"},"action":"service.start","outcome":"info","later_minor_field":"`
	rec += strings.Repeat("x", audit.MaxRecordBytes-len(rec)-2) + `"}`
	if len(rec) != audit.MaxRecordBytes {
		t.Fatalf("record is %d bytes", len(rec))
	}
	if _, err := audit.ParseRecord([]byte(rec)); err != nil {
		t.Fatalf("the largest record is not valid C8: %v", err)
	}
	tg := loadTarget(t, "relp-tls-audit")
	tg.MaxMessageOctets = MinAuditOctets
	msg, err := RenderAudit([]byte(rec), tg)
	if err != nil {
		t.Fatalf("largest record on a MinAuditOctets target: %v", err)
	}
	if a, err := ParseAudit(msg); err != nil || !bytes.Equal(a.Sealed, []byte(rec)) {
		t.Fatalf("read back: %v", err)
	}
	t.Logf("%d octets of %d", len(msg), MinAuditOctets)
}

// A receiver reads every 0.x minor (D1-13): an audit message rendered by a
// 0.1 node still parses, and one from another major does not.
func TestParseAuditReadsOlderMinor(t *testing.T) {
	chain := loadChain(t)
	msg, err := RenderAudit(chain[0], loadTarget(t, "relp-tls-audit"))
	if err != nil {
		t.Fatal(err)
	}
	s := string(msg)
	if _, err := ParseAudit([]byte(strings.Replace(s, `v="`+Identifier+`"`, `v="otsec.syslog/0.1"`, 1))); err != nil {
		t.Errorf("0.1 message: %v", err)
	}
	if _, err := ParseAudit([]byte(strings.Replace(s, `v="`+Identifier+`"`, `v="otsec.syslog/1.0"`, 1))); err == nil {
		t.Error("a 1.0 message was accepted")
	}
}
