package contract

import (
	"strings"
	"testing"

	"otsec.local/otsec/contracts/syslog"
)

// C6 otsec.syslog/0.1: A6's target cases for A1 D1-15 (audit only over a
// required relp-tls target) and C6-A6 change 1 (durable acknowledgement).
// The targets are A6's own, written from the contract's field list.
// Ground truth: GT-HAND from contract prose and D1-15.

const c6Audit = `{
  "schema": "otsec.syslog/0.1",
  "name": "a6-audit",
  "host": "collector.a6.example",
  "port": 2514,
  "transport": "relp-tls",
  "format": "rfc5424",
  "framing": "relp",
  "class": "required",
  "max_message_octets": 17408,
  "facility": 13,
  "tls": {"server_name": "collector.a6.example", "trust_anchor_ref": "a6-ca", "client_credential_ref": "a6-node-forwarder"},
  "relp_window": 64,
  "audit": true,
  "durable_ack": {"verified_utc": "2026-10-24T10:00:00Z", "evidence_ref": "commissioning/a6-audit/kill-test", "peer_check": "name", "permitted_peer": "a6-node", "ack_after": "durable-write"}
}`

const c6UDPAck = `"acknowledgement": {"by": "admin:a6", "at": "2026-10-24T10:00:00Z", "reason": "A6 negative test", "scope": "lab-only"}`

func TestC6AuditTargets(t *testing.T) {
	if _, err := syslog.ParseTarget([]byte(c6Audit)); err != nil {
		t.Fatalf("A6's audit target: %v", err)
	}
	udp := strings.NewReplacer(
		`"transport": "relp-tls"`, `"transport": "udp"`,
		`"format": "rfc5424"`, `"format": "rfc5424"`,
		`"framing": "relp"`, `"framing": "datagram"`,
		`"max_message_octets": 17408`, `"max_message_octets": 1024`,
		`"tls": {"server_name": "collector.a6.example", "trust_anchor_ref": "a6-ca", "client_credential_ref": "a6-node-forwarder"},`, c6UDPAck+",",
		`"relp_window": 64,`, ``,
	).Replace(c6Audit)
	for _, c := range []struct{ name, target string }{
		// D1-15: UDP gives no acknowledgement that a record or checkpoint arrived.
		{"audit over UDP, required", udp},
		{"audit over UDP, best-effort", strings.Replace(strings.Replace(udp, `"class": "required"`, `"class": "best-effort", "replay_seconds": 60`, 1),
			`,
  "durable_ack": {"verified_utc": "2026-10-24T10:00:00Z", "evidence_ref": "commissioning/a6-audit/kill-test", "peer_check": "name", "permitted_peer": "a6-node", "ack_after": "durable-write"}`, "", 1)},
		{"audit on a best-effort relp-tls target", strings.Replace(strings.Replace(c6Audit, `"class": "required"`, `"class": "best-effort", "replay_seconds": 60`, 1),
			`,
  "durable_ack": {"verified_utc": "2026-10-24T10:00:00Z", "evidence_ref": "commissioning/a6-audit/kill-test", "peer_check": "name", "permitted_peer": "a6-node", "ack_after": "durable-write"}`, "", 1)},
		{"audit without a durable-ack check", strings.Replace(c6Audit, `,
  "durable_ack": {"verified_utc": "2026-10-24T10:00:00Z", "evidence_ref": "commissioning/a6-audit/kill-test", "peer_check": "name", "permitted_peer": "a6-node", "ack_after": "durable-write"}`, "", 1)},
		{"audit without mutual TLS", strings.Replace(c6Audit, `, "client_credential_ref": "a6-node-forwarder"`, "", 1)},
	} {
		if c.target == c6Audit {
			t.Fatalf("%s: the variant did not change the target", c.name)
		}
		_, err := syslog.ParseTarget([]byte(c.target))
		if err == nil {
			t.Errorf("%s: accepted", c.name)
		}
		t.Logf("%s: %v", c.name, err)
	}
}
