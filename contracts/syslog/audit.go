package syslog

import (
	"bytes"
	"fmt"
	"regexp"
	"strconv"

	"otsec.local/otsec/contracts/audit"
	"otsec.local/otsec/contracts/version"
)

// AuditMsgID is the RFC 5424 MSGID of an audit message.
const AuditMsgID = "AUDIT"

// The SD-PARAMs of an audit message, in order. Each one only indexes the
// record and is never its source: a receiver takes every fact from the
// sealed bytes in MSG, and checks that the parameters agree with them.
//
//	v     C6 identifier of the rendering, for example otsec.syslog/0.2
//	ac    C8 identifier of the record, for example otsec.audit/0.1
//	node  the record's node_id
//	seq   the record's seq
//	hash  audit.Hash of the sealed bytes, the chain hash of the record
var auditParams = []string{"v", "ac", "node", "seq", "hash"}

var auditHash = regexp.MustCompile(`^[0-9a-f]{64}$`)

// AuditSeverity is the Syslog severity of an audit record: 4 (warning) when
// the outcome is denied, failed or warning, and 5 (notice) otherwise. It
// comes from the platform's own outcome, never from device content.
func AuditSeverity(r *audit.Record) int {
	switch r.Outcome {
	case audit.OutcomeDenied, audit.OutcomeFailed, audit.OutcomeWarning:
		return 4
	}
	return 5
}

// RenderAudit produces the one message for a sealed C8 audit record on an
// audit target (C8-A4, D1-15). The record is never rendered from its
// fields: the sealed bytes go unchanged into the RFC 5424 MSG part (MSG-ANY,
// no BOM), so a receiver verifies the chain over exactly the bytes the node
// sealed. HEADER TIMESTAMP is the record's time.utc, truncated as for
// events, and HOSTNAME is its node.
//
// The record is never truncated, split or summarised. Target.Validate makes
// an audit target big enough for any sealed record (MinAuditOctets), so a
// record that still does not fit is a contract violation: RenderAudit fails
// with too-large and the forwarder holds the audit cursor and alarms. It
// never skips the record.
func RenderAudit(sealed []byte, t *Target) ([]byte, error) {
	if err := t.Validate(); err != nil {
		return nil, err
	}
	if !t.Audit {
		return nil, &Error{Code: CodeAudit, Field: "audit", Detail: fmt.Sprintf("target %q does not carry the audit stream", t.Name)}
	}
	r, err := audit.ParseRecord(sealed)
	if err != nil {
		return nil, &Error{Code: CodeAuditInvalid, Field: "record", Detail: err.Error()}
	}
	ps := []Param{
		{"v", Identifier},
		{"ac", r.Contract},
		{"node", r.NodeID},
		{"seq", strconv.FormatUint(r.Seq, 10)},
		{"hash", audit.Hash(sealed)},
	}
	pri := "<" + strconv.Itoa(t.Facility*8+AuditSeverity(r)) + ">"
	head := pri + "1 " + headerTime(r.Time.UTC) + " " + r.NodeID + " " + AppName + " - " + AuditMsgID + " " + sd(ps) + " "
	msg := append([]byte(head), sealed...)
	if len(msg) > t.MaxMessageOctets {
		return nil, &Error{Code: CodeTooLarge, Field: "message", Detail: fmt.Sprintf("audit record seq %d needs %d octets, limit %d; it is never cut", r.Seq, len(msg), t.MaxMessageOctets)}
	}
	return msg, nil
}

// AuditMessage is an audit message read back by ParseAudit.
type AuditMessage struct {
	PRI       int
	Timestamp string // as rendered
	Hostname  string
	Contract  string // ac
	Node      string
	Seq       uint64
	Hash      string
	// Sealed is MSG: the record's sealed bytes, exactly as received. A
	// receiver feeds these, never a re-encoding, to audit.VerifyChain.
	Sealed []byte
	Record *audit.Record
}

// ParseAudit reads a message in the exact shape RenderAudit produces. It
// checks that the parameters, the header and the PRI's severity agree with
// the sealed record, and that the hash is the hash of the bytes in MSG. It
// does not check the chain: that needs the records before this one
// (audit.VerifyChain).
func ParseAudit(b []byte) (*AuditMessage, error) {
	bad := func(format string, a ...any) (*AuditMessage, error) {
		return nil, &Error{Code: CodeAuditInvalid, Field: "message", Detail: fmt.Sprintf(format, a...)}
	}
	// The parameters never contain ']', so the first one ends the SD
	// element. A value that tried to hide one behind an escape fails
	// ParseMessage below.
	start := bytes.Index(b, []byte("["+SDID))
	if start < 0 {
		return bad("no %s element", SDID)
	}
	end := bytes.IndexByte(b[start:], ']')
	if end < 0 {
		return bad("unterminated SD element")
	}
	end += start + 1
	if end+1 >= len(b) || b[end] != ' ' {
		return bad("no MSG after the SD element")
	}
	m, err := ParseMessage(b[:end])
	if err != nil {
		return nil, err
	}
	if m.Format != FormatRFC5424 || m.MsgID != AuditMsgID {
		return bad("an audit message is RFC 5424 with MSGID %s", AuditMsgID)
	}
	if len(m.Params) != len(auditParams) {
		return bad("parameters %v, want %v", m.Params, auditParams)
	}
	for i, p := range m.Params {
		if p.Name != auditParams[i] {
			return bad("parameter %d is %q, want %q", i, p.Name, auditParams[i])
		}
	}
	a := &AuditMessage{PRI: m.PRI, Timestamp: m.Timestamp, Hostname: m.Hostname, Sealed: b[end+1:]}
	v, _ := m.Get("v")
	a.Contract, _ = m.Get("ac")
	a.Node, _ = m.Get("node")
	a.Hash, _ = m.Get("hash")
	seq, _ := m.Get("seq")
	if got, err := version.Parse(v); err != nil || !self.Accepts(got) {
		return bad("v %q is not an otsec.syslog/0.x identifier", v)
	}
	a.Seq, err = strconv.ParseUint(seq, 10, 64)
	if err != nil || strconv.FormatUint(a.Seq, 10) != seq {
		return bad("seq %q is not a decimal number", seq)
	}
	if !auditHash.MatchString(a.Hash) || a.Hash != audit.Hash(a.Sealed) {
		return bad("hash does not match the sealed bytes in MSG")
	}
	r, err := audit.ParseRecord(a.Sealed)
	if err != nil {
		return nil, &Error{Code: CodeAuditInvalid, Field: "record", Detail: err.Error()}
	}
	a.Record = r
	switch {
	case a.Contract != r.Contract:
		return bad("ac %q, record says %q", a.Contract, r.Contract)
	case a.Node != r.NodeID || a.Hostname != r.NodeID:
		return bad("node %q and hostname %q, record says %q", a.Node, a.Hostname, r.NodeID)
	case a.Seq != r.Seq:
		return bad("seq %d, record says %d", a.Seq, r.Seq)
	case a.Timestamp != headerTime(r.Time.UTC):
		return bad("timestamp %q, record says %q", a.Timestamp, r.Time.UTC)
	case a.PRI%8 != AuditSeverity(r):
		return bad("severity %d, outcome %s means %d", a.PRI%8, r.Outcome, AuditSeverity(r))
	}
	return a, nil
}
