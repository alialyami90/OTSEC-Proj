package adapter

import (
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"slices"

	"otsec.local/otsec/contracts/asset"
	"otsec.local/otsec/contracts/register"
)

// The SNMPv3 result rules (0.7, docs/phase4/C2-adapter-0.7-snmp-results.md,
// approved by C1 on #445). Validate checks the facts, not the messages: no
// BER is parsed here. That every sent PDU is a register read of the
// operation's OIDs is shown by the client's egress check, by
// modules/ied/snmpv3's tests and by C6's V-M1 (b) audit of the transcripts.

// engineIDPattern is C1 0.3's snmp_engine_id form: 5 to 32 octets in
// lowercase hex (RFC 3411 SnmpEngineID).
var engineIDPattern = regexp.MustCompile(`^([0-9a-f]{2}){5,32}$`)

// snmpSession checks an SNMP result's session facts in place of the SEL
// rules.
func (c *check) snmpSession(r Result, code Code) {
	t, s, n := r.Transcript, r.Session, r.Session.SNMP
	if s.WakeSent || s.LanguageProbe != ProbeNotRun || s.PasswordPrompt || s.CredentialSent ||
		s.EchoScan != EchoScanNotApplicable || s.AccessLevel != "" || s.QuitSent {
		c.fail("session: an SNMP session has no wake, language probe, password prompt, credential, echo scan, access level or QUI")
	}
	if n.EngineID != "" && !engineIDPattern.MatchString(n.EngineID) {
		c.fail("session.snmp.engine_id %q is not 5 to 32 octets in lowercase hex", n.EngineID)
	}
	sent, keyed := false, false // a datagram sent; an auth or operate message sent
	for i, sg := range t.Segments {
		if sg.Phase == PhaseClose {
			c.fail("transcript.segments[%d]: an SNMP session has no close phase", i)
		}
		if sg.Dir == Sent {
			sent = true
			keyed = keyed || sg.Phase == PhaseAuth || sg.Phase == PhaseOperate
		}
	}
	switch {
	case !s.Connected && (len(t.Data) != 0 || n.EngineID != "" || n.Authenticated):
		c.fail("session: not connected, so the transcript is empty, with no engine ID and nothing authenticated")
	case s.Connected && !sent:
		c.fail("session: connected means a datagram was sent")
	}
	// Keys are localized only to the pinned engine ID, after discovery
	// reported it, and only an authenticated request is answered under them.
	if n.Authenticated && (n.EngineID == "" || !keyed) {
		c.fail("session: authenticated needs a discovered engine ID and an auth or operate message sent")
	}
	// Every keyed message is stored with its digest zeroed, so no live HMAC
	// is kept to test a password guess against (C3 on #445). Discovery is
	// noAuthNoPriv and has none. This counts redactions; it cannot show,
	// without parsing BER, that one covers the digest field.
	digests := digestsBySegment(t)
	answered := false
	for i, sg := range t.Segments {
		switch d := digests[i]; {
		case sg.Phase == PhaseProbe && d != 0:
			c.fail("transcript.segments[%d]: discovery is not authenticated, so it holds no usm-digest redaction", i)
		case sg.Phase != PhaseProbe && sg.Dir == Sent && d != 1:
			c.fail("transcript.segments[%d]: an authenticated message sent holds exactly one usm-digest redaction, not %d", i, d)
		case sg.Dir == Received && d > 1:
			c.fail("transcript.segments[%d]: a message holds at most one usm-digest redaction, not %d", i, d)
		case sg.Dir == Received && d == 1:
			answered = true
		}
	}
	if n.Authenticated && !answered {
		c.fail("session: authenticated needs a received auth or operate message that carried a digest")
	}
	// A value is read only from an authenticated Response: anything below
	// authPriv is discarded unparsed (C3's #437 §4 rule 1). The one
	// exception is the engine ID, read at discovery (snmpIdentity).
	inAnswer := func(sp Span) bool {
		for i, sg := range t.Segments {
			if sp.Offset >= sg.Offset && sp.Length > 0 && sp.Offset+sp.Length <= sg.Offset+sg.Length {
				return sg.Dir == Received && sg.Phase == PhaseOperate && digests[i] == 1
			}
		}
		return false
	}
	for i, o := range r.Observations {
		if !inAnswer(o.Span) {
			c.fail("observations[%d]: %s is read only from a received operate message that carried a digest", i, o.Name)
		}
	}
	for i, it := range r.Identity.Items {
		if it.Name != asset.AttrSNMPEngineID && !inAnswer(it.Span) {
			c.fail("identity.items[%d]: %s is read only from a received operate message that carried a digest", i, it.Name)
		}
	}
	switch code.Stage() {
	case StageBeforeConnect:
		if code != "" && s.Connected {
			c.fail("error %s is decided before connecting, so the session is not connected", code)
		}
	case StageBeforeAuth:
		if !s.Connected || keyed || n.Authenticated {
			c.fail("error %s is decided at discovery: connected, with no auth or operate message sent and nothing authenticated", code)
		}
	case StageAuth:
		if !keyed {
			c.fail("error %s answers an authenticated request, so an auth or operate message was sent", code)
		}
	case StageAfterAuth:
		if !n.Authenticated {
			c.fail("error %s happens after authentication, so the session authenticated", code)
		}
	}
	if code == "" && !n.Authenticated {
		c.fail("status ok needs an authenticated SNMP session")
	}
}

// digestsBySegment counts the usm-digest redactions in each segment.
func digestsBySegment(t Transcript) []int {
	n := make([]int, len(t.Segments))
	for _, rd := range t.Redactions {
		for i, sg := range t.Segments {
			if rd.Reason == RedactUSMDigest && rd.Offset >= sg.Offset && rd.Offset < sg.Offset+sg.Length {
				n[i]++
			}
		}
	}
	return n
}

// snmpIdentity checks the SNMP identity items and AP-27 for SNMP: the engine
// ID is the first item, read from the discovery answer, and an auth or
// operate message is sent only after it matched (C3's #437 §4 rule 2). The
// FID is compared after authentication, from a response.
func (c *check) snmpIdentity(r Result, code Code) {
	t, items, n := r.Transcript, r.Identity.Items, r.Session.SNMP
	for i, it := range items {
		p := fmt.Sprintf("identity.items[%d]", i)
		sp := it.Span
		if sp.Offset < 0 || sp.Length <= 0 || sp.Offset+sp.Length > int64(len(t.Data)) {
			continue // rxSpan has failed it
		}
		b := t.Data[sp.Offset : sp.Offset+sp.Length]
		if it.Name != asset.AttrSNMPEngineID {
			if it.Observed != string(b) {
				c.fail("%s: the span does not select the observed value", p)
			}
			continue
		}
		if i != 0 {
			c.fail("%s: %s is the first identity item", p, it.Name)
		}
		if it.Observed != hex.EncodeToString(b) || it.Observed != n.EngineID {
			c.fail("%s: the observed engine ID is the hex of its span and equals session.snmp.engine_id", p)
		}
		if sg, ok := segmentAt(t, sp.Offset, sp.Length); !ok || sg.Phase != PhaseProbe || sg.Dir != Received {
			c.fail("%s: the engine ID is read from the discovery answer, a received probe segment", p)
		}
	}
	first := len(items) > 0 && items[0].Name == asset.AttrSNMPEngineID
	if len(items) > 0 && !first {
		c.fail("identity.items[0]: an SNMP identity starts with %s", asset.AttrSNMPEngineID)
	}
	var keyedAt int64 = -1
	for _, sg := range t.Segments {
		if sg.Dir == Sent && (sg.Phase == PhaseAuth || sg.Phase == PhaseOperate) {
			keyedAt = sg.Offset
			break
		}
	}
	if keyedAt >= 0 && !(first && items[0].Expected == items[0].Observed && items[0].Span.Offset < keyedAt) {
		c.fail("an authenticated message was sent, so a matching %s item read at discovery must precede it (AP-27)", asset.AttrSNMPEngineID)
	}
	if code == RefusedEngineIDMismatch && !(first && items[0].Expected != items[0].Observed) {
		c.fail("%s needs the %s item to differ", code, asset.AttrSNMPEngineID)
	}
	// No FID was read, so nothing but the engine ID was compared, and no
	// FID or value cut from one is reported (C1 on #445).
	if code == FailedSNMPFIDUnreadable {
		if !first || len(items) != 1 {
			c.fail("%s: the identity holds only the matching %s item", code, asset.AttrSNMPEngineID)
		}
		for i, o := range r.Observations {
			if o.Name == asset.AttrFirmwareID || o.Name == asset.AttrModel || o.Name == asset.AttrFirmwareVersion {
				c.fail("observations[%d]: %s reports no %s", i, code, o.Name)
			}
		}
	}
}

// read checks an observation's read path (0.7).
func (c *check) read(i int, o Observation, r Result) {
	t, p := r.Transcript, fmt.Sprintf("observations[%d].read", i)
	rd := o.Read
	switch {
	case rd == nil:
		if c.minor >= 7 {
			c.fail("%s is required from 0.7", p)
		}
		return
	case c.minor < 7:
		c.fail("%s is new in 0.7, so a 0.%d result cannot carry it", p, c.minor)
	}
	if !operationIDPattern.MatchString(rd.Operation) {
		c.fail("%s.operation %q is not an operation ID", p, rd.Operation)
	}
	if !c.snmp {
		if rd.OID != "" || rd.Header != "" {
			c.fail("%s: a line result's read names no oid or header", p)
		}
		return
	}
	switch {
	case (rd.OID == "") == (rd.Header == ""):
		c.fail("%s: an SNMP read names exactly one of oid and header", p)
		return
	case rd.OID != "" && !register.ValidOID(rd.OID):
		c.fail("%s.oid %q is not a literal OID under 1.3.6.1", p, rd.OID)
	case rd.Header != "" && rd.Header != asset.HeaderEngineID:
		c.fail("%s.header %q is not %s", p, rd.Header, asset.HeaderEngineID)
	}
	if (rd.Header != "") != (o.Name == asset.AttrSNMPEngineID) {
		c.fail("%s: %s is read from the %s header, and the header holds nothing else", p, asset.AttrSNMPEngineID, asset.HeaderEngineID)
	}
	// Every later message must carry the pinned engine ID (C11 §4 rule 2).
	if rd.Header != "" && o.Value != r.Session.SNMP.EngineID {
		c.fail("%s: the engine ID read is not session.snmp.engine_id", p)
	}
	sp := o.Span
	if sp.Offset < 0 || sp.Length <= 0 || sp.Offset+sp.Length > int64(len(t.Data)) {
		return // rxSpan has failed it
	}
	b := t.Data[sp.Offset : sp.Offset+sp.Length]
	if want := string(b); (rd.Header == "" && o.Value != want) || (rd.Header != "" && o.Value != hex.EncodeToString(b)) {
		c.fail("observations[%d]: the span does not select the value", i)
	}
}

// CheckSNMP checks an SNMP result against the register package and the
// invocation it ran, as CheckLines does for a line result (0.7). Run it with
// Validate on every SNMP result, from the collector or a simulator.
//
//   - The result names the invocation and operation, and the package that
//     permitted its reads.
//   - The invocation names an SNMP operation, or a run of SNMP operations.
//   - Each observation's read names one of those operations, and its OID is
//     one the operation reads: one of a get's oids, or inside a walk's
//     subtree. So an observation cannot claim an OID the operation never
//     asked for (C3's review of #445).
func (r Result) CheckSNMP(p *register.Package, inv Invocation) error {
	if r.Session.SNMP == nil {
		return fmt.Errorf("adapter: snmp: not an SNMP result; check it with CheckLines")
	}
	var errs []error
	fail := func(f string, a ...any) { errs = append(errs, fmt.Errorf(f, a...)) }
	if r.InvocationID != inv.InvocationID || r.OperationID != inv.OperationID {
		fail("the result is for invocation %s, operation %s, not %s, %s", r.InvocationID, r.OperationID, inv.InvocationID, inv.OperationID)
	}
	unverified := r.Error != nil && r.Error.Code == RefusedRegisterUnverified && r.RegisterVersion == 0
	if r.RegisterVersion != p.Revision && !unverified {
		fail("register_version %d, but the package is revision %d", r.RegisterVersion, p.Revision)
	}
	steps := []string{inv.OperationID}
	if run := p.Run(inv.OperationID); run != nil {
		steps = run.Steps
	}
	for _, id := range steps {
		if p.SNMPOperation(id) == nil {
			fail("%s is not an SNMP operation, or a run of them, in this package", inv.OperationID)
			break
		}
	}
	for i, o := range r.Observations {
		if o.Read == nil {
			continue
		}
		op := p.SNMPOperation(o.Read.Operation)
		if op == nil || !slices.Contains(steps, o.Read.Operation) {
			fail("observations[%d]: %s is not an SNMP operation this invocation runs", i, o.Read.Operation)
			continue
		}
		if oid := o.Read.OID; oid != "" && !slices.Contains(op.OIDs, oid) && (op.Subtree == "" || !register.InSubtree(oid, op.Subtree)) {
			fail("observations[%d]: %s does not read %s", i, op.ID, oid)
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("adapter: snmp: %w", errors.Join(errs...))
	}
	return nil
}
