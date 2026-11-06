// Package snmpv3 is the collector's SNMPv3 client (P4-3-C2, C3 0.4): one
// register run, read-only, at authPriv only, against one agent whose engine
// ID is pinned. It is collector code and is linked only into otsec-collector
// (§3 of docs/phase4/C2-c1-0.3-c3-0.4.md).
//
// What a session does, in order (§2.3 there; C3's #437 §4; D4-53):
//
//  1. Discovery (phase probe): the one message below authPriv, a
//     noAuthNoPriv GetRequest with no varbinds. The agent's Report names its
//     engine ID, which must equal the pinned one, or the run ends with
//     refused.engine_id_mismatch before any authenticated message.
//  2. Time synchronization (phase auth): the first step's first request,
//     authPriv, with boots and time 0. The agent's authenticated
//     usmStatsNotInTimeWindows Report gives its boots and time, and the
//     request is sent again with them and a fresh msgID (phase operate). A
//     time-window Report that does not authenticate, or a second one, ends
//     the run with failed.usm_not_in_time_window.
//  3. The steps (phase operate): every request authPriv, every response
//     authenticated and decrypted before it is read.
//
// A Report or Response counts only if it carries the outstanding msgID; the
// Conn delivers only datagrams from the endpoint's address and port. The
// four failure Reports end the run with their code even unauthenticated: a
// forged one can only stop a run, never steer it, and nothing here suspends
// anything (D4-53). Any other Report out of order (#437 §4 rule 1: at
// discovery anything but usmStatsUnknownEngineIDs, afterwards a second one
// or a Report C2 does not name) ends the run with
// failed.snmp_unexpected_report, and an authenticated, encrypted message
// whose ScopedPDU does not decode ends it with
// failed.snmp_scoped_pdu_unreadable, its decrypted bytes kept (C2 0.8,
// D4-54). Anything else that does not authenticate, decrypt, decode or match
// is discarded, kept in the transcript, and the request times out if nothing
// good arrives. Each request is sent at most twice, each time with a fresh
// msgID, and both count against the bounds.
//
// Result turns an Outcome into the C2 result, comparing the identity.
//
// The client cannot write a SET: requestPDU has no encoder for one, and the
// steps come from a validated C3 0.4 package, whose PDU enum has none. Every
// outgoing message also passes Permit, the egress check, as it will leave:
// encoded, encrypted and signed, just before it is written (C11 §4 rule 4).
package snmpv3

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"otsec.local/otsec/contracts/adapter"
	"otsec.local/otsec/contracts/register"
)

// The usmStats counters a Report names (RFC 3414 §5).
const (
	oidUnsupportedSecLevels = "1.3.6.1.6.3.15.1.1.1.0"
	oidNotInTimeWindows     = "1.3.6.1.6.3.15.1.1.2.0"
	oidUnknownUserNames     = "1.3.6.1.6.3.15.1.1.3.0"
	oidUnknownEngineIDs     = "1.3.6.1.6.3.15.1.1.4.0"
	oidWrongDigests         = "1.3.6.1.6.3.15.1.1.5.0"
	oidDecryptionErrors     = "1.3.6.1.6.3.15.1.1.6.0"
)

var reportCodes = map[string]adapter.Code{
	oidUnsupportedSecLevels: adapter.FailedUSMUnsupportedSecLevel,
	oidUnknownUserNames:     adapter.FailedUSMUnknownUser,
	oidWrongDigests:         adapter.FailedUSMWrongDigest,
	oidDecryptionErrors:     adapter.FailedUSMDecryptionError,
}

// timeWindow is RFC 3414's 150-second window.
const timeWindow = 150

// Conn is one datagram socket connected to the endpoint's address and port,
// so Read returns only datagrams from there (D4-53). The collector provides
// it; this package opens nothing.
type Conn interface {
	Write(b []byte) error
	// Read returns the next datagram, or an error once deadline passes.
	Read(deadline time.Time) ([]byte, error)
}

// ErrDeadline is what a Conn's Read returns when the deadline passes.
var ErrDeadline = errors.New("snmpv3: deadline")

// Session is one run against one agent.
type Session struct {
	Conn Conn
	Keys Keys
	// EngineID is the pinned engine ID: the asset's declared
	// snmp_engine_id, which the collector has checked equals the
	// credential's (C1 0.3 §1.4).
	EngineID []byte
	// Permit is the egress check over every outgoing message, given the
	// final wire bytes just before they are written. step is the register
	// operation the message is sent for (discovery's is the run's first
	// step, whose max_reply_bytes it advertises), and engineKnown is false
	// only for discovery. Required: a session without it sends nothing.
	Permit func(step string, engineKnown bool, msg []byte) error
	Now    func() time.Time
}

// Segment is one message sent or received, in the transcript's stored form
// (storedForm). A datagram that is not an SNMPv3 message is kept as
// received, and one whose msgData could not be decrypted keeps its
// ciphertext; every digest is zeroed either way.
type Segment struct {
	Dir       adapter.Direction
	Phase     adapter.Phase
	At        time.Time
	Bytes     []byte
	ScopedOff int // offset of the plaintext scoped PDU, -1 when there is none
	DigestOff int
	DigestLen int // 0: no digest
	// EngineIDOff is the offset of msgAuthoritativeEngineID's contents, -1
	// when the bytes are not a decoded message.
	EngineIDOff int
	EngineIDLen int
}

// Value is one varbind a step read: the OID, the value's tag and contents,
// and where the contents are in the transcript.
type Value struct {
	Step    string
	OID     string
	Tag     byte
	Content []byte
	Segment int // index into Outcome.Segments
	Offset  int // of Content in that segment's Bytes
}

// Outcome is what a session did. Code is "" when every step completed.
type Outcome struct {
	Code   adapter.Code
	Detail string
	// EngineID is the discovered msgAuthoritativeEngineID, nil when no
	// discovery answer counted. Authenticated is true once a message from
	// the agent authenticated and decrypted.
	EngineID      []byte
	Authenticated bool
	Segments      []Segment
	Values        []Value
}

// state is the session in progress.
type state struct {
	s        *Session
	run      *register.Run
	out      Outcome
	deadline time.Time
	received int64
	salt     uint64
	// The agent's boots and time, and when its time was read: the
	// non-authoritative side's notion (RFC 3414 §2.3).
	synced            bool
	boots, agentTime  int64
	syncedAt          time.Time
	timeWindowReports int
	unreadable        bool // an authenticated, encrypted message did not decrypt to a ScopedPDU
}

// errEnd ends the session with o.Code set.
var errEnd = errors.New("end")

// Run runs one SNMP run of a validated C3 0.4 package.
func (s *Session) Run(p *register.Package, runID string) Outcome {
	st := &state{s: s}
	if err := st.start(p, runID); err != nil {
		st.out.Code, st.out.Detail = adapter.FailedInternal, err.Error()
		return st.out
	}
	if err := st.discover(p); err == nil {
		_ = st.steps(p)
	}
	return st.out
}

func (st *state) start(p *register.Package, runID string) error {
	if st.s.Permit == nil || st.s.Conn == nil || st.s.Now == nil {
		return errors.New("snmpv3: a session needs a Conn, a clock and the egress check")
	}
	if err := st.s.Keys.check(); err != nil {
		return err
	}
	if n := len(st.s.EngineID); n < 5 || n > 32 {
		return fmt.Errorf("snmpv3: pinned engine ID of %d octets", n)
	}
	st.run = p.Run(runID)
	if st.run == nil || len(st.run.Steps) == 0 || p.SNMPOperation(st.run.Steps[0]) == nil {
		return fmt.Errorf("snmpv3: %q is not an SNMP run", runID)
	}
	st.deadline = st.s.Now().Add(time.Duration(st.run.DeadlineMS) * time.Millisecond)
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return err
	}
	st.salt = binary.BigEndian.Uint64(b[:])
	return nil
}

func (st *state) end(c adapter.Code, f string, a ...any) error {
	st.out.Code, st.out.Detail = c, fmt.Sprintf(f, a...)
	return errEnd
}

// --- sending and receiving ---------------------------------------------------

func newID() int64 {
	var b [4]byte
	_, _ = rand.Read(b[:])
	return int64(binary.BigEndian.Uint32(b[:]) & 0x7FFFFFFF)
}

// send encodes, protects, checks and writes one request for step. secure
// false is discovery's noAuthNoPriv message.
func (st *state) send(ph adapter.Phase, step string, secure bool, maxSize int64, reqPDU []byte) (msgID int64, err error) {
	msgID = newID()
	sc := scopedOf(st.s.EngineID, nil, reqPDU)
	if !secure {
		sc = scopedOf(nil, nil, reqPDU)
	}
	u := usmParams{}
	flags := byte(flagReportable)
	data := sc
	if secure {
		flags |= flagAuth | flagPriv
		st.salt++
		salt := binary.BigEndian.AppendUint64(nil, st.salt)
		boots, t := st.agentClock()
		enc, err := st.s.Keys.cfb(boots, t, salt, sc, true)
		if err != nil {
			return 0, st.end(adapter.FailedInternal, "%v", err)
		}
		u = usmParams{EngineID: st.s.EngineID, Boots: boots, Time: t, User: []byte(st.s.Keys.User),
			AuthParams: make([]byte, st.s.Keys.digestLen()), PrivParams: salt}
		data = tlvOf(tagOctetString, enc)
	}
	wire := messageOf(msgID, maxSize, flags, u, data)
	m, err := decodeMessage(wire)
	if err != nil {
		return 0, st.end(adapter.FailedInternal, "the client encoded a message it cannot read: %v", err)
	}
	if secure {
		st.s.Keys.sign(wire, m)
	}
	// engineKnown comes from discovery's result, not from the flags the
	// check judges (C3 on #453).
	if err := st.s.Permit(step, st.out.EngineID != nil, wire); err != nil {
		return 0, st.end(adapter.FailedEgressViolation, "the egress check refused a request: %v", err)
	}
	st.record(adapter.Sent, ph, wire, m, sc)
	if err := st.s.Conn.Write(wire); err != nil {
		return 0, st.end(adapter.FailedTransportClosed, "send: %v", err)
	}
	return msgID, nil
}

// record adds a segment in stored form. plain is the plaintext scoped PDU,
// or nil when there is none to store.
func (st *state) record(dir adapter.Direction, ph adapter.Phase, wire []byte, m *message, plain []byte) {
	sg := Segment{Dir: dir, Phase: ph, At: st.s.Now(), ScopedOff: -1, EngineIDOff: -1}
	switch {
	case m == nil:
		sg.Bytes = append([]byte(nil), wire...)
	case plain == nil:
		// Not decrypted: the wire bytes, digest zeroed.
		sg.Bytes = append([]byte(nil), wire...)
		if n := len(m.USM.AuthParams); n > 0 {
			sg.DigestOff, sg.DigestLen = m.AuthOff, n
			clear(sg.Bytes[m.AuthOff : m.AuthOff+n])
		}
		sg.EngineIDOff, sg.EngineIDLen = m.EngineIDOff, len(m.USM.EngineID)
	default:
		sg.Bytes, sg.ScopedOff, sg.DigestOff, sg.DigestLen = storedForm(wire, m, plain)
		// The header keeps its wire offsets, moved by any change in the
		// size of the outer length.
		sg.EngineIDOff, sg.EngineIDLen = m.EngineIDOff+sg.ScopedOff-m.Data.Off, len(m.USM.EngineID)
	}
	st.out.Segments = append(st.out.Segments, sg)
}

// reply is one counted answer to the outstanding request.
type reply struct {
	m       *message
	sc      *scoped
	seg     int
	authed  bool
	timeRep bool // an authenticated usmStatsNotInTimeWindows Report
}

// await waits for the answer to msgID until the step timeout or the run's
// deadline. In discovery the answer is a Report naming an engine ID;
// otherwise it is an authenticated Response to reqID, or the authenticated
// time-window Report. It returns nil on a timeout, and errEnd when a Report
// or a bound ends the run.
func (st *state) await(ph adapter.Phase, msgID, reqID int64, limits register.Limits, discovery bool) (*reply, error) {
	until := st.s.Now().Add(time.Duration(limits.TimeoutMS) * time.Millisecond)
	if until.After(st.deadline) {
		until = st.deadline
	}
	for {
		b, err := st.s.Conn.Read(until)
		if errors.Is(err, ErrDeadline) {
			return nil, nil
		}
		if err != nil {
			return nil, st.end(adapter.FailedTransportClosed, "receive: %v", err)
		}
		st.received += int64(len(b))
		r, ok := st.accept(ph, b, msgID)
		if st.unreadable {
			return nil, st.end(adapter.FailedSNMPScopedPDUUnreadable, "an authenticated, encrypted message whose ScopedPDU does not decode")
		}
		if st.received > st.run.MaxTotalBytes {
			return nil, st.end(adapter.FailedResponseTooLarge, "the run received %d bytes, above max_total_bytes %d", st.received, st.run.MaxTotalBytes)
		}
		if int64(len(b)) > limits.MaxReplyBytes {
			return nil, st.end(adapter.FailedResponseTooLarge, "a %d-byte message, above max_reply_bytes %d", len(b), limits.MaxReplyBytes)
		}
		switch {
		case !ok:
		case r.sc.PDU.Tag == tagReport:
			if err := st.report(r, discovery); err != nil || r.timeRep {
				return r, err
			}
			if n := len(r.m.USM.EngineID); discovery && n > 0 {
				return r, nil
			}
		case !discovery && r.sc.PDU.Tag == tagResponse && r.sc.PDU.RequestID == reqID:
			return r, nil
		}
	}
}

// accept decodes one datagram, records it, and says whether it counts: it
// carries the outstanding msgID and, unless it is a Report, authenticates
// and decrypts under the pinned engine.
func (st *state) accept(ph adapter.Phase, b []byte, msgID int64) (*reply, bool) {
	m, err := decodeMessage(b)
	if err != nil {
		st.record(adapter.Received, ph, b, nil, nil)
		return nil, false
	}
	// With privacy msgData is the encryptedPDU, and without it the
	// plaintext ScopedPDU (RFC 3412 §7.2). A message whose privacy flag
	// disagrees with its msgData is kept as received, digest zeroed, and
	// discarded: it is never stored or read as a decrypted one (C3, C6 on
	// #453).
	if (m.Flags&flagPriv != 0) != m.encrypted() {
		st.record(adapter.Received, ph, b, m, nil)
		return nil, false
	}
	authed := false
	if m.Flags&flagAuth != 0 && bytes.Equal(m.USM.EngineID, st.s.EngineID) && string(m.USM.User) == st.s.Keys.User {
		authed = st.s.Keys.verify(b, m)
	}
	var plain []byte
	switch {
	case !m.encrypted():
		plain = b[m.Data.Off:m.Data.End()]
	case authed && m.Flags&flagPriv != 0:
		plain, _ = st.s.Keys.cfb(m.USM.Boots, m.USM.Time, m.USM.PrivParams, m.Data.Val, false)
	}
	var sc *scoped
	if plain != nil {
		if sc, err = decodeScoped(plain); err != nil {
			sc, plain = nil, nil
		}
	}
	// Only a key holder can send an authenticated, encrypted message, so one
	// that does not decrypt to a ScopedPDU ends the run (C2 0.8, D4-54). Its
	// decrypted bytes are stored in place, never the ciphertext.
	if authed && m.Flags&flagPriv != 0 && m.encrypted() && sc == nil {
		st.unreadable = true
		plain, _ = st.s.Keys.cfb(m.USM.Boots, m.USM.Time, m.USM.PrivParams, m.Data.Val, false)
	}
	if m.encrypted() && sc == nil {
		authed = false // a message that does not decrypt to a scoped PDU is not trusted
	}
	st.record(adapter.Received, ph, b, m, plain)
	seg := len(st.out.Segments) - 1
	if sc == nil || m.MsgID != msgID {
		return nil, false
	}
	r := &reply{m: m, sc: sc, seg: seg, authed: authed}
	if sc.PDU.Tag == tagResponse && !(authed && m.Flags&flagPriv != 0 && st.inWindow(m)) {
		return nil, false
	}
	if authed && m.encrypted() {
		st.out.Authenticated = true
	}
	return r, true
}

// report acts on a Report that matches the outstanding msgID. Two Reports
// are expected, each once and in order (#437 §4 rule 1): discovery's
// usmStatsUnknownEngineIDs, then the time-window Report. Any other Report
// ends the session; the four USM failure Reports with their own codes once
// an authenticated request is out.
func (st *state) report(r *reply, discovery bool) error {
	o := ""
	if len(r.sc.PDU.VarBinds) > 0 {
		o = r.sc.PDU.VarBinds[0].OID
	}
	if discovery {
		if o != oidUnknownEngineIDs {
			return st.end(adapter.FailedSNMPUnexpectedReport, "discovery was answered by a Report of %q", o)
		}
		return nil
	}
	if c, ok := reportCodes[o]; ok {
		return st.end(c, "the agent reported %s", o)
	}
	if o != oidNotInTimeWindows {
		return st.end(adapter.FailedSNMPUnexpectedReport, "a Report of %q after discovery", o)
	}
	st.timeWindowReports++
	if !r.authed || st.timeWindowReports > 1 {
		return st.end(adapter.FailedUSMNotInTimeWindow, "a usmStatsNotInTimeWindows Report that did not authenticate, or a second one")
	}
	r.timeRep = true
	st.synced, st.boots, st.agentTime, st.syncedAt = true, r.m.USM.Boots, r.m.USM.Time, st.s.Now()
	return nil
}

// agentClock is the agent's boots and time as this side estimates them, or
// zeros before synchronization.
func (st *state) agentClock() (int64, int64) {
	if !st.synced {
		return 0, 0
	}
	return st.boots, st.agentTime + int64(st.s.Now().Sub(st.syncedAt)/time.Second)
}

// inWindow applies RFC 3414 §3.2 step 7b for a non-authoritative receiver
// to an authenticated message, and updates the estimate when it is newer.
func (st *state) inWindow(m *message) bool {
	if !st.synced {
		return true
	}
	b, t := st.agentClock()
	if m.USM.Boots == 0x7FFFFFFF || m.USM.Boots < b || (m.USM.Boots == b && m.USM.Time < t-timeWindow) {
		return false
	}
	if m.USM.Boots > b || m.USM.Time > t {
		st.boots, st.agentTime, st.syncedAt = m.USM.Boots, m.USM.Time, st.s.Now()
	}
	return true
}

// --- the phases ----------------------------------------------------------------

func (st *state) firstLimits(p *register.Package) register.Limits {
	return *p.SNMPOperation(st.run.Steps[0]).Limits
}

// discover runs discovery and checks the engine ID against the pinned one,
// before any authenticated message (D4-49 Q1).
func (st *state) discover(p *register.Package) error {
	lim := st.firstLimits(p)
	req, err := requestPDU(tagGetRequest, newID(), 0, 0, nil)
	if err != nil {
		return st.end(adapter.FailedInternal, "%v", err)
	}
	for range 2 {
		id, err := st.send(adapter.PhaseProbe, st.run.Steps[0], false, lim.MaxReplyBytes, req)
		if err != nil {
			return err
		}
		r, err := st.await(adapter.PhaseProbe, id, 0, lim, true)
		if err != nil {
			return err
		}
		if r == nil {
			continue
		}
		e := r.m.USM.EngineID
		if len(e) < 5 || len(e) > 32 {
			return st.end(adapter.FailedTimeout, "discovery answered with an engine ID of %d octets", len(e))
		}
		st.out.EngineID = append([]byte(nil), e...)
		if !bytes.Equal(e, st.s.EngineID) {
			return st.end(adapter.RefusedEngineIDMismatch, "discovery's engine ID %x is not the pinned %x", e, st.s.EngineID)
		}
		return nil
	}
	return st.end(adapter.FailedTimeout, "no discovery answer to two requests")
}

// exchange sends one request authPriv and returns the Response, sending it
// at most twice. A time-window Report in between gives the agent's clock,
// and the request is sent again with it: that resend is not the request's
// retransmission (§2.3 step 3). sends counts every transmission.
func (st *state) exchange(op *register.SNMPOperation, tag byte, a, b int64, oids []string) (r *reply, sends int, err error) {
	reqID := newID()
	pdu, err := requestPDU(tag, reqID, a, b, oids)
	if err != nil {
		return nil, 0, st.end(adapter.FailedInternal, "%v", err)
	}
	for tries := 0; tries < 2; {
		if !st.s.Now().Before(st.deadline) {
			break
		}
		ph := adapter.PhaseOperate
		if !st.synced {
			ph = adapter.PhaseAuth
		}
		id, err := st.send(ph, op.ID, true, op.Limits.MaxReplyBytes, pdu)
		if err != nil {
			return nil, sends, err
		}
		sends++
		r, err := st.await(ph, id, reqID, *op.Limits, false)
		switch {
		case err != nil:
			return nil, sends, err
		case r == nil:
			tries++
		case r.timeRep:
		default:
			return r, sends, nil
		}
	}
	return nil, sends, st.end(adapter.FailedTimeout, "no response to %s", op.ID)
}

// steps runs every step of the run, in order.
func (st *state) steps(p *register.Package) error {
	for _, id := range st.run.Steps {
		op := p.SNMPOperation(id)
		var err error
		if op.PDU == register.PDUGet {
			err = st.get(op)
		} else {
			err = st.walk(op)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func (st *state) keep(op *register.SNMPOperation, r *reply, vb varbind) {
	sg := st.out.Segments[r.seg]
	st.out.Values = append(st.out.Values, Value{Step: op.ID, OID: vb.OID, Tag: vb.Value.Tag,
		Content: append([]byte(nil), vb.Value.Val...), Segment: r.seg, Offset: sg.ScopedOff + vb.Value.ValOff()})
}

func (st *state) checkStatus(op *register.SNMPOperation, r *reply) error {
	if r.sc.PDU.ErrStatus != 0 {
		return st.end(adapter.FailedSNMPErrorStatus, "%s: error-status %d, error-index %d", op.ID, r.sc.PDU.ErrStatus, r.sc.PDU.ErrIndex)
	}
	return nil
}

// get sends one GetRequest of the operation's OIDs. A varbind exception
// (noSuchObject, noSuchInstance) is kept as it came: that OID gives no
// attribute, and the transcript shows why.
func (st *state) get(op *register.SNMPOperation) error {
	r, _, err := st.exchange(op, tagGetRequest, 0, 0, op.OIDs)
	if err != nil {
		return err
	}
	if err := st.checkStatus(op, r); err != nil {
		return err
	}
	for _, vb := range r.sc.PDU.VarBinds {
		st.keep(op, r, vb)
	}
	return nil
}

// walk walks the operation's subtree within its bounds. It ends normally on
// an OID outside the subtree or on endOfMibView. A returned OID not greater
// than the one before it ends the run with failed.snmp_walk_not_increasing,
// and a walk that reaches max_varbinds or max_requests first with
// failed.response_too_large; the bytes are kept either way.
func (st *state) walk(op *register.SNMPOperation) error {
	prev, kept, sent := op.Subtree, 0, 0
	tag, reps := byte(tagGetNextRequest), int64(0)
	if op.PDU == register.PDUGetBulk {
		tag, reps = tagGetBulkRequest, int64(op.MaxRepetitions)
	}
	for {
		if sent >= op.Walk.MaxRequests {
			return st.end(adapter.FailedResponseTooLarge, "%s: the walk did not end within %d requests", op.ID, op.Walk.MaxRequests)
		}
		r, n, err := st.exchange(op, tag, 0, reps, []string{prev})
		sent += n
		if err != nil {
			return err
		}
		if err := st.checkStatus(op, r); err != nil {
			return err
		}
		if len(r.sc.PDU.VarBinds) == 0 {
			return nil
		}
		for _, vb := range r.sc.PDU.VarBinds {
			if vb.Value.Tag == tagEndOfMibView || !register.InSubtree(vb.OID, op.Subtree) {
				return nil
			}
			if !oidLess(prev, vb.OID) {
				return st.end(adapter.FailedSNMPWalkNotIncreasing, "%s: %s after %s", op.ID, vb.OID, prev)
			}
			if kept++; kept > op.Walk.MaxVarbinds {
				return st.end(adapter.FailedResponseTooLarge, "%s: more than %d varbinds", op.ID, op.Walk.MaxVarbinds)
			}
			st.keep(op, r, vb)
			prev = vb.OID
		}
	}
}

// oidLess orders two dotted-decimal OIDs by their arcs (RFC 3416's order).
func oidLess(a, b string) bool {
	as, bs := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(as) && i < len(bs); i++ {
		x, _ := strconv.ParseUint(as[i], 10, 32)
		y, _ := strconv.ParseUint(bs[i], 10, 32)
		if x != y {
			return x < y
		}
	}
	return len(as) < len(bs)
}
