package sel751

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"otsec.local/otsec/contracts/adapter"
	"otsec.local/otsec/contracts/asset"
	"otsec.local/otsec/contracts/register"
	"otsec.local/otsec/modules/ied/telnet"
)

// AdapterID and Version name this build in every result (C2 adapter, A4
// EP-4).
const (
	AdapterID = "sel-751-ascii"
	Version   = "0.1.0"
)

// Timing the manual does not give, chosen here until a capture shows the
// relay's behaviour (H-13).
const (
	// promptQuiet is how long nothing may arrive after a prompt before the
	// adapter acts on it (C2: "the transport acts on a prompt only after a
	// short quiet interval").
	promptQuiet = 200 * time.Millisecond
	// wakeWait is how long the port may stay silent after connecting before
	// the one wake line end is sent.
	wakeWait = time.Second
	// closeAllowance is what the QUI reply may add to max_response_bytes, so
	// that a session stopped at the limit can still end with QUI (D18).
	closeAllowance = 4096
	// maxCommands bounds Telnet negotiation in one session.
	maxCommands = 64
)

// hooks changes timing and adds an egress refusal, for tests only.
type hooks struct {
	quiet, wakeWait time.Duration
	egress          func(ph adapter.Phase, line string) error
}

// ops are the register operations this build can run and read.
var ops = map[string]bool{
	"sel.id": true, "sel.ser.read_all": true, "sel.settings.show_global": true, "sel.settings.show_port1": true,
}

const opID = "sel.id"

// serEmpty is the SER reply when the relay holds no records (S22 p. 7.75,
// "No Data Available"; the exact text is A6's transcription, H-13).
const serEmpty = "No Data Available"

// Identity attributes this build reads, and where (C1 names).
const (
	attrFID    = "firmware_id"   // ID at Level 0, before ACC
	attrSerial = "serial_number" // the SER header, at Level 1
	attrCID    = "sel.cid"       // ID; observed, never compared
)

var (
	errTimeout  = errors.New("sel751: the step timed out")
	errDeadline = errors.New("sel751: the deadline passed")
	errSilent   = errors.New("sel751: nothing received on connect")
	errTooLarge = errors.New("sel751: max_response_bytes reached")
	errClosed   = errors.New("sel751: the connection ended")
)

// Run runs one invocation and reports it. It never returns a Go error:
// every outcome is a C2 Result, and the collector checks it with Validate,
// CheckLines and CheckAgainst before using it.
//
// The dialogue (ADR-0005; A3 §8.3; C2 dialogue.go):
//
//  1. Checks with no traffic: register, invocation, asset and profile,
//     declared FID and its allowlist, credential slot.
//  2. Connect. If the port prints nothing for wakeWait, one bare line end
//     wakes it. A first prompt of "=>" or "=>>" ends the session with nothing
//     sent; a first "Password: ?" ends it before even the wake.
//  3. Probe: QUI after "=", whose reply must match the C2 probe grammar
//     (D16), then ID, whose FID must equal the declared FID exactly.
//  4. Auth, for an operation above Level 0: the floor gate, ACC after "=",
//     the secret only into "Password: ?", and nothing more until "=>"
//     confirms it (C-19). "=>" straight after ACC is AP-23: no secret, QUI.
//  5. Operate: the reads the register's checks name (SHO P 1: LANG :=
//     ENGLISH, posture warnings, firmware branch conditions), then the
//     invocation's operation.
//  6. Close: QUI when the session reached Level 1 and a level prompt makes
//     it safe, then the TCP close.
//
// Every line goes through telnet.Conn.Send, whose egress check passes it
// only if it is the line this step means to send, the register permits it
// in the current phase, and, in the operate phase, it is the invocation's
// operation or a read a register check names (C3, L4).
func Run(ctx context.Context, inv adapter.Invocation, cfg Config) adapter.Result {
	s := &session{ctx: ctx, inv: inv, cfg: cfg, level: -1}
	s.now = cfg.Now
	if s.now == nil {
		s.now = time.Now
	}
	s.h = hooks{quiet: promptQuiet, wakeWait: wakeWait}
	if cfg.hooks != nil {
		s.h = *cfg.hooks
	}
	s.started, s.wallStart = s.now(), time.Now()
	code := s.run()
	return s.result(code)
}

type found struct {
	value string
	span  adapter.Span
}

type session struct {
	ctx context.Context
	inv adapter.Invocation
	cfg Config
	h   hooks
	now func() time.Time

	m        *register.Matcher
	rule     *register.BranchRule
	op       *register.Operation
	expected map[string]string
	allowed  map[string]bool // operate lines: the operation and the reads the register's checks name
	target   asset.EvidenceClass
	regVer   uint64

	conn      *telnet.Conn
	nc        net.Conn
	started   time.Time // by Config.Now, for the result's times
	wallStart time.Time // by the wall clock, for timeouts
	deadline  time.Time
	step      time.Duration
	budget    int64 // max_response_bytes
	total     int64 // bytes received

	rec      recorder
	facts    adapter.SessionFacts
	phase    adapter.Phase
	want     string // the line the current step sends; egress refuses any other
	reply    []byte // received since the last send
	replyAt  time.Time
	replyOff int64 // the last committed reply, in the transcript
	replyLen int64
	lastRead time.Time
	last     string // the prompt the last reply ended with, "" after a send
	level    int    // the highest level a prompt showed
	afterACC bool
	level1   bool // "=>" or "=>>" after ACC: QUI is safe after a timeout
	credSent bool
	dead     bool // the transport ended; nothing more can be sent

	fid, cid, serial *found
	items            []adapter.IdentityItem
	warnings         []adapter.Warning
	records          []adapter.Record
	mismatch         string // the attribute that differed
	detail           string
	tidleReported    bool // Config.TIDLE was called (at most once per run)
}

func (s *session) run() adapter.Code {
	if code := s.check(); code != "" {
		return code
	}
	if code := s.connect(); code != "" {
		return code
	}
	defer s.nc.Close()
	stop := context.AfterFunc(s.ctx, func() { _ = s.nc.SetDeadline(time.Unix(1, 0)) })
	defer stop()
	code := s.dialogue()
	if s.quitAfter(code) && !s.quit() {
		// The session must end with QUI, but the connection is gone: the
		// relay may stay at the level until TIDLE (S22 p. 7.16).
		s.detail = fmt.Sprintf("the connection closed before QUI could be sent (after %s)", orOK(code))
		code = adapter.FailedTransportClosed
	}
	s.commit()
	return code
}

// check refuses, with no traffic, anything that would make the session
// unsafe or its result unusable. The collector has run its own checks
// (role, device-observed refusal, FID gate, busy, floor; A3); these repeat
// the ones the adapter's correctness depends on.
func (s *session) check() adapter.Code {
	for _, ep := range s.cfg.Asset.Endpoints {
		if ep.ID == s.inv.EndpointID {
			s.target = ep.Target
		}
	}
	p := s.cfg.Register
	if p == nil || p.Validate() != nil || p.Family != s.cfg.Profile.ProductFamily {
		s.detail = "no valid register package for the profile's family"
		return adapter.RefusedRegisterUnverified
	}
	s.regVer = p.Revision
	m, err := register.NewMatcher(p)
	if err != nil {
		s.detail = "the register package does not compile"
		return adapter.RefusedRegisterUnverified
	}
	s.m = m
	if err := s.inv.ValidateWith(adapter.RegisterLookup{M: m}); err != nil {
		return coded(err, adapter.RefusedLimits)
	}
	if err := s.inv.CheckAgainst(s.cfg.Asset, s.cfg.Profile); err != nil {
		return coded(err, adapter.RefusedInvocationMismatch)
	}
	if !ops[s.inv.OperationID] {
		s.detail = "this adapter build has no reader for the operation"
		return adapter.RefusedNotInvocable
	}
	s.op, _ = m.Operation(s.inv.OperationID)
	s.expected = map[string]string{}
	for _, e := range s.inv.Expected {
		if e.Name != attrFID && e.Name != attrSerial {
			s.detail = "expected identity names an attribute this adapter cannot read"
			return adapter.RefusedInvocationMismatch
		}
		s.expected[e.Name] = e.Value
	}
	fid, ok := s.expected[attrFID]
	if !ok {
		return adapter.RefusedFirmwareUndeclared
	}
	if s.rule, err = p.Firmware.Decide(fid); err != nil {
		return adapter.RefusedFirmwareNotAllowed
	}
	for _, c := range p.Preconditions {
		if c.Setting != "LANG" {
			s.detail = "a register precondition has no C2 code in this adapter build"
			return adapter.FailedInternal
		}
	}
	elevated := s.op.AccessLevel != register.ProbeAccessLevel
	switch {
	case elevated && s.cfg.Secret == nil:
		return adapter.RefusedCredentialUnavailable
	case elevated && s.cfg.Floor == nil, !elevated && s.cfg.Secret != nil:
		s.detail = "the credential slot and the floor gate do not fit the operation's level"
		return adapter.FailedInternal
	case s.cfg.Dial == nil:
		s.detail = "no dialer"
		return adapter.FailedInternal
	}
	s.allowed = map[string]bool{}
	for _, id := range s.reads() {
		line, err := m.Render(id, nil)
		if err != nil {
			s.detail = "a register check's read does not render"
			return adapter.FailedInternal
		}
		s.allowed[line] = true
	}
	own, err := m.Render(s.inv.OperationID, s.inv.Params)
	if err != nil {
		return adapter.RefusedInvalidParams
	}
	s.allowed[own] = true
	return ""
}

func coded(err error, fallback adapter.Code) adapter.Code {
	var ce *adapter.CodedError
	if errors.As(err, &ce) {
		return ce.Code
	}
	return fallback
}

// reads lists, in order, the operations the register's checks are read
// with: preconditions, the firmware branch's conditions, posture warnings.
// They run at Level 1, before the invocation's operation.
func (s *session) reads() []string {
	if s.op.AccessLevel == register.ProbeAccessLevel {
		return nil
	}
	var out []string
	seen := map[string]bool{}
	add := func(id string) {
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	p := s.cfg.Register
	for _, c := range p.Preconditions {
		add(c.ReadBy)
	}
	if s.rule != nil {
		for _, c := range s.rule.Conditions {
			add(c.ReadBy)
		}
	}
	for _, w := range p.Warnings {
		add(w.ReadBy)
	}
	return out
}

// connect dials the endpoint, retrying only before any byte is sent (D2).
func (s *session) connect() adapter.Code {
	var ep asset.Endpoint
	for _, e := range s.cfg.Asset.Endpoints {
		if e.ID == s.inv.EndpointID {
			ep = e
		}
	}
	if ep.Transport != asset.Telnet || ep.Host == "" || ep.Port <= 0 {
		s.detail = "the endpoint is not a Telnet endpoint with a host and port"
		return adapter.RefusedInvocationMismatch
	}
	l := s.inv.Limits
	s.deadline = s.wallStart.Add(time.Duration(l.DeadlineMS) * time.Millisecond)
	if d, ok := s.ctx.Deadline(); ok && d.Before(s.deadline) {
		s.deadline = d
	}
	s.step = time.Duration(l.StepTimeoutMS) * time.Millisecond
	s.budget = l.MaxResponseBytes
	addr := net.JoinHostPort(ep.Host, strconv.Itoa(ep.Port))
	var err error
	for try := 0; try <= l.ConnectRetries; try++ {
		ctx, cancel := context.WithTimeout(s.ctx, time.Duration(l.ConnectTimeoutMS)*time.Millisecond)
		s.nc, err = s.cfg.Dial(ctx, "tcp", addr)
		cancel()
		if err == nil {
			break
		}
		if s.ctx.Err() != nil {
			break
		}
	}
	if err != nil || s.nc == nil {
		s.detail = fmt.Sprintf("%d connection attempts failed", l.ConnectRetries+1)
		return adapter.FailedConnect
	}
	s.conn, err = telnet.New(s.nc, telnet.Config{
		MaxReceived: s.budget + closeAllowance, MaxCommands: maxCommands, Egress: s.egress,
	})
	if err != nil {
		s.nc.Close()
		s.detail = "the Telnet session could not start"
		return adapter.FailedInternal
	}
	s.facts = adapter.SessionFacts{Connected: true, LanguageProbe: adapter.ProbeNotRun,
		EchoScan: adapter.EchoScanNotApplicable, AccessLevel: "0"}
	s.phase = adapter.PhaseProbe
	return ""
}

// egress is the transport's check on every line (C3 Matcher.Permit, L4).
func (s *session) egress(line []byte) error {
	l := string(line)
	if s.want == "" || l != s.want {
		return errors.New("not the line this step sends")
	}
	if _, id, err := s.m.Permit(register.Phase(s.phase), l); err != nil {
		return fmt.Errorf("register: %v (%s)", err, id)
	}
	if s.phase == adapter.PhaseOperate && !s.allowed[l] {
		return errors.New("not the invocation's operation or a read a register check names")
	}
	if s.h.egress != nil {
		return s.h.egress(s.phase, l)
	}
	return nil
}

func (s *session) dialogue() adapter.Code {
	// Connect: a session left elevated or inside the password prompt is
	// left alone (S22 p. 7.16, p. 7.33; A3 change 7).
	p, err := s.await(time.Now().Add(s.h.wakeWait), false)
	if err == errSilent {
		_ = s.conn.SetDeadline(time.Now().Add(s.step))
		if err := s.conn.SendWake(); err != nil {
			return s.sendFailed(err)
		}
		s.rec.add(adapter.Sent, adapter.PhaseProbe, []byte("\r\n"), s.now())
		s.facts.WakeSent = true
		p, err = s.await(time.Time{}, false)
	}
	if err != nil {
		return s.stepFailed(err)
	}
	switch p {
	case promptLevel1, promptLevel2:
		return adapter.RefusedSessionElevated
	case promptPassword:
		if s.facts.WakeSent {
			// The floor should make this impossible: the wake landed in a
			// password prompt. Nothing more is sent.
			s.detail = "the wake was answered by the password prompt; nothing more sent"
			return adapter.FailedInternal
		}
		return adapter.RefusedSessionPendingPassword
	}

	// The language probe (ADR-0005, D16).
	if code := s.send(adapter.PhaseProbe, "QUI"); code != "" {
		return code
	}
	_, err = s.await(time.Time{}, false)
	rx := s.reply
	s.commit()
	if !adapter.ProbeReplyAccepted(rx) {
		// Any reply but the grammar's, a timeout or a closed connection
		// included, is a rejected probe: the port's commands are unknown,
		// so nothing more is sent (D16).
		s.facts.LanguageProbe = adapter.ProbeRejected
		return adapter.RefusedLanguageProbe
	}
	s.facts.LanguageProbe = adapter.ProbeAccepted
	if err != nil {
		// The reply fits the grammar, but no prompt the adapter acts on
		// followed it (the grammar ignores framing bytes; the prompt rule
		// does not), so nothing more is sent.
		return s.stepFailed(err)
	}

	// The FID gate (AP-27): ID at Level 0.
	idLine, err := s.m.Render(opID, nil)
	if err != nil {
		s.detail = "ID does not render"
		return adapter.FailedInternal
	}
	if code := s.send(adapter.PhaseProbe, idLine); code != "" {
		return code
	}
	if code := s.expect(promptLevel0); code != "" {
		return code
	}
	if code := s.identifyID(); code != "" {
		return code
	}
	if s.op.ID == opID {
		return ""
	}

	if code := s.authenticate(); code != "" {
		return code
	}
	for _, id := range s.reads() {
		if code := s.read(id); code != "" {
			return code
		}
	}
	return s.operate()
}

// expect waits for the reply to the line just sent and commits it. A prompt
// other than want ends the session with the code that prompt means.
func (s *session) expect(want string) adapter.Code {
	p, err := s.await(time.Time{}, false)
	s.commit()
	if err != nil {
		return s.stepFailed(err)
	}
	if p == want {
		return ""
	}
	switch {
	case p == promptLevel0 && s.level >= 1:
		return adapter.FailedAccessLevelDropped
	case p == promptPassword && s.level >= 1 && s.phase == adapter.PhaseOperate:
		// Anything sent now would be a password attempt (C-19), so nothing
		// more is sent, not even QUI (C2 0.2, D2-14).
		return adapter.FailedUnexpectedPasswordPrompt
	case p == promptPassword:
		// Before ACC (the reply to ID): no code names this state, and QUI
		// would still be a password attempt, so nothing more is sent.
		s.detail = "an unexpected password prompt before ACC; nothing more sent"
		return adapter.FailedInternal
	default:
		return adapter.FailedUnexpectedLevel
	}
}

// identifyID reads the ID reply and checks the FID against the declared one.
// A reply with no readable FID is a mismatch with nothing observed: the
// device did not print the declared FID.
func (s *session) identifyID() adapter.Code {
	off, rx := s.lastReply()
	exp := s.expected[attrFID]
	msg, err := frame(rx, off)
	var rep idReport
	if err == nil {
		rep, err = parseID(msg)
	}
	if err == nil {
		// An empty value has no span to point at (C2 spans are never
		// empty), so it is not read: an empty FID is no FID.
		if c, ok := rep.field("CID"); ok && c.value != "" {
			s.cid = &found{c.value, c.span}
		}
		if f, ok := rep.field("FID"); ok && f.value != "" {
			s.fid = &found{f.value, f.span}
			s.items = append(s.items, adapter.IdentityItem{Name: attrFID, Expected: exp, Observed: f.value, Span: f.span})
			if f.value == exp {
				return ""
			}
			s.mismatch = attrFID
			return adapter.RefusedIdentityMismatch
		}
	}
	s.items = append(s.items, adapter.IdentityItem{Name: attrFID, Expected: exp, Span: textSpan(rx, off)})
	s.mismatch = attrFID
	s.detail = "the ID reply has no readable FID line"
	return adapter.RefusedIdentityMismatch
}

// authenticate runs the auth phase (HR-3, C-17, C-19, AP-23, D1-20).
func (s *session) authenticate() adapter.Code {
	if err := s.cfg.Floor.BeforeACC(s.ctx); err != nil {
		s.detail = "the failed-auth floor could not be recorded; ACC not sent"
		return adapter.FailedInternal
	}
	if code := s.send(adapter.PhaseAuth, "ACC"); code != "" {
		return code
	}
	s.afterACC = true
	p, err := s.await(time.Time{}, false)
	s.commit()
	if err != nil {
		return s.stepFailed(err) // an unanswered ACC: nothing more is sent
	}
	switch p {
	case promptPassword:
		s.facts.PasswordPrompt = true
	case promptLevel1:
		s.cfg.Floor.Confirmed(s.ctx)
		return adapter.RefusedPasswordPromptAbsent
	default:
		return adapter.FailedUnexpectedLevel
	}

	// The credential slot: ACC passed egress, the reply ended in "Password:
	// ?", and nothing has been sent since.
	wrote := false
	err = s.cfg.Secret.Use(func(secret []byte) error {
		_ = s.conn.SetDeadline(time.Now().Add(s.step))
		wrote = true
		return s.conn.SendSecret(secret)
	})
	if err != nil && (!wrote || errors.Is(err, telnet.ErrEgress)) {
		s.detail = "the credential could not be sent; nothing more sent"
		return adapter.FailedInternal
	}
	s.rec.credential(s.now())
	s.credSent = true
	s.facts.CredentialSent = true
	s.facts.EchoScan = adapter.EchoScanPerformed
	s.last = ""
	if err != nil {
		s.dead = true
		return adapter.FailedTransportClosed
	}
	p, err = s.await(time.Time{}, false)
	s.commit()
	if err != nil {
		return s.stepFailed(err) // unconfirmed: no QUI (C-19, D1-20)
	}
	switch p {
	case promptLevel1:
		s.cfg.Floor.Confirmed(s.ctx)
		return ""
	case promptLevel2:
		return adapter.FailedUnexpectedLevel
	default:
		// A second "Password: ?" (S22 p. 7.33), or "=": rejected. Nothing
		// more is sent, not even QUI, which would be a second attempt.
		return adapter.FailedAuthRejected
	}
}

// read sends one register check's read and applies every check it serves:
// preconditions first (D16), then posture warnings, then firmware branch
// conditions.
func (s *session) read(id string) adapter.Code {
	line, _ := s.m.Render(id, nil)
	if code := s.send(adapter.PhaseOperate, line); code != "" {
		return code
	}
	if code := s.expect(promptLevel1); code != "" {
		return code
	}
	off, rx := s.lastReply()
	msg, err := frame(rx, off)
	var set map[string]setting
	if err == nil {
		set, err = parseSettings(msg)
	}
	p := s.cfg.Register
	for _, c := range p.Preconditions {
		if c.ReadBy != id {
			continue
		}
		// Only settings that parse as an English port's count (ADR-0005).
		if v, ok := set[c.Setting]; err != nil || !ok || v.value != c.Equals {
			return adapter.RefusedLanguageNotEnglish
		}
	}
	if err != nil {
		s.detail = "the settings reply does not parse"
		return adapter.FailedDeviceError
	}
	s.reportTIDLE(set)
	whole := adapter.Span{Offset: msg.off, Length: int64(len(msg.text))}
	for _, w := range p.Warnings {
		if w.ReadBy != id {
			continue
		}
		v, ok := set[w.Setting]
		switch {
		case !ok:
			s.warnings = append(s.warnings, adapter.Warning{Code: w.ID, Setting: w.Setting, Missing: true, Span: whole})
		case w.Raised(v.value):
			s.warnings = append(s.warnings, adapter.Warning{Code: w.ID, Setting: w.Setting, Observed: v.value, Span: v.span})
		}
	}
	for _, c := range s.rule.Conditions {
		if c.ReadBy != id {
			continue
		}
		if v, ok := set[c.Setting]; !ok || v.value != c.Equals {
			return adapter.RefusedFirmwareCondition
		}
	}
	return ""
}

// reportTIDLE hands the port's Telnet time-out to the collector, once, when
// the same reply shows LANG := ENGLISH, the register's language precondition,
// and TIDLE is 1 to 30 minutes, digits only (S22 Table 4.104).
func (s *session) reportTIDLE(set map[string]setting) {
	if s.cfg.TIDLE == nil || s.tidleReported || !s.english(set) {
		return
	}
	v, ok := set["TIDLE"]
	if !ok || len(v.value) == 0 || len(v.value) > 2 || strings.Trim(v.value, "0123456789") != "" {
		return
	}
	n, _ := strconv.Atoi(v.value)
	if n < 1 || n > 30 {
		return
	}
	s.tidleReported = true
	s.cfg.TIDLE(time.Duration(n) * time.Minute)
}

// english reports whether these settings show LANG := ENGLISH and the
// register makes that a precondition (ADR-0005).
func (s *session) english(set map[string]setting) bool {
	for _, c := range s.cfg.Register.Preconditions {
		if c.Setting == "LANG" && c.Equals == "ENGLISH" {
			v, ok := set["LANG"]
			return ok && v.value == "ENGLISH"
		}
	}
	return false
}

// operate runs the invocation's operation and reads its reply.
func (s *session) operate() adapter.Code {
	line, _ := s.m.Render(s.inv.OperationID, s.inv.Params)
	for _, id := range s.reads() {
		if id == s.inv.OperationID {
			return "" // already read, and its reply checked
		}
	}
	if code := s.send(adapter.PhaseOperate, line); code != "" {
		return code
	}
	if code := s.expect(promptLevel1); code != "" {
		return code
	}
	off, rx := s.lastReply()
	msg, err := frame(rx, off)
	if err != nil {
		s.detail = "the reply has no single framed message"
		return adapter.FailedDeviceError
	}
	if s.inv.OperationID != "sel.ser.read_all" {
		return ""
	}
	if string(bytes.TrimSpace(msg.text)) == serEmpty {
		// An empty buffer prints no report, so no header and no serial:
		// the FID read before ACC is the identity check (S22 p. 7.75).
		return ""
	}
	rep, err := parseSER(msg)
	if err != nil {
		s.detail = "the reply is not a SER report"
		return adapter.FailedDeviceError
	}
	if rep.serial != nil {
		s.serial = &found{rep.serial.value, rep.serial.span}
	}
	if exp, ok := s.expected[attrSerial]; ok {
		it := adapter.IdentityItem{Name: attrSerial, Expected: exp}
		if s.serial != nil {
			it.Observed, it.Span = s.serial.value, s.serial.span
		} else {
			it.Span = rep.context
			if it.Span.Length == 0 {
				it.Span = adapter.Span{Offset: msg.off, Length: int64(len(msg.text))}
			}
		}
		s.items = append(s.items, it)
		if it.Observed != exp {
			s.mismatch = attrSerial
			return adapter.FailedIdentityMismatchLate
		}
	}
	if limit := s.cfg.Profile.MaxReadRows; limit > 0 && len(rep.rows) > limit {
		s.detail = fmt.Sprintf("%d rows; profile %s max_read_rows is %d (D1-12)", len(rep.rows), s.cfg.Profile.ProfileID, limit)
		return adapter.PartialReadRowsExceeded
	}
	ctxSpan := rep.context
	code := adapter.Code("")
	for _, r := range rep.rows {
		rec := adapter.Record{Kind: "sel.ser.row", Span: r.span, ParseOK: r.ok}
		if ctxSpan.Length > 0 {
			sp := ctxSpan
			rec.ContextSpan = &sp
		}
		if r.ok {
			for i, name := range adapter.RecordFields["sel.ser.row"] {
				rec.Fields = append(rec.Fields, adapter.Field{Name: name, Value: r.fields[i]})
			}
		} else {
			code = adapter.PartialParseErrors
		}
		s.records = append(s.records, rec)
	}
	return code
}

// quitAfter decides whether the session ends with QUI (D18, V-S13). Never
// after a rejected probe or a non-English port (D16), a session found
// elevated or at a password prompt, a password no prompt confirmed (C-19),
// or a level that already dropped.
func (s *session) quitAfter(code adapter.Code) bool {
	if !s.facts.Connected {
		return false
	}
	switch code {
	case adapter.RefusedLanguageNotEnglish, adapter.FailedAccessLevelDropped, adapter.FailedTransportClosed,
		adapter.FailedAuthRejected, adapter.RefusedSessionElevated, adapter.RefusedSessionPendingPassword,
		adapter.RefusedLanguageProbe:
		return false
	}
	if s.last == promptPassword {
		return false
	}
	_, levelPrompt := promptLevels[s.last]
	safe := levelPrompt && (!s.credSent || s.level1)
	if !levelPrompt && (code == adapter.FailedTimeout || code == adapter.FailedResponseTooLarge) {
		// A step ended without a prompt. QUI is safe only once a level
		// prompt confirmed ACC and the password (C2 dialogue rule).
		safe = s.level1
	}
	return safe && (s.level >= 1 || code == "" || code == adapter.FailedUnexpectedLevel)
}

// quit sends QUI in the close phase and reads its reply. The close may run
// one step past the deadline: a session at Level 1 must end with QUI.
func (s *session) quit() bool {
	if code := s.send(adapter.PhaseClose, "QUI"); code != "" {
		return false
	}
	s.facts.QuitSent = true
	s.budget += closeAllowance
	_, _ = s.await(time.Time{}, true)
	return true
}

func orOK(c adapter.Code) string {
	if c == "" {
		return "ok"
	}
	return string(c)
}

// send writes one line through the egress check and records it.
func (s *session) send(ph adapter.Phase, line string) adapter.Code {
	s.commit()
	if s.dead {
		return adapter.FailedTransportClosed
	}
	s.phase = ph
	s.want = line
	_ = s.conn.SetDeadline(time.Now().Add(s.step))
	err := s.conn.Send([]byte(line + "\r\n"))
	s.want = ""
	if err != nil {
		return s.sendFailed(err)
	}
	s.rec.add(adapter.Sent, ph, []byte(line+"\r\n"), s.now())
	s.last = ""
	if line == "QUI" && ph == adapter.PhaseProbe {
		s.facts.LanguageProbe = adapter.ProbeRejected // until the reply is accepted
	}
	return ""
}

func (s *session) sendFailed(err error) adapter.Code {
	if errors.Is(err, telnet.ErrEgress) {
		s.detail = "a line failed the egress check and was not sent"
		return adapter.FailedEgressViolation
	}
	s.dead = true
	return adapter.FailedTransportClosed
}

func (s *session) stepFailed(err error) adapter.Code {
	switch {
	case errors.Is(err, errTimeout), errors.Is(err, errDeadline):
		return adapter.FailedTimeout
	case errors.Is(err, errTooLarge):
		return adapter.FailedResponseTooLarge
	}
	s.dead = true
	return adapter.FailedTransportClosed
}

// await reads until the bytes received since the last send end in a prompt
// and nothing more arrives for the quiet interval. silentBy, when set, is
// when an empty reply counts as silence (errSilent). Otherwise it stops at
// the step timeout, the deadline (not in the close phase), the response
// budget, or the end of the connection.
func (s *session) await(silentBy time.Time, closing bool) (string, error) {
	start := time.Now()
	stepEnd := start.Add(s.step)
	buf := make([]byte, 4096)
	for {
		now := time.Now()
		p := promptOf(s.reply)
		end, endErr := stepEnd, errTimeout
		if !closing && s.deadline.Before(end) {
			end, endErr = s.deadline, errDeadline
		}
		if !silentBy.IsZero() && len(s.reply) == 0 && silentBy.Before(end) {
			end, endErr = silentBy, errSilent
		}
		if p != "" {
			if q := s.lastRead.Add(s.h.quiet); !now.Before(q) {
				return s.saw(p), nil
			} else if q.Before(end) {
				end = q
			}
		}
		if s.ctx.Err() != nil {
			return "", errDeadline
		}
		if !now.Before(end) {
			return "", endErr
		}
		room := s.budget - s.total
		if room <= 0 {
			return "", errTooLarge
		}
		_ = s.conn.SetDeadline(end)
		n, err := s.conn.Read(buf[:min(int64(len(buf)), room)])
		if n > 0 {
			if len(s.reply) == 0 {
				s.replyAt = s.now()
			}
			s.reply = append(s.reply, buf[:n]...)
			s.total += int64(n)
			s.lastRead = time.Now()
			continue
		}
		if err == nil {
			continue
		}
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			continue
		}
		s.dead = true
		if p != "" {
			return s.saw(p), nil // nothing more can follow the prompt
		}
		return "", fmt.Errorf("%w: %v", errClosed, err)
	}
}

// saw records the prompt a reply ended with.
func (s *session) saw(p string) string {
	s.last = p
	if l, ok := promptLevels[p]; ok {
		s.noteLevel(l)
		if s.afterACC && l >= 1 {
			s.level1 = true
		}
	}
	return p
}

// noteLevel records a level a prompt showed. access_level is the highest
// level any reply's prompt showed by C2's rule, including a prompt the
// adapter did not act on (inside an open message, say), because Validate
// reads it from the bytes.
func (s *session) noteLevel(l int) {
	s.level = max(s.level, l)
	if s.level >= 0 {
		s.facts.AccessLevel = strconv.Itoa(s.level)
	}
}

// commit stores the reply received since the last send as one segment, with
// any echo of the secret redacted (C-A2-3), and starts a new reply.
func (s *session) commit() {
	if len(s.reply) == 0 {
		return
	}
	if l, ok := promptLevels[promptOf(s.reply)]; ok {
		s.noteLevel(l)
	}
	var echoes [][2]int
	if s.credSent {
		echoes = s.cfg.Secret.EchoSpans(s.reply)
	}
	s.replyOff = s.rec.received(s.phase, s.reply, echoes, s.replyAt)
	s.replyLen = int64(len(s.rec.t.Data)) - s.replyOff
	s.reply = nil
}

// lastReply returns the last committed reply as stored, and its offset.
func (s *session) lastReply() (int64, []byte) {
	return s.replyOff, s.rec.t.Data[s.replyOff : s.replyOff+s.replyLen]
}

// textSpan is the longest run of rx with no framing byte, so a span that
// stands for a whole unreadable reply never covers STX or ETX.
func textSpan(rx []byte, off int64) adapter.Span {
	best, start := adapter.Span{Offset: off}, 0
	for i := 0; i <= len(rx); i++ {
		if i < len(rx) && bytes.IndexByte([]byte{0x00, stx, etx, 0x11, 0x13}, rx[i]) < 0 {
			continue
		}
		if int64(i-start) > best.Length {
			best = adapter.Span{Offset: off + int64(start), Length: int64(i - start)}
		}
		start = i + 1
	}
	return best
}

// result builds the C2 result. Observations go to C1 only from a session
// that completed (ok or partial), or, for an identity mismatch, the value
// that differed, as the evidence for the suspension. Posture warnings are
// reported whenever SHO P 1 showed an English port. Records only with ok or
// partial.parse_errors.
func (s *session) result(code adapter.Code) adapter.Result {
	r := adapter.Result{
		Schema:          adapter.Contract,
		InvocationID:    s.inv.InvocationID,
		OperationID:     s.inv.OperationID,
		Adapter:         adapter.AdapterRef{ID: AdapterID, Version: Version},
		RegisterVersion: s.regVer,
		Target:          s.target,
		Status:          adapter.StatusOK,
		StartedAt:       stamp(s.started),
		EndedAt:         stamp(s.now()),
		Transcript:      s.rec.transcript(),
		Session:         s.facts,
		Identity:        adapter.IdentityCheck{Result: adapter.IdentityNotChecked},
	}
	if r.Target == "" {
		r.Target = asset.DeviceObserved // no endpoint: claim the stricter class
	}
	if !r.Session.Connected {
		r.Session = adapter.SessionFacts{LanguageProbe: adapter.ProbeNotRun, EchoScan: adapter.EchoScanNotApplicable}
	}
	if code != "" {
		r.Status = code.Status()
		r.Error = &adapter.Error{Code: code, Detail: s.detail}
	}
	if len(s.items) > 0 {
		r.Identity = adapter.IdentityCheck{Result: adapter.IdentityMatch, Items: s.items}
		if s.mismatch != "" {
			r.Identity.Result = adapter.IdentityMismatch
		}
	}
	obs := func(name string, f *found) {
		if f != nil && f.value != "" {
			r.Observations = append(r.Observations, adapter.Observation{Name: name, Value: f.value, Span: f.span})
		}
	}
	switch {
	case r.Status == adapter.StatusOK || r.Status == adapter.StatusPartial:
		obs(attrFID, s.fid)
		obs(attrCID, s.cid)
		obs(attrSerial, s.serial)
	case s.mismatch == attrFID:
		obs(attrFID, s.fid)
	case s.mismatch == attrSerial:
		obs(attrSerial, s.serial)
	}
	if code != adapter.RefusedLanguageNotEnglish {
		r.Warnings = s.warnings
	}
	if code == "" || code == adapter.PartialParseErrors {
		r.Records = s.records
	}
	return r
}
