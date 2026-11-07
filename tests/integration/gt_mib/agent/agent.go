package agent

// The command responder: one SNMPv3 engine on a loopback UDP port, with
// one USM user. Each received datagram is processed as RFC 3412 section
// 7.2 and RFC 3414 section 3.2 say, in their order of checks:
//
//  1. the message decodes (RFC 3412 7.2 step 2; snmpInASNParseErrs);
//  2. msgVersion is 3 and msgSecurityModel is USM (step 4);
//  3. msgFlags is not privacy without authentication (step 5);
//  4. RFC 3414 3.2 step 1: the security parameters decode;
//  5. step 3: an unknown msgAuthoritativeEngineID gets the
//     usmStatsUnknownEngineIDs Report, which is discovery (section 4);
//  6. step 4: an unknown user, usmStatsUnknownUserNames;
//  7. step 5: a level the user does not support, usmStatsUnsupportedSecLevels;
//  8. step 6: a wrong MAC, usmStatsWrongDigests;
//  9. step 7a: outside the time window (boots differ, or time by more than
//     150 seconds), usmStatsNotInTimeWindows, reported at authNoPriv;
//  10. step 8: privParameters not 8 octets (RFC 3826 3.3.2 step 1),
//     usmStatsDecryptionErrors;
//  11. the ScopedPDU decodes, and the PDU is answered (RFC 3416 4.2).
//
// A Report is sent (RFC 3412 7.1 step 3b) when the PDU could be read and
// is of the Confirmed Class (RFC 3411 section 2.8: Get, GetNext, GetBulk,
// Set and Inform), or when it could not be read and the reportable flag is
// set. It goes at noAuthNoPriv unless the indication says authNoPriv
// (step 3d), with the request's msgID, request-id 0 where the PDU could
// not be read (step 3c), and the reportable flag cleared (step 7).
//
// Every datagram received is logged, decoded with this package's own
// decoder, before anything else is done with it. That log is the oracle for
// V-M1 (b).

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sync"
	"time"
)

// usmStats OIDs (RFC 3414 section 5: usmStats is usmMIBObjects 1,
// usmMIBObjects is snmpUsmMIB 1, snmpUsmMIB is snmpModules 15; RFC 2578
// section 2: snmpModules is 1.3.6.1.6.3).
const (
	UsmStats                     = "1.3.6.1.6.3.15.1.1"
	UsmStatsUnsupportedSecLevels = UsmStats + ".1.0"
	UsmStatsNotInTimeWindows     = UsmStats + ".2.0"
	UsmStatsUnknownUserNames     = UsmStats + ".3.0"
	UsmStatsUnknownEngineIDs     = UsmStats + ".4.0"
	UsmStatsWrongDigests         = UsmStats + ".5.0"
	UsmStatsDecryptionErrors     = UsmStats + ".6.0"
)

// TimeWindow is RFC 3414 section 2.2.3's 150 seconds.
const TimeWindow = 150

// Error statuses (RFC 3416 section 3).
const (
	TooBig             = 1
	NotWritable        = 17
	AuthorizationError = 16
)

// Send is one datagram to send. Alt sends it from the agent's second
// socket (another source port).
type Send struct {
	Bytes []byte
	Alt   bool
}

// Exchange is one received datagram and the agent's default answer.
type Exchange struct {
	N      int // 1-based count of datagrams received
	From   *net.UDPAddr
	Msg    *Msg   // nil if it did not decode
	Err    error  // why it did not decode, or was discarded
	Level  string // noAuthNoPriv, authNoPriv or authPriv as the flags say
	Scoped *Scoped
	Stage  string // where processing stopped: discovery, report, response, drop
	Report string // the usmStats OID reported, if any
	Out    *Out   // the default answer, if any
	User   User
}

// Hook lets a case change the answer. It returns what to send; returning
// nil sends nothing. The default is DefaultSend.
type Hook func(a *Agent, x *Exchange) []Send

// Config is one agent.
type Config struct {
	EngineID []byte
	Boots    int64
	Users    []User
	MIB      *MIB
	MaxSize  int64 // the local constraint; default 65507
	Hook     Hook
	LogPath  string
	Now      func() time.Time
	Uptime   int64 // snmpEngineTime at start, in seconds
}

// Agent is a running GT-MIB.
type Agent struct {
	cfg   Config
	conn  *net.UDPConn
	alt   *net.UDPConn
	start time.Time
	mu    sync.Mutex
	n     int
	ended int // datagrams the agent has finished with (Handled)
	salt  uint64
	log   *os.File
	done  chan struct{}
}

// Start listens on addr ("127.0.0.1:0" for any port), which must be a
// loopback IP literal: GT-MIB never listens beyond this host (D2-10; D3
// on #496). Both sockets bind that address.
func Start(addr string, cfg Config) (*Agent, error) {
	host, _, err := net.SplitHostPort(addr)
	if ip := net.ParseIP(host); err != nil || ip == nil || !ip.IsLoopback() {
		return nil, fmt.Errorf("gt-mib: listen address %q: a loopback IP literal only", addr)
	}
	if cfg.MaxSize == 0 {
		cfg.MaxSize = 65507
	}
	if cfg.Boots == 0 {
		cfg.Boots = 1
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	ua, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp", ua)
	if err != nil {
		return nil, err
	}
	alt, err := net.ListenUDP("udp", &net.UDPAddr{IP: ua.IP})
	if err != nil {
		conn.Close()
		return nil, err
	}
	a := &Agent{cfg: cfg, conn: conn, alt: alt, start: cfg.Now().Add(-time.Duration(cfg.Uptime) * time.Second), salt: 0x6774_6d69_6200_0000, done: make(chan struct{})}
	if cfg.LogPath != "" {
		if a.log, err = os.OpenFile(cfg.LogPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600); err != nil {
			conn.Close()
			alt.Close()
			return nil, err
		}
	}
	go a.serve()
	return a, nil
}

// Addr is the agent's address.
func (a *Agent) Addr() *net.UDPAddr { return a.conn.LocalAddr().(*net.UDPAddr) }

// Close stops the agent.
func (a *Agent) Close() error {
	a.conn.Close()
	a.alt.Close()
	<-a.done
	if a.log != nil {
		a.log.Close()
	}
	return nil
}

// Received is the number of datagrams received so far.
func (a *Agent) Received() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.n
}

// Handled is the number of datagrams the agent has finished with: every
// datagram it sent in answer to them is written to its socket.
func (a *Agent) Handled() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.ended
}

// EngineTime is the agent's snmpEngineTime now.
func (a *Agent) EngineTime() int64 { return int64(a.cfg.Now().Sub(a.start) / time.Second) }

// Boots is the agent's snmpEngineBoots.
func (a *Agent) Boots() int64 { return a.cfg.Boots }

// EngineID is the agent's snmpEngineID.
func (a *Agent) EngineID() []byte { return a.cfg.EngineID }

// MIB is the agent's served MIB.
func (a *Agent) MIB() *MIB { return a.cfg.MIB }

// NextSalt is the next privacy salt (RFC 3826 3.1.2.1: incremented by one
// per message).
func (a *Agent) NextSalt() []byte {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.salt++
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, a.salt)
	return b
}

func (a *Agent) serve() {
	defer close(a.done)
	buf := make([]byte, 65536)
	for {
		n, from, err := a.conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		raw := append([]byte(nil), buf[:n]...)
		a.mu.Lock()
		a.n++
		x := &Exchange{N: a.n, From: from}
		a.mu.Unlock()
		a.process(raw, x)
		var sends []Send
		if a.cfg.Hook != nil {
			sends = a.cfg.Hook(a, x)
		} else {
			sends = a.DefaultSend(x)
		}
		var sent []LogSent
		for _, s := range sends {
			c := a.conn
			if s.Alt {
				c = a.alt
			}
			_, _ = c.WriteToUDP(s.Bytes, from)
			sent = append(sent, a.describeSent(s))
		}
		a.write(x, raw, sent)
		a.mu.Lock()
		a.ended++
		a.mu.Unlock()
	}
}

// DefaultSend encodes the default answer, if any.
func (a *Agent) DefaultSend(x *Exchange) []Send {
	if x.Out == nil {
		return nil
	}
	return []Send{{Bytes: x.Out.Encode(x.User)}}
}

func level(flags byte) string {
	switch flags & 0x03 {
	case 0:
		return "noAuthNoPriv"
	case FlagAuth:
		return "authNoPriv"
	case FlagAuth | FlagPriv:
		return "authPriv"
	}
	return "privNoAuth"
}

// process runs the checks in order and leaves the default answer in x.
func (a *Agent) process(raw []byte, x *Exchange) {
	m, err := DecodeMsg(raw)
	x.Msg = m
	if err != nil {
		x.Err, x.Stage = err, "drop"
		return
	}
	if m.Version != 3 {
		x.Err, x.Stage = fmt.Errorf("msgVersion %d", m.Version), "drop"
		return
	}
	if m.Model != 3 {
		x.Err, x.Stage = fmt.Errorf("msgSecurityModel %d", m.Model), "drop"
		return
	}
	x.Level = level(m.Flags)
	if x.Level == "privNoAuth" {
		x.Err, x.Stage = fmt.Errorf("msgFlags 0x%02x", m.Flags), "drop"
		return
	}
	if m.Plain != nil {
		// RFC 3412 7.1 step 3a: "If possible, extract the request-id and
		// pduType." A plaintext ScopedPDU can be read before any check.
		if s, err := DecodeScoped(m.Plain); err == nil {
			x.Scoped = &s
		}
	}
	report := func(oid, lvl string, u User) {
		x.Stage, x.Report = "report", oid
		if x.Scoped != nil && !Confirmed(x.Scoped.PDU.Tag) || x.Scoped == nil && m.Flags&FlagReportable == 0 {
			x.Stage = "drop"
			return
		}
		x.User = u
		x.Out = a.ReportOut(x, oid, lvl == "authNoPriv")
	}
	if string(m.EngineID) != string(a.cfg.EngineID) {
		report(UsmStatsUnknownEngineIDs, "noAuthNoPriv", User{})
		if x.Stage == "report" {
			x.Stage = "discovery"
		}
		return
	}
	var u User
	found := false
	for _, c := range a.cfg.Users {
		if c.Name == string(m.User) {
			u, found = c, true
		}
	}
	if !found {
		report(UsmStatsUnknownUserNames, "noAuthNoPriv", User{})
		return
	}
	if (x.Level != "noAuthNoPriv" && u.Auth == "") || (x.Level == "authPriv" && !u.Priv) {
		report(UsmStatsUnsupportedSecLevels, "noAuthNoPriv", User{})
		return
	}
	x.User = u
	if x.Level != "noAuthNoPriv" {
		if !m.CheckMAC(u) {
			report(UsmStatsWrongDigests, "noAuthNoPriv", User{})
			return
		}
		now := a.EngineTime()
		if a.cfg.Boots == 2147483647 || m.Boots != a.cfg.Boots || m.Time > now+TimeWindow || m.Time < now-TimeWindow {
			report(UsmStatsNotInTimeWindows, "authNoPriv", u)
			return
		}
	}
	plain := m.Plain
	if x.Level == "authPriv" {
		if m.Encrypted == nil {
			x.Err, x.Stage = fmt.Errorf("authPriv with a plaintext ScopedPDU"), "drop"
			return
		}
		if plain, err = m.Decrypt(u); err != nil {
			report(UsmStatsDecryptionErrors, "noAuthNoPriv", User{})
			return
		}
	}
	s, err := DecodeScoped(plain)
	if err != nil {
		x.Err, x.Stage = err, "drop"
		return
	}
	x.Scoped = &s
	x.Out = a.respond(m, s, u)
	x.Stage = "response"
}

// respond answers a confirmed-class PDU (RFC 3416 4.2) at the request's
// level.
func (a *Agent) respond(m *Msg, s Scoped, u User) *Out {
	p := s.PDU
	r := PDU{Tag: PDUResponse, ReqID: p.ReqID}
	var oids []string
	for _, b := range p.Binds {
		oids = append(oids, b.OID)
	}
	var vars []Var
	switch p.Tag {
	case PDUGet:
		for _, o := range oids {
			vars = append(vars, a.cfg.MIB.Get(o))
		}
	case PDUGetNext:
		for _, o := range oids {
			vars = append(vars, a.cfg.MIB.Next(o))
		}
	case PDUGetBulk:
		vars = a.cfg.MIB.Bulk(p.F1, p.F2, oids)
	case PDUSet:
		// Read-only: every varbind is refused, the first named (RFC 3416
		// 4.2.5). The client must never send one (V-M1 (b)).
		r.F1, r.F2, r.Binds = NotWritable, 1, p.Binds
		return a.out(m, u, r)
	default:
		return nil // not confirmed class: no response
	}
	for _, v := range vars {
		r.Binds = append(r.Binds, Bind{OID: v.OID, Tag: v.Tag, Val: v.Val})
	}
	o := a.out(m, u, r)
	limit := min(m.MaxSize, a.cfg.MaxSize)
	if p.Tag == PDUGetBulk {
		// RFC 3416 4.2.3: drop trailing varbinds until it fits (reason
		// (1)); GetBulk never answers tooBig, and a Response that does not
		// fit even empty is dropped (snmpSilentDrops).
		for int64(len(o.Encode(u))) > limit {
			if len(o.Scoped.PDU.Binds) == 0 {
				return nil
			}
			o.Scoped.PDU.Binds = o.Scoped.PDU.Binds[:len(o.Scoped.PDU.Binds)-1]
		}
		return o
	}
	if int64(len(o.Encode(u))) > limit {
		// RFC 3416 4.2.1: tooBig, the request-id kept, error-index 0 and
		// no varbinds; dropped if even that does not fit.
		o.Scoped.PDU = PDU{Tag: PDUResponse, ReqID: p.ReqID, F1: TooBig}
		if int64(len(o.Encode(u))) > limit {
			return nil
		}
	}
	return o
}

// Confirmed reports whether a PDU tag is of the Confirmed Class (RFC 3411
// section 2.8).
func Confirmed(tag byte) bool {
	switch tag {
	case PDUGet, PDUGetNext, PDUGetBulk, PDUSet, PDUInform:
		return true
	}
	return false
}

// ReportOut is a Report answering x's message (RFC 3412 7.1 step 3): the
// counter oid with value 1, the request's msgID, its request-id where the
// PDU was read (0 otherwise), and this engine's boots and time. With auth
// it is sent authNoPriv with x.User's key (RFC 3414 3.2 step 7a);
// otherwise noAuthNoPriv. A case may send one where the default would not.
func (a *Agent) ReportOut(x *Exchange, oid string, auth bool) *Out {
	o := &Out{MaxSize: a.cfg.MaxSize, EngineID: a.cfg.EngineID, Boots: a.cfg.Boots, Time: a.EngineTime(),
		Scoped: Scoped{CtxEngine: a.cfg.EngineID, PDU: PDU{Tag: PDUReport,
			Binds: []Bind{{OID: oid, Tag: TagCounter32, Val: []byte{1}}}}}}
	if m := x.Msg; m != nil {
		o.MsgID, o.User = m.MsgID, m.User
	}
	if auth {
		o.Flags = FlagAuth
	}
	if x.Scoped != nil {
		o.Scoped.PDU.ReqID = x.Scoped.PDU.ReqID
	}
	return o
}

func (a *Agent) out(m *Msg, u User, p PDU) *Out {
	o := &Out{MsgID: m.MsgID, MaxSize: a.cfg.MaxSize, Flags: m.Flags &^ FlagReportable, EngineID: a.cfg.EngineID,
		Boots: a.cfg.Boots, Time: a.EngineTime(), User: m.User, Scoped: Scoped{CtxEngine: a.cfg.EngineID, PDU: p}}
	if o.Flags&FlagPriv != 0 {
		o.Salt = a.NextSalt()
	}
	return o
}

// --- the log ---

// LogBind is a logged varbind.
type LogBind struct {
	OID string `json:"oid"`
	Tag string `json:"tag"`
}

// LogPDU is a logged PDU.
type LogPDU struct {
	Type      string    `json:"type"`
	RequestID int64     `json:"request_id"`
	F1        int64     `json:"f1"` // error-status, or non-repeaters
	F2        int64     `json:"f2"` // error-index, or max-repetitions
	Binds     []LogBind `json:"varbinds"`
}

// LogSent is what was sent back.
type LogSent struct {
	Bytes  int    `json:"bytes"`
	Alt    bool   `json:"alt,omitempty"`
	Level  string `json:"level,omitempty"`
	PDU    string `json:"pdu,omitempty"`
	Report string `json:"report,omitempty"`
}

// LogEntry is one received datagram.
type LogEntry struct {
	N          int       `json:"n"`
	At         string    `json:"at"`
	From       string    `json:"from"`
	Bytes      int       `json:"bytes"`
	Hex        string    `json:"hex"`
	DecodeErr  string    `json:"decode_error,omitempty"`
	Version    int64     `json:"version"`
	Community  *string   `json:"community,omitempty"`
	MsgID      int64     `json:"msg_id"`
	MaxSize    int64     `json:"max_size"`
	Flags      int       `json:"flags"`
	Level      string    `json:"level,omitempty"`
	Model      int64     `json:"security_model"`
	EngineID   string    `json:"engine_id"`
	Boots      int64     `json:"boots"`
	Time       int64     `json:"time"`
	User       string    `json:"user"`
	AuthLen    int       `json:"auth_params_len"`
	PrivLen    int       `json:"priv_params_len"`
	CtxEngine  string    `json:"context_engine_id,omitempty"`
	CtxName    string    `json:"context_name,omitempty"`
	PDU        *LogPDU   `json:"pdu,omitempty"`
	Stage      string    `json:"stage"`
	Report     string    `json:"report,omitempty"`
	Sent       []LogSent `json:"sent"`
	Authentic  bool      `json:"authentic"`
	Discovery  bool      `json:"discovery"`
	Decrypted  bool      `json:"decrypted"`
	SourcePort int       `json:"source_port"`
}

func logPDU(p PDU) *LogPDU {
	l := &LogPDU{Type: PDUName(p.Tag), RequestID: p.ReqID, F1: p.F1, F2: p.F2, Binds: []LogBind{}}
	for _, b := range p.Binds {
		l.Binds = append(l.Binds, LogBind{OID: b.OID, Tag: fmt.Sprintf("0x%02x", b.Tag)})
	}
	return l
}

func (a *Agent) describeSent(s Send) LogSent {
	l := LogSent{Bytes: len(s.Bytes), Alt: s.Alt}
	if m, err := DecodeMsg(s.Bytes); err == nil && m.Version == 3 {
		l.Level = level(m.Flags)
		if m.Plain != nil {
			if sc, err := DecodeScoped(m.Plain); err == nil {
				l.PDU = PDUName(sc.PDU.Tag)
				if len(sc.PDU.Binds) == 1 && sc.PDU.Tag == PDUReport {
					l.Report = sc.PDU.Binds[0].OID
				}
			}
		} else {
			l.PDU = "encrypted"
		}
	}
	return l
}

func (a *Agent) write(x *Exchange, raw []byte, sent []LogSent) {
	if a.log == nil {
		return
	}
	e := LogEntry{N: x.N, At: time.Now().UTC().Format(time.RFC3339Nano), From: x.From.String(), SourcePort: x.From.Port,
		Bytes: len(raw), Hex: hex.EncodeToString(raw), Stage: x.Stage, Report: x.Report, Level: x.Level, Sent: sent}
	if e.Sent == nil {
		e.Sent = []LogSent{}
	}
	if x.Err != nil {
		e.DecodeErr = x.Err.Error()
	}
	if m := x.Msg; m != nil {
		e.Version, e.MsgID, e.MaxSize, e.Flags, e.Model = m.Version, m.MsgID, m.MaxSize, int(m.Flags), m.Model
		e.EngineID, e.Boots, e.Time, e.User = hex.EncodeToString(m.EngineID), m.Boots, m.Time, string(m.User)
		e.AuthLen, e.PrivLen = len(m.AuthParams), len(m.PrivParams)
		if m.Community != nil {
			c := string(m.Community)
			e.Community = &c
			if m.CommPDU != nil {
				e.PDU = logPDU(*m.CommPDU)
			}
		}
	}
	e.Discovery = x.Stage == "discovery"
	e.Authentic = x.Level != "" && x.Level != "noAuthNoPriv" && (x.Stage == "response" || x.Report == UsmStatsNotInTimeWindows ||
		x.Report == UsmStatsDecryptionErrors || (x.Stage == "drop" && x.Scoped == nil && x.Err != nil && x.Msg != nil && x.Msg.Encrypted != nil && x.User.Auth != ""))
	if x.Scoped != nil {
		e.CtxEngine, e.CtxName = hex.EncodeToString(x.Scoped.CtxEngine), string(x.Scoped.CtxName)
		e.PDU = logPDU(x.Scoped.PDU)
		e.Decrypted = x.Level == "authPriv"
	}
	b, _ := json.Marshal(e)
	a.mu.Lock()
	defer a.mu.Unlock()
	_, _ = a.log.Write(append(b, '\n'))
}
