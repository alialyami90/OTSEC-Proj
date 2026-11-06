package agent

// The agent's behaviour for each case of ../cases.json (the plan's section
// 2). A case changes the default agent in at most four ways: the served
// MIB, the engine ID it answers discovery with, its USM user, and a Hook
// that changes what it sends. Everything else is the default responder of
// agent.go. The runner checks what the client did; this file only states
// what the agent does.

import (
	"fmt"
	"slices"
	"sort"
	"strings"
)

// Spec is what the runner gives every agent: the engine ID the asset
// record pins, and the USM user the client's credential holds.
type Spec struct {
	EngineID []byte
	User     string
	Auth     Auth
	Password string
	LogPath  string
}

// FIDs (S29 p. 62, Tables A.2 to A.4). F3's is SYNTHESIZED from the form.
const (
	FID2731     = "SEL-2731M-R102-V1-Z003001-D20260408"
	FID2741     = "SEL-2741M-R102-V1-Z003001-D20260408"
	FID2731R100 = "SEL-2731M-R100-V0-Z001001-D20231120"
	FIDSDN      = "SEL-2731S-R102-V1-Z003001-D20260408"
	FID2743     = "SEL-2743M-R102-V1-Z003001-D20260424"
)

// OtherPassword is U2's agent password: another test-only value, so the
// client's MAC fails.
const OtherPassword = "gt-mib-u2-another-test-password"

// outside is an OID past entPhysicalTable (entLogicalTable's first
// column, RFC 6933 section 4), for W1.
const outside = "1.3.6.1.2.1.47.1.2.1.1.2.1"

type caseDef struct {
	mib    func(*Options) // nil: the default MIB, FID2731 in row 1's software revision
	engine bool           // answer with another engine ID than the pinned one (U1)
	user   func(u *User, s Spec, engine []byte)
	hook   func() Hook
	uptime int64 // snmpEngineTime at start, in seconds (U20)
}

// Cases lists every case ID the agent knows, in order.
func Cases() []string {
	ids := make([]string, 0, len(cases)+len(hostile)*2)
	for id := range cases {
		ids = append(ids, id)
	}
	for id, h := range hostile {
		for _, l := range h.layers {
			ids = append(ids, id+"/"+l)
		}
	}
	sort.Strings(ids)
	return ids
}

// NewCase is the Config of case id for spec. A hostile case is named
// "H<n>/outer" or "H<n>/scoped".
func NewCase(id string, spec Spec) (Config, error) {
	d, ok := cases[id]
	if !ok {
		hid, layer, _ := strings.Cut(id, "/")
		h, hok := hostile[hid]
		if !hok || !contains(h.layers, layer) {
			return Config{}, fmt.Errorf("gt-mib: no case %q", id)
		}
		d = caseDef{hook: func() Hook { return h.hook(layer) }}
	}
	engine := append([]byte(nil), spec.EngineID...)
	if d.engine {
		engine[len(engine)-1] ^= 0x03 // ...01 becomes ...02 (U1)
	}
	opts := Options{EngineID: engine, FID: FID2731}
	if d.mib != nil {
		d.mib(&opts)
	}
	u := NewUser(spec.User, spec.Auth, true, spec.Password, engine)
	if d.user != nil {
		d.user(&u, spec, engine)
	}
	cfg := Config{EngineID: engine, Users: []User{u}, MIB: NewMIB(opts), LogPath: spec.LogPath, Uptime: d.uptime}
	if d.hook != nil {
		cfg.Hook = d.hook()
	}
	return cfg, nil
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

// --- hook helpers ---

func send(x *Exchange, o *Out) Send { return Send{Bytes: o.Encode(x.User)} }

func isGet(x *Exchange) bool  { return x.Scoped.PDU.Tag == PDUGet }
func isBulk(x *Exchange) bool { return x.Scoped.PDU.Tag == PDUGetBulk }
func anyReq(*Exchange) bool   { return true }

// onResponse calls f for the i-th exchange (1-based) that reached the
// response stage and matches filter; every other exchange gets the default.
func onResponse(filter func(*Exchange) bool, f func(a *Agent, x *Exchange, i int) []Send) func() Hook {
	return func() Hook {
		i := 0
		return func(a *Agent, x *Exchange) []Send {
			if x.Stage == "response" && filter(x) {
				i++
				return f(a, x, i)
			}
			return a.DefaultSend(x)
		}
	}
}

// afterFID changes the first GetBulk Response that holds the FID's cell
// (entPhysicalSoftwareRev.1) with a varbind after it: change gets the
// varbinds and the cell's index, and returns the new varbinds.
func afterFID(change func(b []Bind, k int) []Bind) func() Hook {
	return func() Hook {
		done := false
		return onResponse(isBulk, func(a *Agent, x *Exchange, _ int) []Send {
			b := x.Out.Scoped.PDU.Binds
			k := slices.IndexFunc(b, func(v Bind) bool { return v.OID == EntCol(10, 1) })
			if done || k < 0 || k+1 >= len(b) {
				return a.DefaultSend(x)
			}
			done = true
			o := copyOut(a, x)
			o.Scoped.PDU.Binds = change(o.Scoped.PDU.Binds, k)
			return []Send{send(x, o)}
		})()
	}
}

// copyOut is a copy of x's default answer with a fresh salt, so a case can
// send several variants of it.
func copyOut(a *Agent, x *Exchange) *Out {
	o := *x.Out
	o.Scoped.PDU.Binds = append([]Bind(nil), x.Out.Scoped.PDU.Binds...)
	if o.Flags&FlagPriv != 0 {
		o.Salt = a.NextSalt()
	}
	return &o
}

// plain makes o a plaintext message at flags (no privacy).
func plain(o *Out, flags byte) *Out { o.Flags, o.Salt = flags, nil; return o }

func silent(*Agent, *Exchange) []Send { return nil }

var cases = map[string]caseDef{
	// 2.1 Identity, positive (V-M1 (e)).
	"I1": {},
	"I2": {mib: func(o *Options) { o.FID = FID2741 }},
	"I3": {mib: func(o *Options) { o.FIDCell = EntCol(2, 3) }},
	"I4": {mib: func(o *Options) { o.Extra = map[string]Var{SysDescr: Octets(FID2731)} }},
	"I5": {mib: func(o *Options) { o.Delete = []string{SysName} }},
	"I6": {mib: func(o *Options) { o.FID = FID2731R100 }},

	// 2.2 Identity, parse failures.
	"F1":  {mib: func(o *Options) { o.FID = "" }},
	"F2":  {mib: func(o *Options) { o.Extra = map[string]Var{EntCol(10, 3): Octets(FID2741)} }},
	"F3":  {mib: func(o *Options) { o.FID = FIDSDN }},
	"F4":  {mib: func(o *Options) { o.FID = FID2743 }},
	"F5a": {mib: func(o *Options) { o.FID = FID2731 + "X" }},
	"F5b": {mib: func(o *Options) { o.FID = strings.Replace(FID2731, "-V1-", "-\xc31-", 1) }},
	"F6":  {mib: func(o *Options) { o.FID = FID2741 }}, // the asset record declares sel-2731

	// 2.3 USM and downgrade (V-M1 (c)). The default answers the first
	// authPriv request, which carries boots and time 0, with the
	// authenticated time-window Report (RFC 3414 3.2 step 7a).
	"U1": {engine: true},
	"U2": {user: func(u *User, s Spec, engine []byte) { *u = NewUser(s.User, s.Auth, true, OtherPassword, engine) }},
	"U3": {user: func(u *User, s Spec, engine []byte) { u.Name = s.User + "-other" }},
	"U4a": {user: func(u *User, s Spec, engine []byte) {
		*u = NewUser(s.User, AuthSHA1, true, s.Password, engine)
	}},
	"U4b": {
		user: func(u *User, s Spec, engine []byte) { *u = NewUser(s.User, AuthSHA1, true, s.Password, engine) },
		hook: func() Hook {
			return func(a *Agent, x *Exchange) []Send {
				if x.Stage == "discovery" {
					return a.DefaultSend(x)
				}
				return nil
			}
		},
	},
	"U5": {user: func(u *User, s Spec, engine []byte) { u.Priv, u.PrivKey = false, nil }}, // authNoPriv only
	"U6": {hook: onResponse(anyReq, func(a *Agent, x *Exchange, _ int) []Send {
		return []Send{send(x, a.ReportOut(x, UsmStatsDecryptionErrors, false))}
	})},
	"U7": {},
	"U7b": {hook: onResponse(anyReq, func(a *Agent, x *Exchange, i int) []Send {
		if i == 1 {
			return nil
		}
		return a.DefaultSend(x)
	})},
	"U8": {hook: onResponse(anyReq, func(a *Agent, x *Exchange, _ int) []Send {
		return []Send{send(x, a.ReportOut(x, UsmStatsNotInTimeWindows, true))}
	})},
	"U9": {hook: func() Hook {
		return func(a *Agent, x *Exchange) []Send {
			if x.Report == UsmStatsNotInTimeWindows && x.Out != nil {
				return []Send{send(x, a.ReportOut(x, UsmStatsNotInTimeWindows, false))}
			}
			return a.DefaultSend(x)
		}
	}},
	"U10": {hook: onResponse(anyReq, func(a *Agent, x *Exchange, _ int) []Send {
		return []Send{send(x, plain(copyOut(a, x), 0))}
	})},
	"U11": {hook: onResponse(anyReq, func(a *Agent, x *Exchange, i int) []Send {
		if i > 1 {
			return nil
		}
		o := copyOut(a, x)
		o.BadMAC = true
		return []Send{send(x, o)}
	})},
	"U12": {hook: func() Hook { return silent }}, // v2c only: no v3 answer at all
	"U13": {},
	"U14": {},
	"U15": {hook: forged(false)},
	"U16": {hook: forged(true)},
	"U17": {hook: onResponse(anyReq, func(a *Agent, x *Exchange, _ int) []Send {
		return []Send{send(x, plain(copyOut(a, x), FlagAuth))}
	})},
	"U18": {hook: onResponse(anyReq, func(a *Agent, x *Exchange, _ int) []Send {
		o := copyOut(a, x)
		o.EngineID = append([]byte(nil), o.EngineID...)
		o.EngineID[len(o.EngineID)-1] ^= 0x03
		return []Send{send(x, o)}
	})},
	"U19a": {hook: onResponse(anyReq, func(a *Agent, x *Exchange, _ int) []Send {
		return []Send{send(x, a.ReportOut(x, UsmStatsUnknownEngineIDs, false))}
	})},
	"U19b": {hook: func() Hook {
		return func(a *Agent, x *Exchange) []Send {
			if x.Stage == "discovery" {
				return append([]Send{send(x, a.ReportOut(x, UsmStatsNotInTimeWindows, false))}, a.DefaultSend(x)...)
			}
			return a.DefaultSend(x)
		}
	}},
	"U20": {uptime: 4 * TimeWindow, hook: onResponse(anyReq, func(a *Agent, x *Exchange, _ int) []Send {
		lower := copyOut(a, x)
		lower.Boots--
		// Older than the window: RFC 3414 3.2 step 7b adopts a later time
		// from an authentic message, so only an earlier one is outside it.
		late := copyOut(a, x)
		late.Time -= 2 * TimeWindow
		r := a.ReportOut(x, UsmStatsNotInTimeWindows, true)
		r.Boots--
		return []Send{send(x, lower), send(x, late), send(x, r)}
	})},

	// 2.4 The walk and its bounds (V-M1 (b)).
	// W1 and W9 come just after the FID's cell, so that the walk has read
	// it and the run can end ok, as the table expects.
	"W1": {hook: afterFID(func(b []Bind, k int) []Bind {
		b[k+1] = Bind{OID: outside, Tag: TagOctets, Val: []byte(FID2741)}
		return b
	})},
	"W2": {hook: onResponse(isBulk, func(a *Agent, x *Exchange, i int) []Send {
		o := copyOut(a, x)
		if i == 1 && len(o.Scoped.PDU.Binds) > 2 {
			o.Scoped.PDU.Binds[1].OID = o.Scoped.PDU.Binds[0].OID
		}
		return []Send{send(x, o)}
	})},
	"W3": {hook: onResponse(isBulk, func(a *Agent, x *Exchange, i int) []Send {
		o := copyOut(a, x)
		if i == 1 && len(o.Scoped.PDU.Binds) > 3 {
			o.Scoped.PDU.Binds[2].OID = o.Scoped.PDU.Binds[0].OID
		}
		return []Send{send(x, o)}
	})},
	"W4": {mib: func(o *Options) { o.Rows = 40 }}, // 40 x 18 = 720 varbinds (RFC 6933 section 4)
	"W5": {hook: onResponse(isBulk, func(a *Agent, x *Exchange, _ int) []Send {
		o := copyOut(a, x)
		if len(o.Scoped.PDU.Binds) > 1 {
			o.Scoped.PDU.Binds = o.Scoped.PDU.Binds[:1]
		}
		return []Send{send(x, o)}
	})},
	"W6": {},
	"W7": {hook: onResponse(isBulk, func(a *Agent, x *Exchange, i int) []Send {
		if i > 1 {
			return a.DefaultSend(x)
		}
		o := copyOut(a, x)
		p := x.Scoped.PDU
		o.Scoped.PDU.Binds = nil
		for _, v := range a.MIB().Bulk(p.F1, p.F2, oidsOf(p)) {
			o.Scoped.PDU.Binds = append(o.Scoped.PDU.Binds, Bind{OID: v.OID, Tag: v.Tag, Val: v.Val})
		}
		// Ignore msgMaxSize: pad the last value until the message is 4000
		// bytes or more.
		last := &o.Scoped.PDU.Binds[len(o.Scoped.PDU.Binds)-1]
		for len(o.Encode(x.User)) < 4000 {
			last.Tag, last.Val = TagOctets, append(last.Val, make([]byte, 256)...)
		}
		return []Send{send(x, o)}
	})},
	"W8": {hook: onResponse(isBulk, func(a *Agent, x *Exchange, i int) []Send {
		o := copyOut(a, x)
		if i == 1 {
			o.Scoped.PDU.F1, o.Scoped.PDU.F2 = AuthorizationError, 1
			o.Scoped.PDU.Binds = []Bind{{OID: x.Scoped.PDU.Binds[0].OID, Tag: TagNull}}
		}
		return []Send{send(x, o)}
	})},
	"W9": {hook: afterFID(func(b []Bind, k int) []Bind {
		// RFC 3416 4.2.3: past the end, a repetition's varbind is
		// endOfMibView under the name it was asked for, the one before.
		return append(b[:k+1], Bind{OID: b[k].OID, Tag: EndOfMibView})
	})},

	// 2.5 Transport faults.
	"T1": {hook: onResponse(isBulk, func(a *Agent, x *Exchange, i int) []Send {
		if i == 1 {
			return nil
		}
		return a.DefaultSend(x)
	})},
	"T2": {hook: onResponse(isBulk, func(a *Agent, x *Exchange, i int) []Send {
		if i <= 2 {
			return nil
		}
		return a.DefaultSend(x)
	})},
	"T3": {hook: func() Hook { return silent }},
	"T4": {hook: onResponse(isGet, func(a *Agent, x *Exchange, i int) []Send {
		if i > 1 {
			return a.DefaultSend(x)
		}
		wrongMsg := copyOut(a, x)
		wrongMsg.MsgID++
		wrongReq := copyOut(a, x)
		wrongReq.Scoped.PDU.ReqID++
		return []Send{send(x, wrongMsg), send(x, wrongReq), send(x, copyOut(a, x))}
	})},
	"T5": {hook: onResponse(isGet, func(a *Agent, x *Exchange, i int) []Send {
		if i > 1 {
			return a.DefaultSend(x)
		}
		alt := send(x, copyOut(a, x))
		alt.Alt = true
		return []Send{alt, send(x, copyOut(a, x))}
	})},

	// 2.8 Module off and the transcript: the default agent. M1 and M2 must
	// receive nothing.
	"M1": {},
	"M2": {},
	"M3": {},

	// 2.6 positives.
	"H0": {hook: onResponse(isBulk, func(a *Agent, x *Exchange, i int) []Send {
		o := copyOut(a, x)
		if i == 1 && len(o.Scoped.PDU.Binds) > 1 {
			// A valid 9-octet Counter64 (2^63, with the 0x00 lead, RFC 2578
			// section 7.1.10 and X.690's two's complement).
			o.Scoped.PDU.Binds[1].Tag = TagCounter64
			o.Scoped.PDU.Binds[1].Val = []byte{0x00, 0x80, 0, 0, 0, 0, 0, 0, 0}
		}
		return []Send{send(x, o)}
	})},
}

func oidsOf(p PDU) []string {
	var out []string
	for _, b := range p.Binds {
		out = append(out, b.OID)
	}
	return out
}

// forged is U15 (the forged noAuthNoPriv usmStatsWrongDigests Report with
// the outstanding msgID, before the agent's own answer) or, with other,
// U16 (the same Report with another msgID, and with the right msgID from
// another source port, then the agent's own answer). It fires on the
// first authPriv request only, so the next run is the default.
func forged(other bool) func() Hook {
	return func() Hook {
		done := false
		return func(a *Agent, x *Exchange) []Send {
			if done || x.Level != "authPriv" {
				return a.DefaultSend(x)
			}
			done = true
			r := a.ReportOut(x, UsmStatsWrongDigests, false)
			if !other {
				return append([]Send{send(x, r)}, a.DefaultSend(x)...)
			}
			wrongID := *r
			wrongID.MsgID++
			fromAlt := send(x, r)
			fromAlt.Alt = true
			return append([]Send{send(x, &wrongID), fromAlt}, a.DefaultSend(x)...)
		}
	}
}
