package adapter

import (
	"encoding/json"
	"regexp"
)

// TelnetFacts are a connected Telnet session's counts (0.10, D4-102,
// docs/phase4/D2-c2-0.10-proposal.md §1). Every field is a number or a flag,
// and none carries device bytes. Each is a pointer, so that absent, 0 and
// false stay apart: an absent required field is never read as 0 or false.
type TelnetFacts struct {
	// Refusals is the three-octet refusals, IAC DONT x or IAC WONT x, the
	// transport wrote, each counted after its Write returned without error.
	Refusals *int64 `json:"refusals,omitempty"`
	// CommandOctetsReceived is the octets read from the socket less the data
	// octets the decoder produced.
	CommandOctetsReceived *int64 `json:"command_octets_received,omitempty"`
	// ReadToEOF: after QUI was sent, the close phase's last read returned
	// the relay's end of stream, with the decoder in no error.
	ReadToEOF *bool `json:"read_to_eof,omitempty"`
	// RexmitOctets is the payload octets the collector's socket
	// retransmitted to the device, as its kernel counts them. Exactly one of
	// it and RexmitUnknown is present.
	RexmitOctets *int64 `json:"rexmit_octets,omitempty"`
	// RexmitUnknown is why the count was not read: one of RexmitUnknowns in
	// a result of this package's minor or earlier, and any token of the same
	// form in a later one, which a reader takes as unknown. Every value
	// fails closed at the node.
	RexmitUnknown string `json:"rexmit_unknown,omitempty"`

	// emptyToken: the decoded JSON carried "rexmit_unknown": "", which is
	// present (only null is absent, §2 rule 5) though the string field
	// cannot say so. DecodeResult sets it; a writer cannot.
	emptyToken bool
}

// markEmptyToken sets emptyToken on r's session.telnet when b carries
// "rexmit_unknown": "" there. b has already decoded into r, so an error here
// cannot happen and is ignored.
func markEmptyToken(b []byte, r *Result) {
	if r.Session.Telnet == nil {
		return
	}
	var probe struct {
		Session struct {
			Telnet struct {
				RexmitUnknown *string `json:"rexmit_unknown"`
			} `json:"telnet"`
		} `json:"session"`
	}
	if json.Unmarshal(b, &probe) == nil {
		u := probe.Session.Telnet.RexmitUnknown
		r.Session.Telnet.emptyToken = u != nil && *u == ""
	}
}

// The rexmit_unknown tokens (0.10).
const (
	// RexmitInFlight: at the read, a payload octet written to the socket
	// was not acknowledged, whether sent or unsent.
	RexmitInFlight = "in-flight"
	// RexmitCallFailed: the call returned an error.
	RexmitCallFailed = "call-failed"
	// RexmitUnsupported: the platform predates the count, or the connection
	// has no socket to ask.
	RexmitUnsupported = "unsupported"
)

// RexmitUnknowns is the closed set of rexmit_unknown tokens at this minor.
var RexmitUnknowns = []string{RexmitInFlight, RexmitCallFailed, RexmitUnsupported}

// MaxTelnetCount is the largest count session.telnet carries, 2^53 - 1, so
// every reader's number type holds it exactly.
const MaxTelnetCount = 1<<53 - 1

// rexmitToken is the form of a rexmit_unknown token from any minor.
var rexmitToken = regexp.MustCompile(`^[a-z-]{1,32}$`)

// telnet checks session.telnet (0.10).
func (c *check) telnet(r Result) {
	s := r.Session
	t := s.Telnet
	if t == nil {
		// A later minor may add another connected transport, so a later
		// result is not held to this half (§2 rule 1).
		if c.minor >= 10 && !c.later && s.Connected && s.SNMP == nil {
			c.fail("session: a connected Telnet session carries session.telnet from 0.10")
		}
		return
	}
	if c.minor < 10 {
		c.fail("session.telnet is new in 0.10, so a 0.%d result cannot carry it", c.minor)
		return
	}
	if s.SNMP != nil || !s.Connected {
		c.fail("session.telnet belongs to a connected session that is not SNMPv3")
	}
	count := func(name string, v *int64) bool {
		switch {
		case v == nil:
			c.fail("session.telnet.%s is required", name)
		case *v < 0 || *v > MaxTelnetCount:
			c.fail("session.telnet.%s %d is outside 0 to 2^53 - 1", name, *v)
		default:
			return true
		}
		return false
	}
	okRefusals := count("refusals", t.Refusals)
	okCommand := count("command_octets_received", t.CommandOctetsReceived)
	if okRefusals && okCommand && *t.CommandOctetsReceived < 3**t.Refusals {
		c.fail("session.telnet.command_octets_received %d is less than 3 x refusals %d", *t.CommandOctetsReceived, *t.Refusals)
	}
	switch {
	case t.ReadToEOF == nil:
		c.fail("session.telnet.read_to_eof is required")
	case *t.ReadToEOF && !s.QuitSent:
		c.fail("session.telnet: read_to_eof needs quit_sent")
	}
	switch {
	case t.emptyToken:
		c.fail("session.telnet.rexmit_unknown is empty; only null is absent")
	case (t.RexmitOctets == nil) == (t.RexmitUnknown == ""):
		c.fail("session.telnet carries exactly one of rexmit_octets and rexmit_unknown")
	case t.RexmitOctets != nil:
		count("rexmit_octets", t.RexmitOctets)
	case !c.later && !contains(RexmitUnknowns, t.RexmitUnknown):
		c.fail("session.telnet.rexmit_unknown %q is not one of the %s tokens", t.RexmitUnknown, Contract)
	case !rexmitToken.MatchString(t.RexmitUnknown):
		c.fail("session.telnet.rexmit_unknown %q is not lowercase letters and hyphens, at most 32 octets", t.RexmitUnknown)
	}
}
