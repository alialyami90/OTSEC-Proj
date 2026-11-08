package adapter

import (
	"net"
	"net/netip"
	"strings"
	"time"

	"otsec.local/otsec/contracts/asset"
)

// validTime is a C2 time (0.9, D4-61): C1's form, RFC 3339 UTC with Z, with
// at most nine fractional digits, which time.Parse would otherwise cut
// without a word. It holds for results of every minor.
func validTime(s string) bool {
	if !asset.ValidTime(s) {
		return false
	}
	if i := strings.IndexByte(s, '.'); i >= 0 {
		return len(s)-i-2 <= 9 // the digits between '.' and 'Z'
	}
	return true
}

// LocalAddrOf is a socket's local address in session.local_addr's form
// (0.9): host:port, the host an IP literal in netip's canonical form,
// unmapped and without a zone, because the sensor sees the IP header and
// no zone (D4, D6 and D3 on #541). It returns "" when a is not an IP
// address with a port that ValidLocalAddr accepts.
func LocalAddrOf(a net.Addr) string {
	if a == nil {
		return ""
	}
	ap, err := netip.ParseAddrPort(a.String())
	if err != nil {
		return ""
	}
	s := netip.AddrPortFrom(ap.Addr().Unmap().WithZone(""), ap.Port()).String()
	if !ValidLocalAddr(s) {
		return ""
	}
	return s
}

// ValidLocalAddr reports whether s is a session.local_addr (0.9): an IP
// literal and a port in canonical form, refusing a hostname, a zone, port
// 0, the unspecified address, an IPv4-mapped IPv6 address and any other
// non-canonical form.
func ValidLocalAddr(s string) bool {
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		return false
	}
	a := ap.Addr()
	return a.Zone() == "" && !a.Is4In6() && !a.IsUnspecified() && ap.Port() != 0 && ap.String() == s
}

// connection checks session.local_addr and session.connected_at (0.9).
func (c *check) connection(r Result) {
	s, t := r.Session, r.Transcript
	if c.minor < 9 {
		if s.LocalAddr != "" || s.ConnectedAt != "" {
			c.fail("session.local_addr and session.connected_at are new in 0.9, so a 0.%d result cannot carry them", c.minor)
		}
		return
	}
	if s.Connected != (s.LocalAddr != "") || s.Connected != (s.ConnectedAt != "") {
		c.fail("session: connected needs local_addr and connected_at, and a session not connected has neither")
	}
	if s.LocalAddr != "" && !ValidLocalAddr(s.LocalAddr) {
		c.fail("session.local_addr %q is not an IP address and port in canonical form", s.LocalAddr)
	}
	if s.ConnectedAt == "" {
		return
	}
	at, ok := parseTime(s.ConnectedAt)
	if !ok {
		c.fail("session.connected_at is not an RFC 3339 UTC time with at most nine fractional digits")
		return
	}
	if start, ok := parseTime(r.StartedAt); ok && at.Before(start) {
		c.fail("session.connected_at is before started_at")
	}
	if end, ok := parseTime(r.EndedAt); ok && at.After(end) {
		c.fail("session.connected_at is after ended_at")
	}
	if len(t.Segments) == 0 {
		return
	}
	first, ok := parseTime(t.Segments[0].At)
	switch {
	case !ok:
	case c.snmp && (!at.Equal(first) || t.Segments[0].Dir != Sent):
		c.fail("session.connected_at of an SNMP session is the at of its first segment, which is sent")
	case at.After(first):
		c.fail("session.connected_at is after the first segment's at")
	}
}

func parseTime(s string) (time.Time, bool) {
	if !validTime(s) {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	return t, err == nil
}
