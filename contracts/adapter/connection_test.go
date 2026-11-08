package adapter

import (
	"net"
	"testing"
)

// LocalAddrOf writes the form ValidLocalAddr accepts: unmapped, with no zone,
// and nothing for an address that is not an IP and port (0.9).
func TestLocalAddrOf(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	for _, c := range []struct {
		in   net.Addr
		want string
	}{
		{&net.TCPAddr{IP: net.IPv4(192, 0, 2, 10), Port: 49152}, "192.0.2.10:49152"},
		{&net.UDPAddr{IP: net.ParseIP("::ffff:192.0.2.10"), Port: 161}, "192.0.2.10:161"},
		{&net.TCPAddr{IP: net.ParseIP("fe80::1"), Port: 23, Zone: "eth0"}, "[fe80::1]:23"},
		{&net.TCPAddr{IP: net.ParseIP("2001:db8:0:0::1"), Port: 23}, "[2001:db8::1]:23"},
		{&net.TCPAddr{IP: net.IPv4zero, Port: 23}, ""},
		{&net.TCPAddr{IP: net.IPv4(192, 0, 2, 10)}, ""},
		{a.LocalAddr(), ""},
		{nil, ""},
	} {
		got := LocalAddrOf(c.in)
		if got != c.want {
			t.Errorf("%v: %q, want %q", c.in, got, c.want)
		}
		if got != "" && !ValidLocalAddr(got) {
			t.Errorf("%v: %q is not valid", c.in, got)
		}
	}
}

// A ten-digit fraction is refused in every minor, and nine are kept (0.9,
// D4-61).
func TestValidTime(t *testing.T) {
	for s, want := range map[string]bool{
		"2026-11-07T20:00:00Z":            true,
		"2026-11-07T20:00:00.1Z":          true,
		"2026-11-07T20:00:00.123456789Z":  true,
		"2026-11-07T20:00:00.1234567891Z": false,
		"2026-11-07T20:00:00.123+00:00":   false,
	} {
		if validTime(s) != want {
			t.Errorf("%s: %v, want %v", s, !want, want)
		}
	}
}
