package collectorwire

import (
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"strconv"
	"strings"
	"unicode/utf16"
)

// Service names (A5 installs both services under these names; ADR-0002).
const (
	NodeService      = "otsec-node"
	CollectorService = "otsec-collector"
	// DefaultPipe is the collector's pipe on Windows.
	DefaultPipe = `\\.\pipe\otsec-collector`
)

// Endpoint names the channel and the identity the far end must have.
//
// For Listen, Peer is the one client identity the collector accepts. For
// Dial, Peer is the identity the server must hold. On Windows Peer is a SID
// string, such as ServiceSID(NodeService); on Linux it is a decimal uid.
// An empty Peer is refused: there is no "accept anyone".
type Endpoint struct {
	// Address is the pipe name (\\.\pipe\...) on Windows, or the socket
	// path on Linux.
	Address string
	Peer    string
}

// ErrPeerRefused means the far end's identity is not the configured one.
// Nothing has been sent on the connection.
var ErrPeerRefused = errors.New("collectorwire: peer identity refused")

// ErrUnsupported is returned by Listen and Dial on an operating system with
// no transport.
var ErrUnsupported = errors.New("collectorwire: no transport on this operating system")

// ServiceSID returns the SID Windows gives the service name, NT
// SERVICE\<name>: S-1-5-80 followed by the SHA-1 of the upper-cased name in
// UTF-16LE, read as five little-endian 32-bit values. It is computed rather
// than looked up, so the configuration does not depend on the service being
// installed when the other side starts, and it is checked against a SID
// Windows publishes (servicesid_test.go).
func ServiceSID(name string) string {
	u := utf16.Encode([]rune(strings.ToUpper(name)))
	b := make([]byte, 2*len(u))
	for i, c := range u {
		binary.LittleEndian.PutUint16(b[2*i:], c)
	}
	h := sha1.Sum(b)
	var s strings.Builder
	s.WriteString("S-1-5-80")
	for i := 0; i < 5; i++ {
		s.WriteByte('-')
		s.WriteString(strconv.FormatUint(uint64(binary.LittleEndian.Uint32(h[4*i:])), 10))
	}
	return s.String()
}
