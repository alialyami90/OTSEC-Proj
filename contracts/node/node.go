// Package node holds the identifiers that more than one contract needs and
// no single contract owns: the node ID and the stream token (A1 decision
// D1-1, docs/phase1/A1-decisions.md). C1 imports it for the collecting node,
// C4 for the event ID, and C5, C6 and C8 through C4. It exists so that no
// contract keeps a copy of another's pattern and C1 and C4 need not import
// each other.
//
// Owner: A1, like contracts/version. Proposed by A4, who maintains it.
package node

import "regexp"

// IDPattern is the node ID format: a lowercase DNS label, 1 to 63
// characters of letters, digits and inner hyphens. It is valid as a Syslog
// HOSTNAME (RFC 5424) and as a file name on Windows and Linux. JSON Schemas
// that cannot import Go repeat this pattern; their tests compare it with
// this constant.
const IDPattern = `^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`

// StreamPattern is the stream token format: 1 to 128 characters of
// lowercase letters, digits, '.', '_', '/' and '-', starting with a letter
// or digit. It never contains ':', which separates the parts of the
// canonical C4 event ID.
const StreamPattern = `^[a-z0-9][a-z0-9._/-]{0,127}$`

var (
	idRE     = regexp.MustCompile(IDPattern)
	streamRE = regexp.MustCompile(StreamPattern)
)

// ID names a platform node.
type ID string

// Valid reports whether id is a well-formed node ID.
func (id ID) Valid() bool { return idRE.MatchString(string(id)) }

// Stream names one native sequence space on a node, for example one
// device's SER buffer or one Syslog sender.
type Stream string

// Valid reports whether s is a well-formed stream token.
func (s Stream) Valid() bool { return streamRE.MatchString(string(s)) }
