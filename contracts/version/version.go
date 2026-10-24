// Package version parses contract identifiers and applies the compatibility
// rule in contracts/README.md.
//
// An identifier has the form "otsec.<name>/<major>.<minor>", for example
// "otsec.event/0.1". Within one major version a change is additive only, so a
// reader accepts every minor of its own major and tolerates fields it does not
// know, except where a contract declares itself strict. Different majors are
// incompatible.
package version

import (
	"fmt"
	"regexp"
	"strconv"
)

// ID is a parsed contract identifier.
type ID struct {
	Name  string // "event" in "otsec.event/0.1"
	Major int
	Minor int
}

var idPattern = regexp.MustCompile(`^otsec\.([a-z][a-z0-9-]*)/(0|[1-9][0-9]{0,3})\.(0|[1-9][0-9]{0,3})$`)

// Parse parses an identifier such as "otsec.event/0.1". It rejects anything
// else, including leading zeros, whitespace and upper case.
func Parse(s string) (ID, error) {
	m := idPattern.FindStringSubmatch(s)
	if m == nil {
		return ID{}, fmt.Errorf("version: %q is not a contract identifier of the form otsec.<name>/<major>.<minor>", s)
	}
	major, _ := strconv.Atoi(m[2])
	minor, _ := strconv.Atoi(m[3])
	return ID{Name: m[1], Major: major, Minor: minor}, nil
}

// String formats the identifier.
func (id ID) String() string {
	return fmt.Sprintf("otsec.%s/%d.%d", id.Name, id.Major, id.Minor)
}

// Accepts reports whether a reader built for id can read a message stamped
// with got: same contract name and same major version. The minor version may
// be higher or lower; readers ignore unknown fields unless the contract is
// strict, and producers never remove or redefine a field within a major.
func (id ID) Accepts(got ID) bool {
	return id.Name == got.Name && id.Major == got.Major
}
