package node

import (
	"strings"
	"testing"
)

func TestID(t *testing.T) {
	for _, s := range []string{"a", "site-a-node1", "0", strings.Repeat("a", 63)} {
		if !ID(s).Valid() {
			t.Errorf("%q rejected", s)
		}
	}
	for _, s := range []string{"", "-a", "a-", "Site", "a_b", "a.b", "a:b", strings.Repeat("a", 64), Reserved} {
		if ID(s).Valid() {
			t.Errorf("%q accepted", s)
		}
	}
}

// "audit" matches IDPattern but is refused, so no node's event ID has the
// form of an operator audit citation (D4-57). Names that only contain it
// are still node IDs.
func TestReservedID(t *testing.T) {
	if !idRE.MatchString(Reserved) || ID(Reserved).Valid() {
		t.Fatalf("%q: pattern %v, valid %v", Reserved, idRE.MatchString(Reserved), ID(Reserved).Valid())
	}
	for _, s := range []string{"audit1", "audit-node", "site-audit"} {
		if !ID(s).Valid() {
			t.Errorf("%q rejected", s)
		}
	}
}

func TestStream(t *testing.T) {
	for _, s := range []string{"a", "sel751-feeder1/ser", "platform/health", "syslog/192.0.2.40", strings.Repeat("a", 128)} {
		if !Stream(s).Valid() {
			t.Errorf("%q rejected", s)
		}
	}
	for _, s := range []string{"", "/a", "A", "a:b", "a b", strings.Repeat("a", 129)} {
		if Stream(s).Valid() {
			t.Errorf("%q accepted", s)
		}
	}
}
