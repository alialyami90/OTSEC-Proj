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
	for _, s := range []string{"", "-a", "a-", "Site", "a_b", "a.b", "a:b", strings.Repeat("a", 64)} {
		if ID(s).Valid() {
			t.Errorf("%q accepted", s)
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
