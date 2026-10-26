package contract

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"otsec.local/otsec/contracts/event"
)

// C4 0.2 source.sender.tls_leaf_sha256 (A4, #167): A6's cases. The
// expected verdicts come from the rule text in contracts/event/event.go and
// doc.go: the fingerprint is the lowercase hex SHA-256 of the sender's DER
// certificate, required with origin_auth tls-mutual in an event of 0.2 or
// later, forbidden with any other origin_auth, and new in 0.2 (so forbidden
// in a 0.1 event). A 0.1 event stays valid without it. The input is the
// RTAC Syslog example, which is valid at 0.1 with origin_auth none.

func TestC4V02TLSLeaf(t *testing.T) {
	base := d123Event(t, "rtac-syslog-user-logon.json")
	const (
		schema = `"schema": "otsec.event/0.1"`
		sender = `"address": "192.0.2.40"`
		auth   = `"origin_auth": "none"`
	)
	for _, s := range []string{schema, sender, auth} {
		if bytes.Count(base, []byte(s)) != 1 {
			t.Fatalf("input changed: %s", s)
		}
	}
	sum := sha256.Sum256([]byte("a6 test certificate bytes"))
	good := hex.EncodeToString(sum[:])
	build := func(minor, origin, leafJSON string) []byte {
		b := bytes.Replace(base, []byte(schema), []byte(`"schema": "otsec.event/0.`+minor+`"`), 1)
		b = bytes.Replace(b, []byte(auth), []byte(`"origin_auth": "`+origin+`"`), 1)
		if leafJSON != "" {
			b = bytes.Replace(b, []byte(sender), []byte(sender+`, `+leafJSON), 1)
		}
		return b
	}
	leaf := func(v string) string { return `"tls_leaf_sha256": "` + v + `"` }
	for _, tc := range []struct {
		name string
		b    []byte
		ok   bool
	}{
		{"0.2 tls-mutual with its leaf", build("2", "tls-mutual", leaf(good)), true},
		{"0.2 tls-mutual without a leaf", build("2", "tls-mutual", ""), false},
		{"0.2 tls-mutual with an empty leaf", build("2", "tls-mutual", leaf("")), false},
		{"0.2 uppercase hex", build("2", "tls-mutual", leaf(strings.ToUpper(good))), false},
		{"0.2 63 hex digits", build("2", "tls-mutual", leaf(good[:63])), false},
		{"0.2 65 hex digits", build("2", "tls-mutual", leaf(good+"0")), false},
		{"0.2 not hex", build("2", "tls-mutual", leaf("g"+good[1:])), false},
		{"0.2 base64 of the digest", build("2", "tls-mutual", leaf("8J+YgPCfmIDwn5iA8J+YgPCfmIDwn5iA8J+YgA==")), false},
		{"0.2 tls-server-only with a leaf", build("2", "tls-server-only", leaf(good)), false},
		{"0.2 none with a leaf", build("2", "none", leaf(good)), false},
		{"0.2 tls-server-only without a leaf", build("2", "tls-server-only", ""), true},
		{"0.2 none without a leaf", build("2", "none", ""), true},
		{"0.1 tls-mutual without a leaf (an old event)", build("1", "tls-mutual", ""), true},
		{"0.1 tls-mutual with a leaf (new in 0.2)", build("1", "tls-mutual", leaf(good)), false},
		{"0.1 none with a leaf", build("1", "none", leaf(good)), false},
		{"0.3 tls-mutual with its leaf", build("3", "tls-mutual", leaf(good)), true},
		{"0.3 tls-mutual without a leaf", build("3", "tls-mutual", ""), false},
		{"case-variant key", build("2", "tls-mutual", `"TLS_LEAF_SHA256": "`+good+`"`), false},
		{"duplicate key", build("2", "tls-mutual", leaf(good)+`, `+leaf(good)), false},
		{"leaf as a number", build("2", "tls-mutual", `"tls_leaf_sha256": 1`), false},
	} {
		e, err := event.Decode(tc.b)
		if (err == nil) != tc.ok {
			t.Errorf("%s: Decode err = %v, want ok=%v", tc.name, err, tc.ok)
		}
		if err == nil && tc.ok && strings.Contains(tc.name, "its leaf") && e.Source.Sender.TLSLeafSHA256 != good {
			t.Errorf("%s: decoded leaf %q", tc.name, e.Source.Sender.TLSLeafSHA256)
		}
	}
}

// TestC4V02Identifier: every event this build writes says 0.2, so a
// tls-mutual event it writes must carry the leaf.
func TestC4V02Identifier(t *testing.T) {
	if event.Identifier != "otsec.event/0.2" {
		t.Fatalf("Identifier %q", event.Identifier)
	}
}
