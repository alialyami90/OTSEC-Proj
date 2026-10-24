package contract

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"

	"otsec.local/otsec/contracts/audit"
)

// C8 otsec.audit/0.1: A6's tamper and strictness cases (C8-A6 review and
// re-check). The chain is A6's own, sealed through the contract's Seal; the
// expected verdicts come from doc.go's claims (every change with a later
// record after it is detected; a tail change only against a head checkpoint,
// the AP-17 residual). Ground truth: GT-HAND, independent of A3's testdata.

const c8Node = "site-a6-node-1"

func c8Pending(action, extra string) []byte {
	return []byte(fmt.Sprintf(`{"contract":"otsec.audit/0.1","node_id":%q,`+
		`"time":{"utc":"2026-10-24T12:00:00.000001Z","resolution_ns":1000,"clock":{"sync":"synchronized","source":"ntp"}},`+
		`"actor":{"type":"system","id":"collector"},"action":%q,"outcome":"info"%s}`, c8Node, action, extra))
}

func c8Chain(t *testing.T) [][]byte {
	t.Helper()
	prev := strings.Repeat("0", 64)
	var out [][]byte
	for i, action := range []string{"audit.chain.start", "service.start", "service.start", "service.stop", "service.start", "service.stop"} {
		b, err := audit.Seal(c8Pending(action, ""), uint64(i+1), prev)
		if err != nil {
			t.Fatalf("seal %d: %v", i+1, err)
		}
		out = append(out, b)
		prev = audit.Hash(b)
	}
	return out
}

func c8Head(stored [][]byte, i int) *audit.Checkpoint {
	return &audit.Checkpoint{NodeID: c8Node, Seq: uint64(i + 1), Hash: audit.Hash(stored[i])}
}

func TestC8Tamper(t *testing.T) {
	s := c8Chain(t)
	last := len(s) - 1
	without := func(i int) [][]byte { return append(append([][]byte{}, s[:i]...), s[i+1:]...) }
	swap := append([][]byte{}, s...)
	swap[2], swap[3] = swap[3], swap[2]
	reenc := append([][]byte{}, s...)
	reenc[2] = append([]byte(" "), s[2]...)
	tail := append([][]byte{}, s...)
	tail[last] = append(append([]byte{}, s[last]...), ' ')
	for _, c := range []struct {
		name     string
		node     string
		stored   [][]byte
		from     *audit.Checkpoint
		head     *audit.Checkpoint
		verifies bool
	}{
		{"unchanged, no head", c8Node, s, nil, nil, true},
		{"unchanged, with head", c8Node, s, nil, c8Head(s, last), true},
		{"middle record dropped", c8Node, without(2), nil, nil, false},
		{"two records swapped", c8Node, swap, nil, nil, false},
		{"same JSON, other bytes", c8Node, reenc, nil, nil, false},
		{"prefix removed, no from", c8Node, s[2:], nil, nil, false},
		{"prefix removed, from held", c8Node, s[2:], c8Head(s, 1), nil, true},
		{"from with no node", c8Node, s[2:], &audit.Checkpoint{Seq: 2, Hash: audit.Hash(s[1])}, nil, false},
		{"last dropped, with head", c8Node, s[:last], nil, c8Head(s, last), false},
		{"last altered, with head", c8Node, tail, nil, c8Head(s, last), false},
		{"another node expected", "site-a6-node-2", s, nil, nil, false},
		{"no node expected", "", s, nil, nil, false},
		// The AP-17 residual, as documented: without a head, a change to the
		// newest record has nothing after it to break.
		{"last dropped, no head (residual)", c8Node, s[:last], nil, nil, true},
		{"last altered, no head (residual)", c8Node, tail, nil, nil, true},
	} {
		err := audit.VerifyChain(c.node, c.stored, c.from, c.head)
		if (err == nil) != c.verifies {
			t.Errorf("%s: verifies = %v (%v), want %v", c.name, err == nil, err, c.verifies)
		}
		if err != nil && !errors.Is(err, audit.ErrChainBroken) {
			t.Errorf("%s: error does not wrap ErrChainBroken: %v", c.name, err)
		}
	}
}

func TestC8RecordStrictness(t *testing.T) {
	s := c8Chain(t)
	if _, err := audit.ParseRecord(s[1]); err != nil {
		t.Fatalf("sealed record: %v", err)
	}
	for _, c := range []struct{ name, insert string }{
		{"unknown field on a 0.1 record", `"api_token":"x",`},
		{"secret-like field", `"secret_value":"x",`},
		{"password field", `"Password":"x",`},
		{"long-s secret", "\"ſecret\":\"x\","},
		{"case-variant duplicate of seq", `"SEQ":9,`},
	} {
		b := bytes.Replace(s[1], []byte("{"), []byte("{"+c.insert), 1)
		if _, err := audit.ParseRecord(b); err == nil {
			t.Errorf("ParseRecord: %s accepted", c.name)
		}
	}
	// A pending record may not choose its own place in the chain.
	if _, err := audit.ValidatePending(s[1]); err == nil {
		t.Error("ValidatePending accepted a record carrying seq and prev_hash")
	}
}
