package collectorwire

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestDecodeStrict(t *testing.T) {
	type inner struct {
		B int `json:"b"`
	}
	type doc struct {
		A  int             `json:"a"`
		In inner           `json:"in"`
		L  []inner         `json:"l"`
		R  json.RawMessage `json:"r"`
	}
	ok := []string{
		`{"a":1}`,
		`{"a":1,"in":{"b":2},"l":[{"b":1},{"b":1}]}`,
		` {"a":1} `,
		`{"r":{"x":1,"y":{"x":2}}}`,
		// A raw value is a map to the checker: exact duplicates are refused,
		// case variants are its own decoder's business (C2, C8 strict).
		`{"r":{"x":1,"X":2}}`,
	}
	for _, s := range ok {
		var d doc
		if err := DecodeStrict([]byte(s), &d); err != nil {
			t.Errorf("%s: %v", s, err)
		}
	}
	bad := map[string]string{
		`{"a":1,"a":2}`:                 "duplicate",
		`{"a":1,"A":2}`:                 "not a field name",
		`{"A":1}`:                       "not a field name",
		"{\"\u017fx\":1}":               "not a field name",
		`{"in":{"b":1,"b":2}}`:          "duplicate",
		`{"l":[{"b":1,"b":2}]}`:         "duplicate",
		`{"r":{"x":1,"x":2}}`:           "duplicate",
		`{"a":1,"z":2}`:                 "not a field name",
		`{"a":1}{"a":2}`:                "trailing",
		`{"a":1} x`:                     "",
		"{\"a\":1,\"in\":{\"b\":\xff}}": "UTF-8",
		`{"a":`:                         "",
	}
	for s, want := range bad {
		var d doc
		err := DecodeStrict([]byte(s), &d)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: got %v, want an error containing %q", s, err, want)
		}
	}
}

// FuzzDecodeStrict: anything DecodeStrict accepts is a single valid JSON
// value with no duplicate keys, so encoding/json reads it the same way.
func FuzzDecodeStrict(f *testing.F) {
	f.Add([]byte(`{"a":{"b":[1,{"c":2}]}}`))
	f.Add([]byte(`{"a":1,"a":2}`))
	f.Add([]byte(`[{"a":1},{"a":1}]`))
	f.Fuzz(func(t *testing.T, in []byte) {
		var v any
		if err := DecodeStrict(in, &v); err != nil {
			return
		}
		if !json.Valid(in) {
			t.Fatalf("accepted invalid JSON %q", in)
		}
	})
}

func TestOutcomeRoundTrip(t *testing.T) {
	o := RunOutcome{InvocationID: "inv-1", Result: json.RawMessage(`{"x":1}`), Audit: []json.RawMessage{json.RawMessage(`{"y":2}`)}}
	b, err := EncodeOutcome(o)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeOutcome(b)
	if err != nil {
		t.Fatal(err)
	}
	if got.Wire != WireID || got.InvocationID != "inv-1" || string(got.Result) != `{"x":1}` || len(got.Audit) != 1 {
		t.Fatalf("got %+v", got)
	}
}

func TestDecodeOutcomeRefuses(t *testing.T) {
	cases := []string{
		`{"wire":"otsec.collectorwire/9.0","invocation_id":"i","result":{},"audit":[]}`,
		`{"wire":"otsec.collectorwire/0.1","invocation_id":"","result":{},"audit":[]}`,
		`{"wire":"otsec.collectorwire/0.1","invocation_id":"i","audit":[]}`,
		`{"wire":"otsec.collectorwire/0.1","invocation_id":"i","result":{}}`,
		`{"wire":"otsec.collectorwire/0.1","invocation_id":"i","result":{},"audit":[],"extra":1}`,
		`{"wire":"otsec.collectorwire/0.1","invocation_id":"i","invocation_id":"j","result":{},"audit":[]}`,
	}
	for _, s := range cases {
		if _, err := DecodeOutcome([]byte(s)); err == nil {
			t.Errorf("accepted %s", s)
		}
	}
	many := RunOutcome{InvocationID: "i", Result: json.RawMessage(`{}`)}
	for i := 0; i <= MaxOutcomeRecords; i++ {
		many.Audit = append(many.Audit, json.RawMessage(`{}`))
	}
	if _, err := EncodeOutcome(many); err == nil {
		t.Error("encoded more than MaxOutcomeRecords records")
	}
}

func TestDecodeReplyStrict(t *testing.T) {
	good := `{"contract":"otsec.authz/0.1","request_id":"r1","status":"accepted","invocation_id":"i","collector_seq":7}`
	r, err := DecodeReply([]byte(good))
	if err != nil || !r.Accepted() || r.CollectorSeq != 7 {
		t.Fatalf("got %+v, %v", r, err)
	}
	for _, s := range []string{
		`{"contract":"otsec.authz/0.1","request_id":"r1","status":"accepted","collector_seq":7,"collector_seq":8}`,
		`{"contract":"otsec.authz/0.1","request_id":"r1","status":"accepted","collector_seq":7,"note":"x"}`,
		// A6's review of #79: Unicode and ASCII case variants of a field name.
		`{"contract":"otsec.authz/0.1","request_id":"r1","status":"refused","ſtatus":"accepted","collector_seq":7}`,
		`{"contract":"otsec.authz/0.1","request_id":"r1","STATUS":"accepted","collector_seq":7}`,
		// C7 0.5 fields its stamp or status rules out.
		`{"contract":"otsec.authz/0.4","request_id":"r1","status":"accepted","collector_seq":7,"repeat_of":3}`,
		`{"contract":"otsec.authz/0.5","request_id":"r1","status":"accepted","collector_seq":7,"repeat_of":3}`,
	} {
		if _, err := DecodeReply([]byte(s)); err == nil {
			t.Errorf("accepted %s", s)
		}
	}
}
