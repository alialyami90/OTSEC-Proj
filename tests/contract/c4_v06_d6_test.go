package contract

// C4 otsec.event/0.6 (docs/phase4/D4-c4-0.6-proposal.md, approved at
// 5e7f0487 on #768, D4-121), D6's independent rows E6-1, E6-2 and E6-3,
// and E6-4 (c), the head leg, against step 1 (#772, merged as 9a6df521).
// Brief P4-4-C4-06-D6R (D4-121 item 3.10). E6-4 (a), its strict leg and the
// pins are in c4_v06_old_readers_d6_test.go, and E6-6 (with step 3, #780)
// in c4_v06_e66_d6_test.go. E6-17 (D4-120 item 3.4's workflow) is owed.
//
// The events are D6's own, built from §2's text, not from D4's code or
// tests. Each case pins the refusal as its exact list of (field, code)
// pairs, repeats kept, so a second error of the same code shows: §2 says a
// relation is checked over present, well-formed keys only, "so each
// refusal has one code". The codes where §2 is silent are D4's, recorded in
// D4-121 item 2.2 (D6's N1 on #772): stream, hash and the baseline schema
// as enum, and a seq key without its reason as forbidden. Where §2 names a
// relation over two details and not which one the refusal names, the field
// is pinned as at 9a6df521: first_seq.<r> for first_seq > last_seq,
// last_seq.<r> for last_seq > through, cause for later-minor with
// unreadable, and health.details.reason for an event with no reason.
//
// Later minors are computed from event.Identifier, earlier ones from 0 up
// to the minor that defines the types, and C13's identifier from
// netobs.SelfIdentifier(); no later minor is a literal (self-check 11).
// E6-2's later baseline stamp is netobs.BaselineIdentifier's minor + 1.
// BaselineIdentifier is the document's schema, not baselineSelf, which is
// unexported; both are 0.1 at 9a6df521, and C4 does not read lateness
// (§2.2, "Not checked by C4"), so the stamp's value cannot change an
// outcome here.
//
// Controls: each mutant that §6 names for E6-1 to E6-3 and E6-4 (c), and
// D6's six that survived D4's tests on #772 (M1, M2, M4, M8, M9, M19; D6's
// N3 there), applied one at a time to contracts/event/refused.go or
// event.go and shown failing these tests. The diffs, the commands and the
// outputs are in the PR body.
//
// Ground truth: GT-HAND, from the approved text. Every value is
// constructed; none is device output. Evidence class: desk, and CI-Linux
// and CI-Windows for these tests on the PR.

import (
	"encoding/json"
	"fmt"
	"maps"
	"reflect"
	"slices"
	"strings"
	"testing"

	"otsec.local/otsec/contracts/event"
	"otsec.local/otsec/contracts/netobs"
	"otsec.local/otsec/contracts/version"
)

const (
	c4v6Max  = "18446744073709551615" // 2^64 - 1
	c4v6Over = "18446744073709551616" // 2^64

	// c4v6Defining is the minor that defines both detector.* types (§2).
	c4v6Defining = 6

	c4v6Obs  = "detector.observation-refused"
	c4v6Base = "detector.baseline-refused"
)

// c4v6Minor returns event.Identifier with its minor moved by d.
func c4v6Minor(t *testing.T, d int) string {
	t.Helper()
	v, err := version.Parse(event.Identifier)
	if err != nil {
		t.Fatal(err)
	}
	v.Minor += d
	return v.String()
}

// c4v6Detector is a stored telemetry-health event of type typ, stamped
// schema, with details d.
func c4v6Detector(t *testing.T, schema, typ string, d map[string]string) []byte {
	t.Helper()
	e := map[string]any{"schema": schema, "id": map[string]any{"node_id": "d6-node", "stream": "platform/health", "seq": 61},
		"origin": "platform", "kind": "telemetry-health", "source": map[string]any{"origin_auth": "platform"},
		"received": map[string]any{"utc": "2026-11-21T09:00:00.000250Z", "resolution_ns": 1000,
			"clock": map[string]any{"sync": "synchronized", "source": "chrony"}},
		"health": map[string]any{"type": typ, "details": d}}
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// c4v6Pairs lists each failure in err as "field code", sorted, with
// repeats kept. A leaf that is not an *event.Error is listed as such.
func c4v6Pairs(err error) []string {
	var out []string
	var walk func(error)
	walk = func(err error) {
		switch x := err.(type) {
		case nil:
		case *event.Error:
			out = append(out, x.Field+" "+string(x.Code))
		case interface{ Unwrap() []error }:
			for _, y := range x.Unwrap() {
				walk(y)
			}
		default:
			out = append(out, "not an *event.Error: "+err.Error())
		}
	}
	walk(err)
	slices.Sort(out)
	return out
}

// c4v6D is the pair of a refused detail.
func c4v6D(k string, code event.Code) string { return "health.details." + k + " " + string(code) }

// c4v6Want decodes b and checks its refusal is exactly want; no want means
// accepted.
func c4v6Want(t *testing.T, name string, b []byte, want ...string) {
	t.Helper()
	_, err := event.Decode(b)
	got, w := c4v6Pairs(err), slices.Clone(want)
	slices.Sort(w)
	if !slices.Equal(got, w) {
		t.Errorf("%s:\n  got  %q\n  want %q\n  (%v)", name, got, w, err)
	}
}

// c4v6Edit returns a copy of base with set applied and del removed.
func c4v6Edit(base, set map[string]string, del ...string) map[string]string {
	d := maps.Clone(base)
	maps.Copy(d, set)
	for _, k := range del {
		delete(d, k)
	}
	return d
}

// c4v6Padded is v with whitespace or a line break around it, ending once
// in a forged Syslog line. A detail value is checked whole and never
// trimmed (D3's N1 on #778): the envelope checks no detail value, so one
// that passes here reaches C6's hd="key=value" as it is.
func c4v6Padded(v string) []string {
	return []string{" " + v, v + " ", "\t" + v, v + "\n", v + "\r\n<13>forged"}
}

// c4v6One is a valid counts event with one reason (§2.1).
func c4v6One() map[string]string {
	return map[string]string{
		"stream":  "network-observation/5a3c2e10-7b4d-4c8e-9f1a-2b3c4d5e6f70",
		"since":   "2026-11-21T08:00:00.000125Z",
		"through": "10",
		"netobs":  netobs.SelfIdentifier(),
		"count":   "2",

		"reason.malformed": "2", "first_seq.malformed": "9", "last_seq.malformed": "10",
	}
}

// c4v6Full is a valid counts event with every detail: the three reasons,
// and unsure.
func c4v6Full() map[string]string {
	return c4v6Edit(c4v6One(), map[string]string{
		"unsure": "9-10",
		"count":  "6",

		"reason.later-minor": "1", "first_seq.later-minor": "9", "last_seq.later-minor": "9",
		"reason.detector-refused": "3", "first_seq.detector-refused": "8", "last_seq.detector-refused": "10",
	})
}

// E6-1 (C4-0.6-1): detector.observation-refused's form at the reader's own
// minor.
func TestC4v06E61ObservationRefused(t *testing.T) {
	at := event.Identifier
	want := func(name string, d map[string]string, pairs ...string) {
		t.Helper()
		c4v6Want(t, name, c4v6Detector(t, at, c4v6Obs, d), pairs...)
	}
	one, full := c4v6One(), c4v6Full()

	// Accepted.
	want("one reason; first_seq 9, last_seq 10, through 10; no unsure", one)
	want("every detail", full)
	want("all three reasons, count at 2^64 - 1", c4v6Edit(full, map[string]string{"count": c4v6Max,
		"reason.later-minor": "18446744073709551613", "reason.malformed": "1", "reason.detector-refused": "1"}))
	want("first_seq = last_seq = through", c4v6Edit(one, map[string]string{"first_seq.malformed": "10"}))
	want("last_seq 9, through 10", c4v6Edit(one, map[string]string{"last_seq.malformed": "9"}))
	want("netobs from netobs.Identifier03", c4v6Edit(one, map[string]string{"netobs": netobs.Identifier03}))
	for _, u := range []string{"9-10", "8-9", "10-10", "1-10"} {
		want("unsure "+u+", through 10", c4v6Edit(one, map[string]string{"unsure": u}))
	}
	// netobs names the writer's C13 minor, which a later build may move.
	nv, err := version.Parse(netobs.SelfIdentifier())
	if err != nil {
		t.Fatal(err)
	}
	nv.Minor++
	want("netobs one C13 minor above this reader's", c4v6Edit(one, map[string]string{"netobs": nv.String()}))

	// Refused: each required key missing, as missing only, with no
	// relation code (a relation over a missing key: two codes).
	for _, k := range []string{"stream", "since", "through", "netobs", "count"} {
		want(k+" missing", c4v6Edit(full, nil, k), c4v6D(k, event.CodeMissing))
	}
	want("no reason", c4v6Edit(one, nil, "reason.malformed", "first_seq.malformed", "last_seq.malformed"),
		"health.details.reason "+string(event.CodeMissing))

	// A reason out of form; the sum and the seq relations are not checked
	// over it (M2).
	for _, v := range []string{"0", "01", c4v6Over, "", "-1", "+2", "2.0", "x"} {
		want("reason.malformed "+v, c4v6Edit(one, map[string]string{"reason.malformed": v}), c4v6D("reason.malformed", event.CodeEnum))
	}
	// Each count out of form, as one refusal.
	for _, k := range []string{"through", "count", "first_seq.malformed", "last_seq.malformed"} {
		for _, v := range []string{"0", "010", c4v6Over} {
			want(k+" "+v, c4v6Edit(full, map[string]string{k: v}), c4v6D(k, event.CodeEnum))
		}
	}

	// An unknown reason at the reader's own minor (enum), with or without
	// its seq keys, and with count counting it or not: one refusal per key,
	// and no relation over it (M19).
	for _, c := range []struct {
		count string
		seqs  bool
	}{{"2", false}, {"3", false}, {"2", true}, {"3", true}} {
		d := c4v6Edit(one, map[string]string{"count": c.count, "reason.other": "1"})
		pairs := []string{c4v6D("reason.other", event.CodeEnum)}
		if c.seqs {
			// first_seq above last_seq and last_seq above through, so a
			// relation checked over the unknown reason would add a code.
			d["first_seq.other"], d["last_seq.other"] = "12", "11"
			pairs = append(pairs, c4v6D("first_seq.other", event.CodeEnum), c4v6D("last_seq.other", event.CodeEnum))
		}
		want(fmt.Sprintf("reason.other, count %s, seqs %v", c.count, c.seqs), d, pairs...)
	}

	// A seq key without its reason (forbidden, D4-121 item 2.2), and the
	// reverse (missing).
	for _, k := range []string{"first_seq.later-minor", "last_seq.later-minor"} {
		want(k+" without its reason", c4v6Edit(one, map[string]string{k: "9"}), c4v6D(k, event.CodeForbidden))
	}
	withLM := c4v6Edit(one, map[string]string{"count": "3", "reason.later-minor": "1", "first_seq.later-minor": "9", "last_seq.later-minor": "9"})
	want("reason.later-minor without first_seq", c4v6Edit(withLM, nil, "first_seq.later-minor"), c4v6D("first_seq.later-minor", event.CodeMissing))
	want("reason.later-minor without last_seq", c4v6Edit(withLM, nil, "last_seq.later-minor"), c4v6D("last_seq.later-minor", event.CodeMissing))
	want("reason.later-minor without either seq", c4v6Edit(withLM, nil, "first_seq.later-minor", "last_seq.later-minor"),
		c4v6D("first_seq.later-minor", event.CodeMissing), c4v6D("last_seq.later-minor", event.CodeMissing))

	// The sum.
	want("count one above the sum", c4v6Edit(full, map[string]string{"count": "7"}), c4v6D("count", event.CodeEnum))
	want("count one below the sum", c4v6Edit(full, map[string]string{"count": "5"}), c4v6D("count", event.CodeEnum))
	want("count the number of reasons", c4v6Edit(full, map[string]string{"count": "3"}), c4v6D("count", event.CodeEnum))
	want("the wrapped sum", c4v6Edit(one, map[string]string{"count": "1", "reason.malformed": "2",
		"reason.later-minor": c4v6Max, "first_seq.later-minor": "9", "last_seq.later-minor": "9"}), c4v6D("count", event.CodeEnum))

	// The seq pair's order, as numbers.
	want("first_seq above last_seq", c4v6Edit(one, map[string]string{"first_seq.malformed": "7", "last_seq.malformed": "3"}),
		c4v6D("first_seq.malformed", event.CodeEnum))
	want("first_seq 10, last_seq 9", c4v6Edit(one, map[string]string{"first_seq.malformed": "10", "last_seq.malformed": "9"}),
		c4v6D("first_seq.malformed", event.CodeEnum))
	want("last_seq above through", c4v6Edit(one, map[string]string{"through": "5", "first_seq.malformed": "2", "last_seq.malformed": "6"}),
		c4v6D("last_seq.malformed", event.CodeEnum))
	want("last_seq 10, through 9", c4v6Edit(one, map[string]string{"through": "9"}), c4v6D("last_seq.malformed", event.CodeEnum))

	// A malformed through with a valid unsure and seq pair: only through
	// is refused (M4).
	want("through malformed, unsure valid", c4v6Edit(one, map[string]string{"through": "01", "unsure": "9-10"}),
		c4v6D("through", event.CodeEnum))

	// The other forms.
	for _, v := range []string{"2026-11-21 08:00:00Z", "2026-11-21T08:00:00", "", "x"} {
		want("since "+v, c4v6Edit(one, map[string]string{"since": v}), c4v6D("since", event.CodeTimeFormat))
	}
	for _, v := range []string{"", "Not A Token", "network observation"} {
		want("stream "+v, c4v6Edit(one, map[string]string{"stream": v}), c4v6D("stream", event.CodeEnum))
	}
	// netobs reads with the name netobs and no other: the baseline's
	// identifier, C4's own (M9), free text and empty.
	for _, v := range []string{netobs.BaselineIdentifier, event.Identifier, "netobs 0.3", ""} {
		want("netobs "+v, c4v6Edit(one, map[string]string{"netobs": v}), c4v6D("netobs", event.CodeEnum))
	}
	for _, v := range []string{"10-9", "9-11", "0-5", "9", "9-", "-10", "9-10-11", "09-10", "9-010", "nine-ten", ""} {
		want("unsure "+v+", through 10", c4v6Edit(one, map[string]string{"unsure": v}), c4v6D("unsure", event.CodeEnum))
	}
	// Each valid value padded is refused under the key's own code.
	valid := c4v6Edit(one, map[string]string{"unsure": "9-10"})
	for _, k := range []string{"stream", "since", "netobs", "unsure"} {
		code := event.CodeEnum
		if k == "since" {
			code = event.CodeTimeFormat
		}
		for _, v := range c4v6Padded(valid[k]) {
			want(fmt.Sprintf("%s %q", k, v), c4v6Edit(valid, map[string]string{k: v}), c4v6D(k, code))
		}
	}
}

// E6-2 (C4-0.6-2): detector.baseline-refused's form at the reader's own
// minor.
func TestC4v06E62BaselineRefused(t *testing.T) {
	at := event.Identifier
	want := func(name string, d map[string]string, pairs ...string) {
		t.Helper()
		c4v6Want(t, name, c4v6Detector(t, at, c4v6Base, d), pairs...)
	}
	const hash = "sha256:fcc505934269bbfbff031c5b6908d80d5a2672a19b6725533ec3d0918db5ce83"
	base := map[string]string{"hash": hash, "schema": netobs.BaselineIdentifier, "cause": "not-canonical"}
	bv, err := version.Parse(netobs.BaselineIdentifier)
	if err != nil {
		t.Fatal(err)
	}
	bv.Minor++
	laterStamp := bv.String()

	// Accepted.
	want("not-canonical", base)
	for _, c := range []string{"not-canonical", "malformed"} {
		want("unreadable, "+c, c4v6Edit(base, map[string]string{"schema": "unreadable", "cause": c}))
	}
	want("the baseline stamp one minor later, later-minor", c4v6Edit(base, map[string]string{"schema": laterStamp, "cause": "later-minor"}))

	// Refused.
	for _, k := range []string{"hash", "schema", "cause"} {
		want(k+" missing", c4v6Edit(base, nil, k), c4v6D(k, event.CodeMissing))
	}
	for _, v := range []string{
		"sha256:FCC505934269BBFBFF031C5B6908D80D5A2672A19B6725533EC3D0918DB5CE83",
		hash[:len(hash)-1],
		hash[len("sha256:"):],
		hash + "0",
		"",
	} {
		want("hash "+v, c4v6Edit(base, map[string]string{"hash": v}), c4v6D("hash", event.CodeEnum))
	}
	// schema reads with the name netbaseline: C4's own identifier, C13's
	// (M8), free text and empty.
	for _, v := range []string{event.Identifier, netobs.SelfIdentifier(), "Unreadable", "netbaseline 0.1", ""} {
		want("schema "+v, c4v6Edit(base, map[string]string{"schema": v}), c4v6D("schema", event.CodeEnum))
	}
	for _, v := range []string{"later", "Not-Canonical", "detector-refused", ""} {
		want("cause "+v, c4v6Edit(base, map[string]string{"cause": v}), c4v6D("cause", event.CodeEnum))
	}
	want("later-minor with unreadable", c4v6Edit(base, map[string]string{"schema": "unreadable", "cause": "later-minor"}),
		c4v6D("cause", event.CodeEnum))
	// The relation is not checked over a malformed schema or cause.
	want("later-minor with a malformed schema", c4v6Edit(base, map[string]string{"schema": "x", "cause": "later-minor"}),
		c4v6D("schema", event.CodeEnum))
	want("an unknown cause with unreadable", c4v6Edit(base, map[string]string{"schema": "unreadable", "cause": "later"}),
		c4v6D("cause", event.CodeEnum))
	// Each valid value padded is refused (enum).
	for _, k := range []string{"hash", "schema", "cause"} {
		for _, v := range c4v6Padded(base[k]) {
			want(fmt.Sprintf("%s %q", k, v), c4v6Edit(base, map[string]string{k: v}), c4v6D(k, event.CodeEnum))
		}
	}
	for _, v := range c4v6Padded("unreadable") {
		want(fmt.Sprintf("schema %q", v), c4v6Edit(base, map[string]string{"schema": v}), c4v6D("schema", event.CodeEnum))
	}
}

// E6-3 (§2, "Rules for both types"): minor gating. Each type is refused
// below 0.6 (forbidden, at health.type, naming 0.6), on every earlier
// minor (M1). At the reader's own minor the detail set is closed; one minor
// later it is open, and the keys §2 defines are still checked.
func TestC4v06E63Gating(t *testing.T) {
	types := []struct {
		typ string
		d   map[string]string
	}{
		{c4v6Obs, c4v6Full()},
		{c4v6Base, map[string]string{"hash": "sha256:fcc505934269bbfbff031c5b6908d80d5a2672a19b6725533ec3d0918db5ce83",
			"schema": netobs.BaselineIdentifier, "cause": "not-canonical"}},
	}
	defining := version.ID{Name: "event", Major: 0, Minor: c4v6Defining}.String()
	later := c4v6Minor(t, 1)

	for _, ty := range types {
		for m := 0; m < c4v6Defining; m++ {
			// The envelope is valid at every earlier minor, so the gate is
			// the one refusal.
			stamp := version.ID{Name: "event", Major: 0, Minor: m}.String()
			b := c4v6Detector(t, stamp, ty.typ, ty.d)
			c4v6Want(t, ty.typ+" at "+stamp, b, "health.type "+string(event.CodeForbidden))
			if _, err := event.Decode(b); !strings.Contains(fmt.Sprint(err), "new in "+defining) {
				t.Errorf("%s at %s: %v, want the refusal to name %s", ty.typ, stamp, err, defining)
			}
		}

		// At the reader's own minor, closed; one minor later, open.
		unknown := c4v6Edit(ty.d, map[string]string{"d6_later": "x"})
		c4v6Want(t, ty.typ+": an unknown key at "+event.Identifier, c4v6Detector(t, event.Identifier, ty.typ, unknown),
			c4v6D("d6_later", event.CodeEnum))
		c4v6Want(t, ty.typ+": an unknown key at "+later, c4v6Detector(t, later, ty.typ, unknown))
		c4v6Want(t, ty.typ+" at "+later, c4v6Detector(t, later, ty.typ, ty.d))
	}

	// One minor later, the keys §2 defines are still checked.
	obs := c4v6Full()
	c4v6Want(t, "a malformed through at "+later, c4v6Detector(t, later, c4v6Obs, c4v6Edit(obs, map[string]string{"through": "01"})),
		c4v6D("through", event.CodeEnum))
	c4v6Want(t, "a malformed reason at "+later, c4v6Detector(t, later, c4v6Obs, c4v6Edit(obs, map[string]string{"reason.malformed": "0"})),
		c4v6D("reason.malformed", event.CodeEnum))
	c4v6Want(t, "count off the sum at "+later, c4v6Detector(t, later, c4v6Obs, c4v6Edit(obs, map[string]string{"count": "7"})),
		c4v6D("count", event.CodeEnum))
	c4v6Want(t, "a seq key without its reason at "+later, c4v6Detector(t, later, c4v6Obs, c4v6Edit(obs, map[string]string{"count": "5"}, "reason.later-minor")),
		c4v6D("first_seq.later-minor", event.CodeForbidden), c4v6D("last_seq.later-minor", event.CodeForbidden))
	c4v6Want(t, "a malformed netobs at "+later, c4v6Detector(t, later, c4v6Obs, c4v6Edit(obs, map[string]string{"netobs": event.Identifier})),
		c4v6D("netobs", event.CodeEnum))
	c4v6Want(t, "a stream that is not a token at "+later, c4v6Detector(t, later, c4v6Obs, c4v6Edit(obs, map[string]string{"stream": "Not A Token"})),
		c4v6D("stream", event.CodeEnum))
	c4v6Want(t, "a since that is not RFC 3339 at "+later, c4v6Detector(t, later, c4v6Obs, c4v6Edit(obs, map[string]string{"since": "2026-11-21 08:00:00Z"})),
		c4v6D("since", event.CodeTimeFormat))
	c4v6Want(t, "unsure 10-9 at "+later, c4v6Detector(t, later, c4v6Obs, c4v6Edit(obs, map[string]string{"unsure": "10-9"})),
		c4v6D("unsure", event.CodeEnum))

	// An unknown reason one minor later: accepted with its seq pair and
	// summed into count; refused when count leaves it out, or without its
	// pair.
	lr := c4v6Edit(obs, map[string]string{"count": "10", "reason.d6-later": "4", "first_seq.d6-later": "9", "last_seq.d6-later": "10"})
	c4v6Want(t, "an unknown reason at "+later+", summed", c4v6Detector(t, later, c4v6Obs, lr))
	c4v6Want(t, "an unknown reason at "+later+", not summed", c4v6Detector(t, later, c4v6Obs, c4v6Edit(lr, map[string]string{"count": "6"})),
		c4v6D("count", event.CodeEnum))
	c4v6Want(t, "an unknown reason at "+later+" without last_seq", c4v6Detector(t, later, c4v6Obs, c4v6Edit(lr, nil, "last_seq.d6-later")),
		c4v6D("last_seq.d6-later", event.CodeMissing))
	c4v6Want(t, "an unknown reason at "+later+", last_seq above through", c4v6Detector(t, later, c4v6Obs, c4v6Edit(lr, map[string]string{"last_seq.d6-later": "11"})),
		c4v6D("last_seq.d6-later", event.CodeEnum))

	// An unknown cause one minor later: accepted when it is a token (D1-23,
	// D4-121 item 2.2), refused when it is not; hash still checked.
	base := types[1].d
	c4v6Want(t, "an unknown cause at "+later, c4v6Detector(t, later, c4v6Base, c4v6Edit(base, map[string]string{"cause": "d6-later"})))
	c4v6Want(t, "a cause that is not a token at "+later, c4v6Detector(t, later, c4v6Base, c4v6Edit(base, map[string]string{"cause": "Not A Token"})),
		c4v6D("cause", event.CodeEnum))
	// The token is checked over its whole length: at most 64 characters,
	// and nothing after them (D3's N1 on #778).
	tok64 := "d6-" + strings.Repeat("x", 61)
	c4v6Want(t, "a 64-character cause at "+later, c4v6Detector(t, later, c4v6Base, c4v6Edit(base, map[string]string{"cause": tok64})))
	for _, v := range append([]string{tok64 + "x", tok64 + "\r\n<13>forged"}, c4v6Padded("d6-later")...) {
		c4v6Want(t, fmt.Sprintf("cause %q at %s", v, later), c4v6Detector(t, later, c4v6Base, c4v6Edit(base, map[string]string{"cause": v})),
			c4v6D("cause", event.CodeEnum))
	}
	c4v6Want(t, "a malformed hash at "+later, c4v6Detector(t, later, c4v6Base, c4v6Edit(base, map[string]string{"hash": "sha256:x"})),
		c4v6D("hash", event.CodeEnum))
	c4v6Want(t, "a malformed schema at "+later, c4v6Detector(t, later, c4v6Base, c4v6Edit(base, map[string]string{"schema": event.Identifier})),
		c4v6D("schema", event.CodeEnum))
}

// E6-4 (c), the head leg (§6 E6-4; §1, "no field"): on the 0.6 code or
// later, c4v6Fill's network-observation and collection.run events, with
// every exported field of event.Event set, have the key paths pinned in
// the 0.5 code (c4v6Pinned05, 88 paths). A field 0.6 adds to event.Event or
// to a type under it is set by the fill, so it shows as a path not in the
// pins. Keys inside netobs and health.details are open, so "no flag" stays
// desk (§1).
func TestC4v06E64cHeadLeg(t *testing.T) {
	v, err := version.Parse(event.Identifier)
	if err != nil || v.Name != "event" || v.Major != 0 || v.Minor < c4v6Defining {
		t.Fatalf("event.Identifier is %s: (c) is the leg on the 0.6 code or later", event.Identifier)
	}
	if len(c4v6Pinned05) != 88 {
		t.Fatalf("the 0.5 pins hold %d paths, want 88 (#771)", len(c4v6Pinned05))
	}
	// The fill sets exported fields only. encoding/json also marshals the
	// exported fields of an unexported embedded struct, which the fill
	// would leave unset, so such a field could hide from the pins.
	c4v6NoHidden(t, "Event", reflect.TypeOf(event.Event{}), map[reflect.Type]bool{})

	for _, c := range []struct {
		kind event.Kind
		typ  string
	}{
		{event.KindNetworkObservation, ""},
		{event.KindHealth, "collection.run"},
	} {
		b, err := json.Marshal(c4v6Fill(t, c.kind, c.typ))
		if err != nil {
			t.Fatal(err)
		}
		got := c4v6Paths(t, b)
		var added, gone []string
		for _, p := range got {
			if !slices.Contains(c4v6Pinned05, p) {
				added = append(added, p)
			}
		}
		for _, p := range c4v6Pinned05 {
			if !slices.Contains(got, p) {
				gone = append(gone, p)
			}
		}
		if len(added) > 0 || len(gone) > 0 {
			t.Errorf("%s %q in the %s code: key paths not in the 0.5 pins %q, pinned paths missing %q", c.kind, c.typ, event.Identifier, added, gone)
		}
	}
}

// c4v6NoHidden fails for an unexported embedded struct anywhere under t.
func c4v6NoHidden(t *testing.T, path string, ty reflect.Type, seen map[reflect.Type]bool) {
	t.Helper()
	for ty.Kind() == reflect.Pointer || ty.Kind() == reflect.Slice || ty.Kind() == reflect.Map {
		ty = ty.Elem()
	}
	if ty.Kind() != reflect.Struct || seen[ty] {
		return
	}
	seen[ty] = true
	for i := 0; i < ty.NumField(); i++ {
		f := ty.Field(i)
		if f.Anonymous && !f.IsExported() {
			t.Errorf("%s embeds unexported %s, whose fields c4v6Fill cannot set", path, f.Type)
		}
		if f.IsExported() {
			c4v6NoHidden(t, path+"."+f.Name, f.Type, seen)
		}
	}
}
