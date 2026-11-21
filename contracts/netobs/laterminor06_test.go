package netobs

// The later-minor refusals at judging, C4 0.6's C4-0.6-3 and C13's
// stored-observation text beside it (docs/phase4/D4-c4-0.6-proposal.md
// §3.1, §3.2; tests E6-6 to E6-12, D4's unit rows). Every later minor is
// computed from event.Identifier or self, never written as a literal.

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"otsec.local/otsec/contracts/event"
	"otsec.local/otsec/contracts/version"
)

// c4At is C4's identifier at minor.
func c4At(major, minor int) string {
	return version.ID{Name: eventSelf.Name, Major: major, Minor: minor}.String()
}

// c4Later is one C4 minor above this build's.
func c4Later() string { return c4At(eventSelf.Major, eventSelf.Minor+1) }

// c13Later is one C13 minor above self.
func c13Later() string {
	return version.ID{Name: self.Name, Major: self.Major, Minor: self.Minor + 1}.String()
}

// fxObsEvent is a valid network-observation event at C4's own minor,
// carrying fxStored at C13's self.
func fxObsEvent(t *testing.T) *event.Event {
	t.Helper()
	e := &event.Event{
		Schema: event.Identifier, ID: event.EventID{NodeID: worstNode, Stream: worstStrm, Seq: 7},
		Origin: event.OriginPlatform, Kind: event.KindNetworkObservation,
		Source:   event.Source{Asset: &event.AssetRef{ID: fxAsset, Binding: event.Binding{Method: "observed-address", Confidence: "inferred"}}, OriginAuth: "platform"},
		Received: event.Received{UTC: "2026-11-07T10:00:01.123456789Z", ResolutionNS: 1, Clock: event.Clock{Sync: "synchronized", Source: "test-clock"}},
		Netobs:   mustJSON(t, fxStored()),
	}
	if err := e.Validate(); err != nil {
		t.Fatalf("the fixture event: %v", err)
	}
	return e
}

// laterRefusal reports whether err is one *Error, not a join, with
// CodeSchema at field and ErrLaterMinor.
func laterRefusal(err error, field string) bool {
	x, ok := err.(*Error)
	return ok && x.Code == CodeSchema && x.Field == field && errors.Is(err, ErrLaterMinor)
}

// TestE6x6LaterC4Observation is E6-6: a network-observation event one C4
// minor above event.Identifier is refused as schema with ErrLaterMinor,
// alone, and its observation is nil; the same event at event.Identifier is
// accepted.
func TestE6x6LaterC4Observation(t *testing.T) {
	e := fxObsEvent(t)
	if o, err := ObservationFromEvent(e); err != nil || o == nil {
		t.Fatalf("control: the event at %s: %v, %v", event.Identifier, o, err)
	}
	e.Schema = c4Later()
	o, err := ObservationFromEvent(e)
	if !laterRefusal(err, "schema") || o != nil {
		t.Errorf("the event at %s: %v, %v; want schema with ErrLaterMinor and a nil observation", e.Schema, o, err)
	}

	// Through event.Decode, with unknown keys at the top level and in
	// source.asset, which the later minor's forward read ignores.
	var m map[string]any
	if err := json.Unmarshal(mustJSON(t, e), &m); err != nil {
		t.Fatal(err)
	}
	m["added_later"] = true
	m["source"].(map[string]any)["asset"].(map[string]any)["added_later"] = "x"
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	d, err := event.Decode(b)
	if err != nil {
		t.Fatalf("event.Decode of the later event with unknown keys: %v", err)
	}
	if o, err := ObservationFromEvent(d); !laterRefusal(err, "schema") || o != nil {
		t.Errorf("with unknown keys: %v, %v; want schema with ErrLaterMinor, not decode", o, err)
	}

	// A second defect: the envelope asset conflicts with the body's
	// dst_asset. The refusal is alone, not joined with the conflict.
	e.Source.Asset.ID = fxMaster
	if o, err := ObservationFromEvent(e); !laterRefusal(err, "schema") || o != nil || len(Codes(err)) != 1 {
		t.Errorf("with a conflicting asset: %v, %v; want the refusal alone", o, err)
	}
	e.Schema = event.Identifier
	if _, err := ObservationFromEvent(e); !hasCode(err, CodeConflict) || errors.Is(err, ErrLaterMinor) {
		t.Errorf("control: the conflict at %s: %v", event.Identifier, err)
	}
}

// TestE6x7CheckHelper is E6-7: the helper against a reader minor that is
// neither C4's nor C13's, below, equal and above.
func TestE6x7CheckHelper(t *testing.T) {
	m := eventSelf.Minor + self.Minor + 1
	if m == eventSelf.Minor || m == self.Minor {
		t.Fatalf("reader minor %d is not apart from C4's %d and C13's %d", m, eventSelf.Minor, self.Minor)
	}
	for _, tc := range []struct {
		minor int
		later bool
	}{{m - 1, false}, {m, false}, {m + 1, true}} {
		err := checkEventMinor(c4At(eventSelf.Major, tc.minor), m)
		switch {
		case tc.later && !laterRefusal(err, "schema"):
			t.Errorf("minor %d against reader %d: %v, want ErrLaterMinor", tc.minor, m, err)
		case !tc.later && err != nil:
			t.Errorf("minor %d against reader %d: %v, want nil", tc.minor, m, err)
		}
	}
}

// TestE6x7GuardMinorsApart is E6-7's guard: while C4's minor equals C13's,
// E6-6 cannot kill the mutant that compares the event against C13's self.
func TestE6x7GuardMinorsApart(t *testing.T) {
	if eventSelf.Minor == self.Minor {
		t.Errorf("C4's minor %d equals C13's %d: E6-6 no longer kills the mutant that compares an event's minor against C13's self; set E6-6's control apart", eventSelf.Minor, self.Minor)
	}
}

// TestE6x8ValidatePath is E6-8: a later-C4 event with an unknown
// binding.method fails Validate, event.Decode still returns the event, and
// the check refuses it as a later minor; at event.Identifier the check
// returns nil.
func TestE6x8ValidatePath(t *testing.T) {
	e := fxObsEvent(t)
	e.Source.Asset.Binding.Method = "added-later"
	for _, tc := range []struct {
		schema string
		later  bool
	}{{c4Later(), true}, {event.Identifier, false}} {
		e.Schema = tc.schema
		d, err := event.Decode(mustJSON(t, e))
		if d == nil || err == nil {
			t.Fatalf("event.Decode at %s: %v, %v; want the event and a Validate error", tc.schema, d, err)
		}
		got := CheckEventMinor(d)
		switch {
		case tc.later && !laterRefusal(got, "schema"):
			t.Errorf("the check at %s: %v, want ErrLaterMinor", tc.schema, got)
		case !tc.later && got != nil:
			t.Errorf("the check at %s: %v, want nil", tc.schema, got)
		}
	}
}

// TestE6x9Unreadable is E6-9: a schema the check cannot read is refused
// as schema without ErrLaterMinor.
func TestE6x9Unreadable(t *testing.T) {
	maj, min := eventSelf.Major, eventSelf.Minor
	for name, s := range map[string]string{
		"none":                  "",
		"unparseable":           event.Identifier + "x",
		"no minor":              c4At(maj, min)[:len(c4At(maj, min))-1],
		"another name":          version.ID{Name: self.Name, Major: maj, Minor: min}.String(),
		"major + 1, minor 0":    c4At(maj+1, 0),
		"major + 1, minor + 1":  c4At(maj+1, min+1),
		"major + 1, same minor": c4At(maj+1, min),
		"another name, later":   version.ID{Name: self.Name, Major: maj, Minor: min + 1}.String(),
		"no otsec. prefix":      event.Identifier[len("otsec."):],
	} {
		e := fxObsEvent(t)
		e.Schema = s
		err := CheckEventMinor(e)
		if x, ok := err.(*Error); !ok || x.Code != CodeSchema || x.Field != "schema" || errors.Is(err, ErrLaterMinor) {
			t.Errorf("%s (%q): %v; want schema without ErrLaterMinor", name, s, err)
		}
		if o, err := ObservationFromEvent(e); o != nil || !hasCode(err, CodeSchema) || errors.Is(err, ErrLaterMinor) {
			t.Errorf("%s (%q) through ObservationFromEvent: %v, %v", name, s, o, err)
		}
	}
}

// TestE6x10FieldSplit is E6-10: a later-C13 body in a current-C4 envelope
// is refused with Field netobs.schema, alone, also with a second defect; a
// body error at self is prefixed; an oversize body keeps Field netobs.
func TestE6x10FieldSplit(t *testing.T) {
	e := fxObsEvent(t)
	body := fxStored()
	body.Schema = c13Later()
	e.Netobs = mustJSON(t, body)
	if o, err := ObservationFromEvent(e); !laterRefusal(err, "netobs.schema") || o != nil {
		t.Errorf("a later-C13 body: %v, %v; want netobs.schema with ErrLaterMinor, alone", o, err)
	}
	body.LastUTC = "2026-11-07T09:00:00.000000Z"
	e.Netobs = mustJSON(t, body)
	if o, err := ObservationFromEvent(e); !laterRefusal(err, "netobs.schema") || o != nil || len(Codes(err)) != 1 {
		t.Errorf("a later-C13 body with last_utc before first_utc: %v, %v; want the refusal alone", o, err)
	}
	body.Schema = SelfIdentifier()
	e.Netobs = mustJSON(t, body)
	_, err := ObservationFromEvent(e)
	if !refusedAt(err, CodeOrder, "netobs.last_utc") || errors.Is(err, ErrLaterMinor) {
		t.Errorf("control: the same body at self: %v; want order at netobs.last_utc", err)
	}
	e.Netobs = append(bytes.Repeat([]byte(" "), event.MaxNetobsBytes), []byte("{}")...)
	if _, err := ObservationFromEvent(e); err == nil || err.(*Error).Field != "netobs" || err.(*Error).Code != CodeRange {
		t.Errorf("an oversize body: %v; want range at netobs", err)
	}
	e.Netobs = []byte(`{"schema":1}`)
	if _, err := ObservationFromEvent(e); err == nil || err.(*Error).Field != "netobs" || err.(*Error).Code != CodeDecode {
		t.Errorf("a body that does not decode: %v; want decode at netobs", err)
	}
}

// TestE6x11Placement is E6-11: every other event one C4 minor later still
// passes event.Decode, and the alert still passes AlertFromEvent, so the
// refusal is not in Decode or Validate.
func TestE6x11Placement(t *testing.T) {
	later := c4Later()
	for _, name := range []string{
		"sel751-fig10-16-row1.json",       // SER
		"rtac-syslog-user-logon.json",     // Syslog
		"health-sensor-counters.json",     // sensor.counters
		"health-netobs-alert.json",        // netobs.alert
		"health-observation-refused.json", // detector.observation-refused
		"health-baseline-refused.json",    // detector.baseline-refused
		"constructed-network-observation.json",
	} {
		raw, err := os.ReadFile(filepath.Join("..", "event", "testdata", "valid", name))
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatal(err)
		}
		m["schema"] = later
		b, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := event.Decode(b); err != nil {
			t.Errorf("%s at %s: event.Decode refused it: %v", name, later, err)
		}
	}

	// The event fixture's alert body is illustrative, so the alert leg
	// builds a full alert from fxAlert.
	h, err := fxAlert().Health()
	if err != nil {
		t.Fatal(err)
	}
	e := fxObsEvent(t)
	e.Kind, e.Netobs, e.Health = event.KindHealth, nil, &h
	if err := e.Validate(); err != nil {
		t.Fatalf("the alert event: %v", err)
	}
	e.Schema = later
	d, err := event.Decode(mustJSON(t, e))
	if err != nil {
		t.Fatalf("the alert event at %s: event.Decode refused it: %v", later, err)
	}
	if _, err := AlertFromEvent(d); err != nil {
		t.Errorf("the alert event at %s: AlertFromEvent refused it: %v", later, err)
	}
}

// TestE6x12LaterC13Stored is E6-12: a stored observation one C13 minor
// above self is refused as schema with ErrLaterMinor, with and without an
// unknown key, and the observation is nil; the same record at self is
// read; a stored alert one minor later is still read.
func TestE6x12LaterC13Stored(t *testing.T) {
	o := fxStored()
	if got, err := DecodeStored(mustJSON(t, o)); err != nil || got == nil {
		t.Fatalf("control: the record at %s: %v, %v", SelfIdentifier(), got, err)
	}
	o.Schema = c13Later()
	plain := mustJSON(t, o)
	withKey := encodeWith(t, o, func(m map[string]any) { m["added_later"] = true })
	for name, b := range map[string][]byte{"no unknown key": plain, "an unknown key": withKey} {
		if got, err := DecodeStored(b); !laterRefusal(err, "schema") || got != nil {
			t.Errorf("%s at %s: %v, %v; want schema with ErrLaterMinor and nil", name, o.Schema, got, err)
		}
	}
	if err := o.ValidateStored(); !laterRefusal(err, "schema") {
		t.Errorf("ValidateStored at %s: %v", o.Schema, err)
	}

	a := fxAlert()
	a.Schema = c13Later()
	h, err := a.Health()
	if err != nil {
		t.Fatalf("an alert at %s: %v", a.Schema, err)
	}
	if _, err := AlertFromHealth(h); err != nil {
		t.Errorf("a stored alert at %s is not read: %v", a.Schema, err)
	}
}
