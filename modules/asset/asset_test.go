package asset

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"otsec.local/otsec/contracts/adapter"
	c1 "otsec.local/otsec/contracts/asset"
)

// The inputs are the C1 and C2 goldens: the simulated SEL-751 record and the
// C2 results of a simulated SEL-751 session. Every value in them is invented.

const ep = "port1-telnet"

func record(t *testing.T, name string) c1.Asset {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "contracts", "asset", "testdata", "valid", name))
	if err != nil {
		t.Fatal(err)
	}
	a, err := c1.Decode(b)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func result(t *testing.T, name string) adapter.Result {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "contracts", "adapter", "testdata", "results", "valid", name+".json"))
	if err != nil {
		t.Fatal(err)
	}
	r, err := adapter.DecodeResult(b)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func attr(t *testing.T, a c1.Asset, name string) c1.Attribute {
	t.Helper()
	at, ok := a.Attribute(name)
	if !ok {
		t.Fatalf("no attribute %s", name)
	}
	return at
}

func names(cs []Change) string {
	var out []string
	for _, c := range cs {
		out = append(out, c.Name)
	}
	slices.Sort(out)
	return strings.Join(out, ",")
}

func TestApply(t *testing.T) {
	rec, res := record(t, "sel-751-simulated.json"), result(t, "ok")
	out, changes, err := Apply(rec, res, ep)
	if err != nil {
		t.Fatal(err)
	}
	if err := out.Validate(); err != nil || out.Schema != c1.Contract {
		t.Fatalf("%s: %v", out.Schema, err)
	}
	// firmware_id and sel.cid are read again with the values the record
	// holds, so the first read stays and nothing changes. The model and the
	// firmware version are new; the serial number gains a session read.
	if got := names(changes); got != "firmware_version,model,serial_number" {
		t.Errorf("changes %s", got)
	}
	before, after := attr(t, rec, c1.AttrFirmwareID), attr(t, out, c1.AttrFirmwareID)
	if !reflect.DeepEqual(before, after) {
		t.Errorf("firmware_id moved: %+v", after)
	}
	for name, op := range map[string]string{c1.AttrModel: "sel.id", c1.AttrFirmwareVersion: "sel.id", c1.AttrSerialNumber: res.OperationID} {
		at := attr(t, out, name)
		o := at.Observations[len(at.Observations)-1]
		src := o.Source
		if o.EvidenceClass != c1.Simulated || src.Method != c1.SimulatorRun || src.Kind != c1.DeviceRead || src.Ref != res.InvocationID ||
			src.Read == nil || *src.Read != (c1.Read{Transport: c1.Telnet, Operation: op}) || src.Span == nil {
			t.Errorf("%s: %+v %+v", name, o, src.Read)
			continue
		}
		var want adapter.Observation
		for _, ro := range res.Observations {
			if ro.Name == name {
				want = ro
			}
		}
		if o.Value != want.Value || src.Span.Offset != want.Span.Offset || src.Span.Length != want.Span.Length ||
			src.ObservedAt != res.Transcript.ReceivedAt(want.Span) {
			t.Errorf("%s: %+v, want %+v", name, o, want)
		}
	}
	if m := attr(t, out, c1.AttrModel); m.Value != "SEL-751" || m.Confidence != c1.SingleSource {
		t.Errorf("model %+v", m)
	}
	// Two classes agree on the serial number: corroborated.
	if s := attr(t, out, c1.AttrSerialNumber); s.Confidence != c1.Corroborated || len(s.Observations) != 2 {
		t.Errorf("serial_number %+v", s)
	}
	// The same read again changes nothing.
	again, changes, err := Apply(out, res, ep)
	if err != nil || len(changes) != 0 || !reflect.DeepEqual(again, out) {
		t.Errorf("second apply: %v, changes %+v", err, changes)
	}
}

// A device value that differs from the record's replaces the session
// observation, and never an operator-declared value.
func TestApplyDifferentValues(t *testing.T) {
	rec := record(t, "sel-751-simulated.json")
	for i := range rec.Attributes {
		switch rec.Attributes[i].Name {
		case "sel.cid":
			rec.Attributes[i].Value = "E000"
			rec.Attributes[i].Observations[0].Value = "E000"
		case c1.AttrSerialNumber:
			rec.Attributes[i].Value = "DECLARED0000001"
			rec.Attributes[i].Observations[0].Value = "DECLARED0000001"
		}
	}
	if err := rec.Validate(); err != nil {
		t.Fatal(err)
	}
	out, changes, err := Apply(rec, result(t, "ok"), ep)
	if err != nil {
		t.Fatal(err)
	}
	if cid := attr(t, out, "sel.cid"); cid.Value != "E754" || len(cid.Observations) != 1 || cid.Observations[0].Value != "E754" {
		t.Errorf("sel.cid %+v", cid)
	}
	s := attr(t, out, c1.AttrSerialNumber)
	if s.Value != "DECLARED0000001" || s.Confidence != c1.Conflicting {
		t.Errorf("a device claim overwrote the declared serial: %+v", s)
	}
	for _, c := range changes {
		if c.Name == "sel.cid" && (c.Old != "E000" || c.New != "E754") {
			t.Errorf("change %+v", c)
		}
		if c.Name == c1.AttrSerialNumber && c.New != "DECLARED0000001" {
			t.Errorf("change %+v", c)
		}
	}
}

func TestApplyRefuses(t *testing.T) {
	rec, ok := record(t, "sel-751-simulated.json"), result(t, "ok")
	for name, c := range map[string]struct {
		rec  func(a *c1.Asset)
		res  func(r *adapter.Result)
		ep   string
		want string
	}{
		"an unknown endpoint": {ep: "port2", want: `no endpoint "port2"`},
		"a target that is not the endpoint's": {rec: func(a *c1.Asset) {
			a.Endpoints[0].Target = c1.DeviceObserved
		}, want: "is not endpoint port1-telnet's target"},
		"an operator-only attribute": {res: func(r *adapter.Result) {
			r.Observations = append(r.Observations, r.Observations[len(r.Observations)-1])
			r.Observations[len(r.Observations)-1].Name = c1.AttrVendor
		}, want: "does not report vendor"},
		"a later minor record": {rec: func(a *c1.Asset) { a.Schema = "otsec.asset/0.4" }, want: "is not one this module writes"},
		"another contract":     {rec: func(a *c1.Asset) { a.Schema = "otsec.adapter/0.3" }, want: "is not one this module writes"},
		"an invalid result":    {res: func(r *adapter.Result) { r.Transcript.SHA256 = strings.Repeat("0", 64) }, want: "sha256"},
		"an snmpv3 endpoint, with no read path in a 0.6 result": {rec: func(a *c1.Asset) {
			a.Endpoints[0].Transport = c1.SNMPv3
		}, want: "has no read path"},
	} {
		r, res, e := rec, ok, ep
		r.Endpoints = slices.Clone(rec.Endpoints)
		res.Observations = slices.Clone(ok.Observations)
		if c.rec != nil {
			c.rec(&r)
		}
		if c.res != nil {
			c.res(&res)
		}
		if c.ep != "" {
			e = c.ep
		}
		out, changes, err := Apply(r, res, e)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v", name, err)
		}
		if changes != nil || !reflect.DeepEqual(out, r) {
			t.Errorf("%s: the record changed on a refusal", name)
		}
	}
}

// A result that did not collect, or whose identity did not match, is not
// applied.
func TestApplyNotApplied(t *testing.T) {
	rec := record(t, "sel-751-simulated.json")
	for _, n := range []string{"refused.identity_mismatch", "failed.timeout", "failed.identity_mismatch", "refused.firmware_not_allowlisted"} {
		out, changes, err := Apply(rec, result(t, n), ep)
		if !errors.Is(err, ErrNotApplied) || changes != nil || !reflect.DeepEqual(out, rec) {
			t.Errorf("%s: %v, %+v", n, err, changes)
		}
	}
}

// A 0.2 record is written as 0.3. Its session reads have no read path, so
// the result's reads of the same attributes replace them, and the change
// shows.
func TestApplyUpgrades(t *testing.T) {
	rec := record(t, "sel-751-at-0.2.json")
	out, changes, err := Apply(rec, result(t, "ok"), ep)
	if err != nil {
		t.Fatal(err)
	}
	if out.Schema != c1.Contract {
		t.Fatalf("schema %s", out.Schema)
	}
	if got := names(changes); got != "firmware_id,firmware_version,model,sel.cid,serial_number" {
		t.Errorf("changes %s", got)
	}
	for _, at := range out.Attributes {
		for _, o := range at.Observations {
			if o.Source.Kind != o.EffectiveKind() || o.Source.Kind == "" {
				t.Errorf("%s: kind %q", at.Name, o.Source.Kind)
			}
		}
	}
	if d := attr(t, out, c1.AttrDeviceClass).Observations[0].Source.Kind; d != c1.Operator {
		t.Errorf("an operator entry reads as %s", d)
	}
	// A session read the result does not repeat cannot be kept without a
	// read path, and an attribute left with nothing is refused.
	res := result(t, "ok")
	res.Observations = slices.DeleteFunc(slices.Clone(res.Observations), func(o adapter.Observation) bool { return o.Name == "sel.cid" })
	if _, _, err := Apply(rec, res, ep); err == nil || !strings.Contains(err.Error(), "invalid") {
		t.Errorf("0.2 session read not repeated: %v", err)
	}
}

func TestFamilyConflict(t *testing.T) {
	out, _, err := Apply(record(t, "sel-751-simulated.json"), result(t, "ok"), ep)
	if err != nil {
		t.Fatal(err)
	}
	if m, bad := FamilyConflict(out, []string{"SEL-751"}); bad {
		t.Errorf("SEL-751 in its own family: %s", m)
	}
	if m, bad := FamilyConflict(out, []string{"SEL-2731M", "SEL-2741M"}); !bad || m != "SEL-751" {
		t.Errorf("SEL-751 in the switch family: %q %v", m, bad)
	}
	// No device-read model, no conflict: a declared model is not a read.
	rec := record(t, "sel-751-simulated.json")
	if _, bad := FamilyConflict(rec, nil); bad {
		t.Error("conflict with no model")
	}
	rec.Attributes = append(rec.Attributes, c1.Attribute{Name: c1.AttrModel, Value: "SEL-9999", Confidence: c1.SingleSource,
		Observations: []c1.Observation{{Value: "SEL-9999", EvidenceClass: c1.OperatorDeclared,
			Source: c1.Source{Method: c1.OperatorEntry, Ref: "admin:lab-admin", ObservedAt: "2026-11-05T09:00:00Z", Kind: c1.Operator}}}})
	if _, bad := FamilyConflict(rec, []string{"SEL-751"}); bad {
		t.Error("a declared model raised a conflict")
	}
}

// The module writes the minor contracts/asset defines.
func TestSelfMinor(t *testing.T) {
	if c1.Contract != "otsec.asset/0.3" || selfMinor != 3 {
		t.Fatalf("contracts/asset is %s; move selfMinor and the upgrade with it", c1.Contract)
	}
}
