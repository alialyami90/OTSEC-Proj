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

// An SNMP result's reads are copied as they are: the operation, and the OID
// or the header (C2 0.7). Nothing is inferred.
func TestApplySNMP(t *testing.T) {
	rec := record(t, "sel-2731m-snmpv3.json")
	// The two binding attributes keep only their declared value, so the
	// result's reads of them are the ones the record holds afterwards.
	for i, at := range rec.Attributes {
		if at.Name == c1.AttrSNMPEngineID || at.Name == c1.AttrFirmwareID {
			rec.Attributes[i].Observations = slices.DeleteFunc(slices.Clone(at.Observations), func(o c1.Observation) bool {
				return o.Source.Method == c1.SimulatorRun
			})
		}
	}
	b, err := os.ReadFile(filepath.Join("..", "..", "contracts", "adapter", "testdata", "snmp", "results", "valid", "ok.json"))
	if err != nil {
		t.Fatal(err)
	}
	res, err := adapter.DecodeResult(b)
	if err != nil {
		t.Fatal(err)
	}
	out, changes, err := Apply(rec, res, "mgmt-snmpv3")
	if err != nil {
		t.Fatal(err)
	}
	if got := names(changes); got != "firmware_id,hostname,snmp_engine_id" {
		t.Errorf("changes %s", got)
	}
	want := map[string]c1.Read{
		c1.AttrSNMPEngineID: {Transport: c1.SNMPv3, Operation: "sel27x1.snmp.system", Header: c1.HeaderEngineID},
		c1.AttrHostname:     {Transport: c1.SNMPv3, Operation: "sel27x1.snmp.system", OID: "1.3.6.1.2.1.1.5.0"},
		c1.AttrFirmwareID:   {Transport: c1.SNMPv3, Operation: "sel27x1.snmp.entity", OID: "1.3.6.1.2.1.47.1.1.1.1.10.1"},
		c1.AttrModel:        {Transport: c1.SNMPv3, Operation: "sel27x1.snmp.entity", OID: "1.3.6.1.2.1.47.1.1.1.1.10.1"},
	}
	for name, w := range want {
		at := attr(t, out, name)
		i := slices.IndexFunc(at.Observations, func(o c1.Observation) bool { return o.Source.Method == c1.SimulatorRun })
		if i < 0 || at.Observations[i].Source.Read == nil || *at.Observations[i].Source.Read != w {
			t.Errorf("%s: %+v", name, at.Observations)
		}
	}
	if at := attr(t, out, c1.AttrHostname); at.Value != "sw-bay-1" {
		t.Errorf("hostname %q", at.Value)
	}
	if _, _, err := Apply(record(t, "sel-751-simulated.json"), res, ep); err == nil ||
		!strings.Contains(err.Error(), "endpoint port1-telnet is telnet, and the result is not a session of that transport") {
		t.Errorf("an SNMP result on a Telnet endpoint: %v", err)
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
		"a line result on an snmpv3 endpoint": {rec: func(a *c1.Asset) {
			a.Endpoints[0].Transport = c1.SNMPv3
		}, want: "endpoint port1-telnet is snmpv3, and the result is not a session of that transport"},
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
	if m, bad := FamilyConflict(out, Models("sel-2731")); !bad || m != "SEL-751" {
		t.Errorf("SEL-751 in the switch family: %q %v", m, bad)
	}
	// No device-read model, no conflict: a declared model is not a read.
	rec := record(t, "sel-751-simulated.json")
	if _, bad := FamilyConflict(rec, nil); bad {
		t.Error("conflict with no model")
	}
	// No list, no check (C5 on #453).
	if m, bad := FamilyConflict(out, nil); bad {
		t.Errorf("conflict with no list: %s", m)
	}
	if m, bad := FamilyConflict(out, Models("sel-rtac")); bad {
		t.Errorf("conflict for an unlisted family: %s", m)
	}
	rec.Attributes = append(rec.Attributes, c1.Attribute{Name: c1.AttrModel, Value: "SEL-9999", Confidence: c1.SingleSource,
		Observations: []c1.Observation{{Value: "SEL-9999", EvidenceClass: c1.OperatorDeclared,
			Source: c1.Source{Method: c1.OperatorEntry, Ref: "admin:lab-admin", ObservedAt: "2026-11-05T09:00:00Z", Kind: c1.Operator}}}})
	if _, bad := FamilyConflict(rec, []string{"SEL-751"}); bad {
		t.Error("a declared model raised a conflict")
	}
}

// The module writes the minor contracts/asset defines.
// Upgrade refuses at load what Apply could not write as 0.3: a record of a
// later minor, and an attribute whose only observation was a 0.2 session
// read.
func TestUpgrade(t *testing.T) {
	for _, n := range []string{"sel-751-model-and-firmware.json", "sel-751-simulated.json", "sel-2731m-snmpv3.json"} {
		rec := record(t, n)
		if out, err := Upgrade(rec); err != nil || !reflect.DeepEqual(out, rec) {
			t.Errorf("%s: %v", n, err)
		}
	}
	rec := record(t, "sel-751-at-0.2.json")
	if out, err := Upgrade(rec); err == nil || !strings.Contains(err.Error(), "sel.cid") || !reflect.DeepEqual(out, rec) {
		t.Errorf("0.2 with a session read only: %v", err)
	}
	// Without sel.cid, firmware_id keeps only its operator entry, so it can
	// no longer be corroborated.
	rec.Attributes = slices.DeleteFunc(rec.Attributes, func(at c1.Attribute) bool { return at.Name == "sel.cid" })
	if _, err := Upgrade(rec); err == nil || !strings.Contains(err.Error(), "corroborated") {
		t.Errorf("0.2 with a corroboration lost: %v", err)
	}
	i := slices.IndexFunc(rec.Attributes, func(at c1.Attribute) bool { return at.Name == c1.AttrFirmwareID })
	rec.Attributes[i].Confidence = c1.SingleSource
	if out, err := Upgrade(rec); err != nil || out.Schema != c1.Contract || len(attr(t, out, c1.AttrFirmwareID).Observations) != 1 {
		t.Errorf("0.2 with an operator entry left: %v", err)
	}
	if _, err := Upgrade(record(t, "later-minor.json")); err == nil {
		t.Error("a 0.4 record written as 0.3")
	}
}

// The family lists are the ones §1.5 of the approved contract note gives.
// No capability profile document carries models yet; when one does, it
// should be compared here too.
func TestModels(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "docs", "phase4", "C2-c1-0.3-c3-0.4.md"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "covers (`SEL-751`; `SEL-2731M` and `SEL-2741M`)") {
		t.Fatal("§1.5's family lists changed; update familyModels and this test")
	}
	if got := Models("sel-751"); !slices.Equal(got, []string{"SEL-751"}) {
		t.Errorf("sel-751: %v", got)
	}
	// One RSTP-mode model per product: §1.5's SEL-2731M and SEL-2741M.
	if got := append(Models("sel-2731"), Models("sel-2741")...); !slices.Equal(got, []string{"SEL-2731M", "SEL-2741M"}) {
		t.Errorf("sel-2731 and sel-2741: %v", got)
	}
	if got := Models("sel-27x1"); got != nil {
		t.Errorf("the profile family is not a product: %v", got)
	}
	if got := Models("sel-rtac"); got != nil {
		t.Errorf("sel-rtac: %v", got)
	}
	// Each declared family in the contract examples has its list.
	for _, n := range []string{"sel-751-simulated.json", "sel-2731m-snmpv3.json"} {
		if f := attr(t, record(t, n), c1.AttrProductFamily).Value; Models(f) == nil {
			t.Errorf("%s: no models for %s", n, f)
		}
	}
	m := Models("sel-751")
	m[0] = "x"
	if Models("sel-751")[0] != "SEL-751" {
		t.Error("the list is shared")
	}
}

func TestSelfMinor(t *testing.T) {
	if c1.Contract != "otsec.asset/0.3" || selfMinor != 3 {
		t.Fatalf("contracts/asset is %s; move selfMinor and the upgrade with it", c1.Contract)
	}
}
