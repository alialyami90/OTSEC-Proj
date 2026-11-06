// Package asset is the node-side asset module (R1.8, P4-3-C2). It turns the
// identity observations of one collector result into C1 0.3 attributes and
// says which attributes changed (docs/phase4/C2-c1-0.3-c3-0.4.md §3).
//
// It is a pure function over a record and a result. It opens no socket and
// imports no network, syscall or os/exec package and no modules/ied package
// (AP-28, D4-50; imports_test.go). It is not the SNMP client, it does not
// schedule, and it does not match. The node calls it only while its asset
// switch is on (C5).
//
// The rules it applies:
//
//   - Only a result that collected (ok or partial) with a matching identity
//     is applied. Anything else changes nothing: an identity mismatch is
//     the collector's suspension, not a new identity.
//   - Each result observation becomes an adapter-session observation for a
//     device endpoint, or a simulator-session one for a simulator, from the
//     endpoint's target and never from what the far end says. Its kind is
//     device-read, its ref is the invocation ID, its span is the
//     observation's span, and its read path names the endpoint's transport
//     and the operation that read the bytes.
//   - The first read is kept (§1.2). A new observation with the same value,
//     evidence class and method as the one the record holds leaves the
//     record as it is, so an observation's ref stays the run that first
//     carried the value. A different value replaces it and is a change.
//   - A device claim never overwrites an operator-declared value: such an
//     attribute keeps the declared value, and disagreement makes it
//     conflicting (C1's confidence rules). With no declared value the
//     attribute takes the device's.
//   - Attributes the device cannot report about itself
//     (asset.OperatorOnlyAttributes) are refused, and so is a result whose
//     record would fail C1's Validate.
package asset

import (
	"errors"
	"fmt"
	"slices"

	"otsec.local/otsec/contracts/adapter"
	c1 "otsec.local/otsec/contracts/asset"
	"otsec.local/otsec/contracts/version"
)

// selfMinor is the C1 minor this module writes.
const selfMinor = 3

// ErrNotApplied is wrapped by the error Apply returns for a result that
// carries no identity to apply: it did not collect, or its identity did not
// match. The record is returned unchanged.
var ErrNotApplied = errors.New("asset: result not applied")

// Change is one attribute whose value or source changed. Old is "" for an
// attribute the record did not have.
type Change struct {
	Name string
	Old  string
	New  string
}

// Apply merges the identity observations of res, read on the record's
// endpoint endpointID, into rec, and returns the new record and its changes.
// A record below 0.3 is written as 0.3; see upgrade.
func Apply(rec c1.Asset, res adapter.Result, endpointID string) (c1.Asset, []Change, error) {
	if err := res.Validate(); err != nil {
		return rec, nil, fmt.Errorf("asset: %w", err)
	}
	if (res.Status != adapter.StatusOK && res.Status != adapter.StatusPartial) || res.Identity.Result != adapter.IdentityMatch {
		return rec, nil, fmt.Errorf("%w: status %s, identity %s", ErrNotApplied, res.Status, res.Identity.Result)
	}
	i := slices.IndexFunc(rec.Endpoints, func(ep c1.Endpoint) bool { return ep.ID == endpointID })
	if i < 0 {
		return rec, nil, fmt.Errorf("asset: the record has no endpoint %q", endpointID)
	}
	ep := rec.Endpoints[i]
	method, ok := map[c1.EvidenceClass]c1.SourceMethod{c1.DeviceObserved: c1.AdapterSession, c1.Simulated: c1.SimulatorRun}[res.Target]
	if !ok || ep.Target != res.Target {
		return rec, nil, fmt.Errorf("asset: result target %q is not endpoint %s's target %q", res.Target, ep.ID, ep.Target)
	}
	out, err := upgrade(rec)
	if err != nil {
		return rec, nil, err
	}
	var changes []Change
	for _, o := range res.Observations {
		if slices.Contains(c1.OperatorOnlyAttributes, o.Name) {
			return rec, nil, fmt.Errorf("asset: a device does not report %s about itself", o.Name)
		}
		read, err := readOf(res, ep, o)
		if err != nil {
			return rec, nil, err
		}
		sp := c1.Span{Offset: o.Span.Offset, Length: o.Span.Length}
		at := res.Transcript.ReceivedAt(o.Span)
		if at == "" {
			at = res.EndedAt
		}
		ob := c1.Observation{Value: o.Value, EvidenceClass: res.Target, Source: c1.Source{
			Method: method, Ref: res.InvocationID, Span: &sp, ObservedAt: at, Kind: c1.DeviceRead,
			Read: read,
		}}
		if c, ok := merge(&out, o.Name, ob); ok {
			changes = append(changes, c)
		}
	}
	if err := out.Validate(); err != nil {
		return rec, nil, fmt.Errorf("asset: the merged record is invalid: %w", err)
	}
	return out, changes, nil
}

// merge puts ob into the attribute name, adding the attribute if the record
// lacks it, and reports the change, if any.
func merge(a *c1.Asset, name string, ob c1.Observation) (Change, bool) {
	i := slices.IndexFunc(a.Attributes, func(at c1.Attribute) bool { return at.Name == name })
	if i < 0 {
		a.Attributes = append(a.Attributes, c1.Attribute{Name: name, Value: ob.Value,
			Confidence: c1.SingleSource, Observations: []c1.Observation{ob}})
		return Change{Name: name, New: ob.Value}, true
	}
	at := &a.Attributes[i]
	old := at.Value
	j := slices.IndexFunc(at.Observations, func(o c1.Observation) bool {
		return o.EvidenceClass == ob.EvidenceClass && o.Source.Method == ob.Source.Method
	})
	switch {
	case j >= 0 && at.Observations[j].Value == ob.Value:
		return Change{}, false // the first read stays
	case j >= 0:
		at.Observations[j] = ob
	default:
		at.Observations = append(at.Observations, ob)
	}
	if !slices.ContainsFunc(at.Observations, func(o c1.Observation) bool { return o.EvidenceClass == c1.OperatorDeclared }) {
		at.Value = ob.Value
	}
	at.Confidence = c1.DeriveConfidence(at.Value, at.Observations)
	return Change{Name: name, Old: old, New: at.Value}, true
}

// readOf is C1's read path for an observation: the endpoint's transport and
// the result's read (C2 0.7), copied, never parsed from the transcript. The
// caller has checked the read against the register (CheckLines or
// CheckSNMP). A C2 0.6 result has no read, so for the SEL-751's own reads
// the operation is inferred: the serial number comes from the SER header,
// read by the invoked operation, and every other attribute from the ID
// reply (sel.id). No other inference is made: an SNMPv3 observation needs
// its OID or header, which a 0.6 result cannot carry, and is refused.
func readOf(res adapter.Result, ep c1.Endpoint, o adapter.Observation) (*c1.Read, error) {
	if (ep.Transport == c1.SNMPv3) != (res.Session.SNMP != nil) {
		return nil, fmt.Errorf("asset: endpoint %s is %s, and the result is not a session of that transport", ep.ID, ep.Transport)
	}
	if r := o.Read; r != nil {
		return &c1.Read{Transport: ep.Transport, Operation: r.Operation, OID: r.OID, Header: r.Header}, nil
	}
	if ep.Transport == c1.SNMPv3 {
		return nil, fmt.Errorf("asset: %s from an snmpv3 result has no read path in %s", o.Name, res.Schema)
	}
	if o.Name == c1.AttrSerialNumber {
		return &c1.Read{Transport: ep.Transport, Operation: res.OperationID}, nil
	}
	return &c1.Read{Transport: ep.Transport, Operation: "sel.id"}, nil
}

// upgrade writes a record as 0.3. Every observation takes the kind its
// method gives it (Observation.EffectiveKind). A session read in a 0.2
// record has no read path, and none is guessed: it is removed, and the
// result's read of the same attribute, which carries one, takes its place.
// An attribute the result does not read again is then left without that
// observation; if it has none left, Validate refuses the record, and its
// operator rewrites it at 0.3. A record of a later minor is refused, so
// nothing this reader does not know is dropped by writing it as 0.3.
func upgrade(rec c1.Asset) (c1.Asset, error) {
	id, err := version.Parse(rec.Schema)
	if err != nil || id.Name != "asset" || id.Major != 0 || id.Minor > selfMinor {
		return rec, fmt.Errorf("asset: record schema %q is not one this module writes (%s or earlier)", rec.Schema, c1.Contract)
	}
	out := rec
	out.Attributes = make([]c1.Attribute, len(rec.Attributes))
	for i, at := range rec.Attributes {
		var kept []c1.Observation
		for _, o := range at.Observations {
			if o.Source.Kind == "" {
				o.Source.Kind = o.EffectiveKind()
			}
			if o.Source.Read == nil && o.Source.Kind == c1.DeviceRead &&
				(o.Source.Method == c1.AdapterSession || o.Source.Method == c1.SimulatorRun) {
				continue
			}
			kept = append(kept, o)
		}
		at.Observations = kept
		out.Attributes[i] = at
	}
	out.Endpoints = slices.Clone(rec.Endpoints)
	out.Schema = c1.Contract
	return out, nil
}

// Upgrade writes a record as 0.3, as Apply does before it merges a result
// (see upgrade), and checks the outcome with C1's Validate. The node calls
// it on each declared record at configuration load (C5 on #445), so a
// record that cannot be written as 0.3 is refused there and not at every
// run. It is stricter than Apply: a 0.2 session read with no read path is
// dropped here, and an attribute left with nothing fails, even if a later
// result would have read that attribute again.
func Upgrade(rec c1.Asset) (c1.Asset, error) {
	out, err := upgrade(rec)
	if err != nil {
		return rec, err
	}
	if err := out.Validate(); err != nil {
		return rec, fmt.Errorf("asset: the record written as %s is invalid: %w", c1.Contract, err)
	}
	return out, nil
}

// Models gives, for a declared product_family, the models that product
// covers, each as the device prints it (§1.5 of
// docs/phase4/C2-c1-0.3-c3-0.4.md). The node holds only an asset's profile
// reference, not the profile documents, so the lists are carried here for
// FamilyConflict (C5 on #445). product_family names one product, not the
// profile's family: sel-2731 and sel-2741 each list their RSTP-mode model,
// so an OT SDN (S) or unmanaged (U) model is a conflict (D4-51, D4-54). A
// family not listed has no list, and no family check is made.
func Models(productFamily string) []string {
	return slices.Clone(familyModels[productFamily])
}

var familyModels = map[string][]string{
	"sel-751":  {"SEL-751"},
	"sel-2731": {"SEL-2731M"},
	"sel-2741": {"SEL-2741M"},
}

// FamilyConflict reports whether the record's device-read model is outside
// the models its declared product family covers (§1.5): models is the list
// the family's capability profile gives. A conflict is shown in health as
// identity.family_conflict and settled by an administrator; it is never a
// match input. A record with no device-read model has no conflict, and
// neither has one checked against no list (no family check is made).
func FamilyConflict(rec c1.Asset, models []string) (model string, conflict bool) {
	at, ok := rec.Attribute(c1.AttrModel)
	if !ok || len(models) == 0 {
		return "", false
	}
	for _, o := range at.Observations {
		if o.EffectiveKind() == c1.DeviceRead && !slices.Contains(models, o.Value) {
			return o.Value, true
		}
	}
	return "", false
}
