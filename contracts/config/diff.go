package config

import (
	"errors"
	"fmt"
	"slices"
	"sort"

	"otsec.local/otsec/contracts/asset"
)

// Difference is the semantic difference between two snapshots of one asset
// under one rule. It compares settings by name, so the column a setting is
// printed at, how a value wraps, a header or the order of settings never
// shows. An empty Changes means the configuration did not change.
type Difference struct {
	Schema  string `json:"schema"`
	Kind    string `json:"kind"` // KindDifference
	AssetID string `json:"asset_id"`
	Rule    string `json:"rule"`
	// Target is both snapshots' target. Snapshots of different targets are
	// not compared.
	Target asset.EvidenceClass `json:"target"`
	From   Ref                 `json:"from"`
	To     Ref                 `json:"to"`
	// Changes are in the rule's class order. Within a class, a section
	// change comes first, then setting changes by name in byte order.
	Changes []Change `json:"changes"`
}

// Ref names a snapshot by its digest (Digest over its stored bytes) and the
// invocation that read it.
type Ref struct {
	SnapshotDigest string `json:"snapshot_digest"`
	InvocationID   string `json:"invocation_id"`
	RetrievedAt    string `json:"retrieved_at"`
}

// Change is one difference.
type Change struct {
	Class string     `json:"class"`
	Kind  ChangeKind `json:"kind"`
	// Name is the setting's name; it is empty for a section change.
	Name string `json:"name,omitempty"`
	// From and To are the values as printed: From is absent for an added
	// setting, To for a removed one, and both for a section change.
	From *string `json:"from,omitempty"`
	To   *string `json:"to,omitempty"`
	// Sensitive is the rule's mark for the class: mask From and To when
	// displaying them.
	Sensitive bool `json:"sensitive"`
}

// ChangeKind is closed.
type ChangeKind string

const (
	Changed ChangeKind = "changed" // in both, with different values
	Added   ChangeKind = "added"   // only in To
	Removed ChangeKind = "removed" // only in From
	// SectionAppeared: the class was absent in From and present in To.
	// Its settings are listed as added too.
	SectionAppeared ChangeKind = "section-appeared"
	// SectionDisappeared: present in From and absent in To. Its settings
	// are listed as removed too.
	SectionDisappeared ChangeKind = "section-disappeared"
)

// ChangeKinds lists every kind.
var ChangeKinds = []ChangeKind{Changed, Added, Removed, SectionAppeared, SectionDisappeared}

// ErrNotComparable is returned for two snapshots that do not describe the
// same thing: another asset, rule or target. It is never an empty Difference.
var ErrNotComparable = errors.New("config: snapshots are not comparable")

// Compare decodes two stored snapshots, from and to, and returns their
// Difference. It takes the stored bytes, not the decoded snapshots, so that
// the digests it records are always over the bytes as stored.
func Compare(from, to []byte) (Difference, error) {
	a, err := DecodeSnapshot(from)
	if err != nil {
		return Difference{}, fmt.Errorf("from: %w", err)
	}
	b, err := DecodeSnapshot(to)
	if err != nil {
		return Difference{}, fmt.Errorf("to: %w", err)
	}
	if a.AssetID != b.AssetID || a.Rule != b.Rule || a.Target != b.Target {
		return Difference{}, fmt.Errorf("%w: asset %s and %s, rule %s and %s, target %s and %s", ErrNotComparable,
			a.AssetID, b.AssetID, a.Rule, b.Rule, a.Target, b.Target)
	}
	d := Difference{
		Schema: Contract, Kind: KindDifference, AssetID: a.AssetID, Rule: a.Rule, Target: a.Target,
		From:    Ref{SnapshotDigest: Digest(from), InvocationID: a.InvocationID, RetrievedAt: a.RetrievedAt},
		To:      Ref{SnapshotDigest: Digest(to), InvocationID: b.InvocationID, RetrievedAt: b.RetrievedAt},
		Changes: []Change{},
	}
	for i, cl := range Rules[a.Rule].Classes {
		x, y := a.Sections[i], b.Sections[i]
		switch {
		case x.State == Absent && y.State == Present:
			d.Changes = append(d.Changes, Change{Class: cl.ID, Kind: SectionAppeared, Sensitive: cl.Sensitive})
		case x.State == Present && y.State == Absent:
			d.Changes = append(d.Changes, Change{Class: cl.ID, Kind: SectionDisappeared, Sensitive: cl.Sensitive})
		}
		old, cur := values(x), values(y)
		var names []string
		for n := range old {
			names = append(names, n)
		}
		for n := range cur {
			if _, ok := old[n]; !ok {
				names = append(names, n)
			}
		}
		sort.Strings(names)
		for _, n := range names {
			ov, inOld := old[n]
			nv, inCur := cur[n]
			ch := Change{Class: cl.ID, Name: n, Sensitive: cl.Sensitive}
			switch {
			case inOld && inCur && ov == nv:
				continue
			case inOld && inCur:
				ch.Kind, ch.From, ch.To = Changed, &ov, &nv
			case inCur:
				ch.Kind, ch.To = Added, &nv
			default:
				ch.Kind, ch.From = Removed, &ov
			}
			d.Changes = append(d.Changes, ch)
		}
	}
	return d, d.Validate()
}

func values(s Section) map[string]string {
	m := make(map[string]string, len(s.Settings))
	for _, st := range s.Settings {
		m[st.Name] = st.Value
	}
	return m
}

// DecodeDifference parses and validates a difference, with DecodeSnapshot's
// decoding rules.
func DecodeDifference(b []byte) (Difference, error) {
	var d Difference
	if err := decode(b, &d); err != nil {
		return Difference{}, fmt.Errorf("config: difference: %w", err)
	}
	return d, d.Validate()
}

// SameChanges reports whether o is the same change as d: the same asset, rule
// and target, measured from the same baseline snapshot, with equal Changes.
// The two may differ in the snapshot they end at, its invocation and its
// time. So a configuration that stays changed read after read compares as
// one change, not a new one each time. Changes are in the rule's order, so
// equal slices are the same set. Two empty differences are the same
// (nothing changed in either), which callers that mean "a change" must rule
// out first.
func (d Difference) SameChanges(o Difference) bool {
	return d.AssetID == o.AssetID && d.Rule == o.Rule && d.Target == o.Target &&
		d.From.SnapshotDigest == o.From.SnapshotDigest && slices.EqualFunc(d.Changes, o.Changes, func(a, b Change) bool {
		return a.Class == b.Class && a.Kind == b.Kind && a.Name == b.Name && a.Sensitive == b.Sensitive &&
			equalValue(a.From, b.From) && equalValue(a.To, b.To)
	})
}

func equalValue(a, b *string) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

// Validate checks every rule that can be checked from the difference alone.
func (d Difference) Validate() error {
	c := &check{}
	c.header(d.Schema, d.Kind, KindDifference, d.AssetID)
	if d.Target != asset.DeviceObserved && d.Target != asset.Simulated {
		c.fail("target must be %q or %q", asset.DeviceObserved, asset.Simulated)
	}
	for _, r := range []struct {
		p string
		r Ref
	}{{"from", d.From}, {"to", d.To}} {
		if !digestPattern.MatchString(r.r.SnapshotDigest) || !uuidPattern.MatchString(r.r.InvocationID) || !asset.ValidTime(r.r.RetrievedAt) {
			c.fail("%s needs a snapshot_digest \"sha256:<hex>\", an invocation_id and a retrieved_at", r.p)
		}
	}
	rule, ok := c.rule(d.Rule)
	if !ok {
		return c.err("difference")
	}
	if d.Changes == nil {
		c.fail("changes is required; an empty list means no change")
	}
	prev := [3]int{-1, -1, 0}
	prevName := ""
	for i, ch := range d.Changes {
		p := fmt.Sprintf("changes[%d]", i)
		cl, at, ok := rule.class(ch.Class)
		if !ok {
			c.fail("%s: class %q is not a class of rule %s", p, ch.Class, rule.ID)
			continue
		}
		if ch.Sensitive != cl.Sensitive {
			c.fail("%s: sensitive is %v for %s", p, cl.Sensitive, cl.ID)
		}
		section := ch.Kind == SectionAppeared || ch.Kind == SectionDisappeared
		switch {
		case section:
			if ch.Name != "" || ch.From != nil || ch.To != nil {
				c.fail("%s: a section change has no name and no values", p)
			}
			if !cl.MayBeAbsent {
				c.fail("%s: %s cannot be absent under rule %s, so it cannot appear or disappear", p, cl.ID, rule.ID)
			}
		case ch.Kind == Changed || ch.Kind == Added || ch.Kind == Removed:
			if !settingName.MatchString(ch.Name) {
				c.fail("%s: name %q is not a setting name", p, ch.Name)
			}
			if (ch.From != nil) != (ch.Kind != Added) || (ch.To != nil) != (ch.Kind != Removed) {
				c.fail("%s: %s carries %s", p, ch.Kind, map[ChangeKind]string{Changed: "from and to", Added: "to only", Removed: "from only"}[ch.Kind])
			}
			for _, v := range []*string{ch.From, ch.To} {
				if v != nil && !valueText.MatchString(*v) {
					c.fail("%s: a value must be printable ASCII with no space at either end", p)
				}
			}
			if ch.Kind == Changed && ch.From != nil && ch.To != nil && *ch.From == *ch.To {
				c.fail("%s: changed with equal values", p)
			}
		default:
			c.fail("%s.kind %q is not a change kind", p, ch.Kind)
			continue
		}
		key := [3]int{at, 1, 0}
		if section {
			key[1] = 0
		}
		if key[0] < prev[0] || (key[0] == prev[0] && (key[1] < prev[1] || (key[1] == 1 && prev[1] == 1 && ch.Name <= prevName))) ||
			(key == prev && key[1] == 0) {
			c.fail("%s: changes are in class order, a section change first, then names in byte order, each once", p)
		}
		prev, prevName = key, ch.Name
	}
	return c.err("difference")
}
