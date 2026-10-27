package config

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"

	"otsec.local/otsec/contracts/adapter"
	"otsec.local/otsec/contracts/register"
)

// FromResult writes the snapshot of a configuration read from the C2 result
// of the run that made it (C2 0.6). It is the one way a snapshot is made, so
// the node and the tests build it alike.
//
// The result must be ok, of the invocation, and hold one configuration
// record for each step of the run, in the run's order (adapter.CheckLines
// holds the result to that). The steps' lines must be exactly the rule's
// classes. Sections follow the rule's order, which is not the run's: the run
// sends the gate reads first (C3 0.3). A record's fields are the settings the
// adapter's own parser read, copied as they are; CheckAgainst makes them
// agree with the contract's tokenizer, so FromResult does not tokenize.
//
// The snapshot is validated. It is not checked against the transcript: the
// node runs CheckAgainst on it before storing it, as it runs CheckLines on
// the result.
func FromResult(ruleID string, m *register.Matcher, inv adapter.Invocation, r adapter.Result) (Snapshot, error) {
	rule, ok := Rules[ruleID]
	if !ok {
		return Snapshot{}, fmt.Errorf("config: rule %q is not a rule of %s", ruleID, Contract)
	}
	if r.Status != adapter.StatusOK {
		return Snapshot{}, fmt.Errorf("config: a snapshot is written from an ok result, not %s", r.Status)
	}
	if r.InvocationID != inv.InvocationID || r.OperationID != inv.OperationID {
		return Snapshot{}, fmt.Errorf("config: the result is not of invocation %s (%s)", inv.InvocationID, inv.OperationID)
	}
	lines, err := m.RenderRun(inv.OperationID)
	if err != nil {
		return Snapshot{}, fmt.Errorf("config: %w", err)
	}
	if len(r.Records) != len(lines) {
		return Snapshot{}, fmt.Errorf("config: %d records for the run's %d steps", len(r.Records), len(lines))
	}
	secs := make([]*Section, len(rule.Classes))
	for i, line := range lines {
		k := slices.IndexFunc(rule.Classes, func(c Class) bool { return c.Command == line })
		if k < 0 {
			return Snapshot{}, fmt.Errorf("config: step %d (%q) is not a class of rule %s", i+1, line, rule.ID)
		}
		if secs[k] != nil {
			return Snapshot{}, fmt.Errorf("config: class %s is read twice", rule.Classes[k].ID)
		}
		rec := r.Records[i]
		sec := Section{Command: line, Class: rule.Classes[k].ID, Sensitive: rule.Classes[k].Sensitive, Span: rec.Span}
		if rec.Span.Offset < 0 || rec.Span.Length <= 0 || rec.Span.Offset+rec.Span.Length > int64(len(r.Transcript.Data)) {
			return Snapshot{}, fmt.Errorf("config: step %d: the record's span lies outside the transcript", i+1)
		}
		sum := sha256.Sum256(r.Transcript.Data[rec.Span.Offset : rec.Span.Offset+rec.Span.Length])
		sec.SHA256 = hex.EncodeToString(sum[:])
		switch {
		case !rec.ParseOK:
			return Snapshot{}, fmt.Errorf("config: step %d (%s) did not parse; an unreadable section fails the read", i+1, line)
		case rec.Kind == adapter.RecordConfigAbsent:
			sec.State = Absent
		case rec.Kind == adapter.RecordConfigSection:
			sec.State = Present
			for _, f := range rec.Fields {
				sec.Settings = append(sec.Settings, Setting{Name: f.Name, Value: f.Value})
			}
		default:
			return Snapshot{}, fmt.Errorf("config: step %d: %s is not a configuration record", i+1, rec.Kind)
		}
		secs[k] = &sec
	}
	s := Snapshot{
		Schema: Contract, Kind: KindSnapshot, AssetID: inv.AssetID,
		InvocationID: r.InvocationID, OperationID: r.OperationID, Adapter: r.Adapter,
		RegisterVersion: r.RegisterVersion, Target: r.Target, RetrievedAt: r.EndedAt, Rule: rule.ID,
		Transcript: Evidence{Ref: "sha256:" + r.Transcript.SHA256, SHA256: r.Transcript.SHA256, Length: int64(len(r.Transcript.Data))},
	}
	for k, sec := range secs {
		if sec == nil {
			return Snapshot{}, fmt.Errorf("config: the run does not read class %s (%s)", rule.Classes[k].ID, rule.Classes[k].Command)
		}
		s.Sections = append(s.Sections, *sec)
	}
	return s, s.Validate()
}
