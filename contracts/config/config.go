package config

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"otsec.local/otsec/contracts/adapter"
	"otsec.local/otsec/contracts/asset"
	"otsec.local/otsec/contracts/internal/strictjson"
	"otsec.local/otsec/contracts/version"
)

// Contract is this package's identifier.
const Contract = "otsec.config/0.3"

var self = version.ID{Name: "config", Major: 0, Minor: 3}

// Kinds of document. A document's kind says which of the two it is, so one
// reader can tell them apart.
const (
	KindSnapshot   = "config.snapshot"
	KindDifference = "config.difference"
)

// Snapshot is one configuration read of one asset: every settings class its
// rule lists, as the device printed them. It is written once, from one C2
// result, and never edited.
type Snapshot struct {
	Schema string `json:"schema"`
	Kind   string `json:"kind"` // KindSnapshot
	// AssetID is the C1 asset read.
	AssetID string `json:"asset_id"`
	// InvocationID and OperationID are the C2 invocation that read it.
	InvocationID string             `json:"invocation_id"`
	OperationID  string             `json:"operation_id"`
	Adapter      adapter.AdapterRef `json:"adapter"`
	// RegisterVersion is the C3 register package that permitted every line
	// of the session.
	RegisterVersion uint64 `json:"register_version"`
	// Target is the C2 result's target: device-observed or simulated. It
	// is the evidence class of every setting below.
	Target asset.EvidenceClass `json:"target"`
	// RetrievedAt is the C2 result's ended_at, RFC 3339 UTC.
	RetrievedAt string `json:"retrieved_at"`
	// Rule names the rule that tokenized the replies, e.g. "sel-751-sho/2".
	Rule string `json:"rule"`
	// Transcript is the session's transcript as C5 stores it.
	Transcript Evidence `json:"transcript"`
	// Sections are the rule's classes, all of them, in the rule's order.
	Sections []Section `json:"sections"`
}

// Evidence names a stored capture, as C4 native.evidence does.
type Evidence struct {
	Ref    string `json:"ref"`    // "sha256:" + SHA256, the C5 evidence ref
	SHA256 string `json:"sha256"` // lowercase hex of SHA-256 of the transcript bytes
	Length int64  `json:"length"`
}

// Section is one settings class.
type Section struct {
	// Command is the exact register line that read it, e.g. "SHO P 1".
	Command string `json:"command"`
	// Class is the rule's ID for the class, e.g. "port.1".
	Class string       `json:"class"`
	State SectionState `json:"state"`
	// Sensitive is the rule's mark for the class: mask the values when
	// displaying them.
	Sensitive bool `json:"sensitive"`
	// Span is the reply's message text in the transcript, and SHA256 is the
	// SHA-256 of those bytes. The bytes themselves are only in the transcript.
	Span   adapter.Span `json:"span"`
	SHA256 string       `json:"sha256"`
	// Settings are in printed order. An absent section has none.
	Settings []Setting `json:"settings,omitempty"`
}

// SectionState is closed.
type SectionState string

const (
	// Present: the relay printed the class's settings.
	Present SectionState = "present"
	// Absent: the relay answered with the rule's "not available" reply. It
	// is the relay's statement that the class does not exist on this unit,
	// for example a port or protocol not ordered.
	Absent SectionState = "absent"
)

// SectionStates lists every state.
var SectionStates = []SectionState{Present, Absent}

// Setting is one setting as printed. It carries no span: the section's
// bytes are the evidence, and CheckAgainst re-reads every setting from them
// by the rule, so a span would say nothing the rule does not.
type Setting struct {
	Name string `json:"name"`
	// Value is the value's printed pieces joined by one space. It has one
	// piece unless the relay wrapped it.
	Value string `json:"value"`
}

// Rule is a family's rule: which classes a complete read holds, and how a
// reply is tokenized. The tokenization is stated in doc.go and enforced by
// CheckAgainst.
type Rule struct {
	ID     string
	Family string // the C3 register family
	// NotAvailable is the reply text, without leading and trailing space,
	// that makes a section absent.
	NotAvailable string
	Classes      []Class
}

// Class is one settings class of a rule.
type Class struct {
	ID      string
	Command string
	// MayBeAbsent: the class depends on an ordering option, so a relay may
	// answer that the command is not available.
	MayBeAbsent bool
	Sensitive   bool
	Source      string // where S22 lists it
}

// RuleSEL751SHO is the SEL-751 rule: every SHO form of S22 Table 7.67
// (p. 7.77), each at Level 1, without the trailing setting-name parameter and
// with an explicit port or map number. Port F is standard; Ports 1 to 4 are
// ordering options (S22 Table 7.1 p. 7.1), and the maps depend on the
// protocol option. Port 1 cannot be absent, because a Telnet session reaches
// the relay through it and reads SHO P 1 for LANG (ADR-0005). Which
// classes can really be absent, and whether an absent one answers exactly
// "Invalid Command" (S22 p. 7.31), is documented-untested.
//
// The classes are in the order the register's run sel.config.read_all sends
// their commands (C3 0.3, revision 5): the gate reads first (Port 1 for LANG,
// then Global), then the rest. A snapshot holds its sections in this order,
// which is the order they were read in, so each section's span comes after
// the one before it (0.2, B1's ruling on #279). Rule sel-751-sho/1, which
// listed them in the order of S22 Table 7.67, is retired, not edited: no
// snapshot under it was ever stored, since every example was simulated.
var RuleSEL751SHO = Rule{
	ID:           "sel-751-sho/2",
	Family:       "sel-751",
	NotAvailable: "Invalid Command",
	Classes: []Class{
		{ID: "port.1", Command: "SHO P 1", Sensitive: true, Source: "S22 Table 7.67; Table 4.104"},
		{ID: "global", Command: "SHO G", Source: "S22 Table 7.67; Tables 4.84 to 4.102"},
		{ID: "group.1", Command: "SHO 1", Source: "S22 Table 7.67; Figure 7.43"},
		{ID: "group.2", Command: "SHO 2", Source: "S22 Table 7.67"},
		{ID: "group.3", Command: "SHO 3", Source: "S22 Table 7.67"},
		{ID: "group.4", Command: "SHO 4", Source: "S22 Table 7.67"},
		{ID: "logic.1", Command: "SHO L 1", Source: "S22 Table 7.67"},
		{ID: "logic.2", Command: "SHO L 2", Source: "S22 Table 7.67"},
		{ID: "logic.3", Command: "SHO L 3", Source: "S22 Table 7.67"},
		{ID: "logic.4", Command: "SHO L 4", Source: "S22 Table 7.67"},
		{ID: "port.f", Command: "SHO P F", Sensitive: true, Source: "S22 Table 7.67"},
		{ID: "port.2", Command: "SHO P 2", MayBeAbsent: true, Sensitive: true, Source: "S22 Table 7.67; Table 7.1"},
		{ID: "port.3", Command: "SHO P 3", MayBeAbsent: true, Sensitive: true, Source: "S22 Table 7.67; Table 7.1"},
		{ID: "port.4", Command: "SHO P 4", MayBeAbsent: true, Sensitive: true, Source: "S22 Table 7.67; Table 7.1"},
		{ID: "report", Command: "SHO R", Source: "S22 Table 7.67"},
		{ID: "front-panel", Command: "SHO F", Source: "S22 Table 7.67"},
		{ID: "modbus", Command: "SHO M", MayBeAbsent: true, Source: "S22 Table 7.67"},
		{ID: "iec-103", Command: "SHO I", MayBeAbsent: true, Source: "S22 Table 7.67"},
		{ID: "eip.1", Command: "SHO E 1", MayBeAbsent: true, Source: "S22 Table 7.67"},
		{ID: "eip.2", Command: "SHO E 2", MayBeAbsent: true, Source: "S22 Table 7.67"},
		{ID: "eip.3", Command: "SHO E 3", MayBeAbsent: true, Source: "S22 Table 7.67"},
		{ID: "dnp.1", Command: "SHO DNP 1", MayBeAbsent: true, Source: "S22 Table 7.67; Figure D.3"},
		{ID: "dnp.2", Command: "SHO DNP 2", MayBeAbsent: true, Source: "S22 Table 7.67"},
		{ID: "dnp.3", Command: "SHO DNP 3", MayBeAbsent: true, Source: "S22 Table 7.67"},
	},
}

// Rules lists every rule this minor knows, by ID.
var Rules = map[string]Rule{RuleSEL751SHO.ID: RuleSEL751SHO}

func (r Rule) class(id string) (Class, int, bool) {
	for i, c := range r.Classes {
		if c.ID == id {
			return c, i, true
		}
	}
	return Class{}, -1, false
}

var (
	hexSHA256   = regexp.MustCompile(`^[0-9a-f]{64}$`)
	uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	// settingName is C2's: a leading digit is allowed (51SAT, S22 Table 4.84).
	settingName = regexp.MustCompile(`^[A-Z0-9][A-Z0-9_]{0,15}$`)
	// valueText: printable ASCII with no space at either end and no run of
	// two spaces, since two spaces end a value.
	valueText = regexp.MustCompile(`^[!-~](?:[ -~]*[!-~])?$`)
)

// Digest is a C9 document's digest: "sha256:" and the lowercase hex SHA-256
// of the document's stored bytes, exactly as written, with no canonical form
// (D4-4 item 5, the C10 rule). C7 0.6's node.change_approval and
// node.baseline_ack name a snapshot by it (baseline_digest), C8 0.5's
// config.change_detected names a snapshot and a difference by it
// (snapshot_digest, difference_digest), and a Difference names its two
// snapshots by it.
func Digest(stored []byte) string {
	sum := sha256.Sum256(stored)
	return "sha256:" + hex.EncodeToString(sum[:])
}

var digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// DecodeSnapshot parses and validates a snapshot. Decoding is strict except
// for forward compatibility (strictjson.Forward): case-variant and duplicate
// keys are rejected, and unknown exact-case fields are ignored. A snapshot of
// this package's own minor or earlier is also decoded strictly, so that a
// writer bug is caught (the C1, C2 and C4 rule).
func DecodeSnapshot(b []byte) (Snapshot, error) {
	var s Snapshot
	if err := decode(b, &s); err != nil {
		return Snapshot{}, fmt.Errorf("config: snapshot: %w", err)
	}
	return s, s.Validate()
}

func decode[T any](b []byte, v *T) error {
	if err := strictjson.Forward(b, v); err != nil {
		return err
	}
	var probe struct {
		Schema string `json:"schema"`
	}
	if err := strictjson.Forward(b, &probe); err != nil {
		return err
	}
	if id, err := version.Parse(probe.Schema); err == nil && id.Name == self.Name && id.Major == self.Major && id.Minor <= self.Minor {
		var own T
		if err := strictjson.Decode(b, &own); err != nil {
			return err
		}
	}
	return nil
}

// The size of a snapshot is bounded (C9 0.3, D4-25), so that a configuration
// record, which is the snapshot and the transcript it points into, always fits
// the configuration database's record cap with room to spare. C5's
// Record.Bytes counts the event (Encode's bytes), the capture (the
// transcript's bytes) and the source cursor, and the record cap
// (Quota.MaxRecordBytes) is held to it.
const (
	// RecordCap is the configuration database's record cap, 1.5 MiB (D4-13).
	// platform/node.ConfigRecordBytes is the same number; a test in
	// bound_node_test.go fails if the two drift apart.
	RecordCap = 3 << 19
	// MaxTranscriptBytes is the longest transcript a configuration run keeps:
	// the register run's max_total_bytes. A test holds it to the register.
	MaxTranscriptBytes = 512 << 10
	// RecordHeadroom is what a record at both bounds leaves under RecordCap,
	// for a source cursor and anything else Record.Bytes counts that the
	// snapshot and the transcript do not (B1 on #345).
	RecordHeadroom = 64 << 10
	// MaxSettings bounds the settings of all sections together: S22's 8,734
	// plus a quarter. A relay printing more is not read as a SEL-751.
	MaxSettings = 10918
	// MaxSnapshotBytes bounds Encode's output: what is left of RecordCap
	// after the longest transcript and the headroom, 960 KiB. The count bound
	// alone does not give this, because a value can be long and JSON can
	// double a quote.
	MaxSnapshotBytes = RecordCap - MaxTranscriptBytes - RecordHeadroom
	// SnapshotFixedMax is what RecordsFit allows for everything but the
	// settings: the header, the transcript reference and the 24 sections'
	// own fields. B5 measured 5.3 KB for the golden snapshot.
	SnapshotFixedMax = 16 << 10
)

// ErrTooLarge is wrapped by every refusal for size, so a caller can tell a
// read that is too big for a snapshot from one that is malformed.
var ErrTooLarge = errors.New("a snapshot is bounded in settings and bytes")

// Encode is the snapshot's one stored form: compact UTF-8 JSON in the order
// of the struct, with no HTML escaping and no trailing newline. MaxSnapshotBytes
// bounds its length.
func (s Snapshot) Encode() ([]byte, error) {
	return encodeCompact(s)
}

func encodeCompact(v any) ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(b.Bytes(), []byte("\n")), nil
}

// RecordsFit reports whether a read of these records can become a snapshot
// within the bounds, before one is built: at most MaxSettings settings, and
// the encoded settings plus SnapshotFixedMax within MaxSnapshotBytes. A run
// that fails it ends with failed.config_unparsable and no snapshot (C2 0.6).
// Validate holds a built snapshot to the same bounds, and TestRecordsFit shows
// that a read RecordsFit passes is a snapshot Validate passes.
func RecordsFit(recs []adapter.Record) error {
	var n int
	size := SnapshotFixedMax
	for _, r := range recs {
		n += len(r.Fields)
		if n > MaxSettings {
			return fmt.Errorf("config: the read holds more than %d settings: %w", MaxSettings, ErrTooLarge)
		}
		for _, f := range r.Fields {
			b, err := encodeCompact(Setting{Name: f.Name, Value: f.Value})
			if err != nil {
				return fmt.Errorf("config: %w", err)
			}
			size += len(b) + 1
		}
		if size > MaxSnapshotBytes {
			return fmt.Errorf("config: the read's settings encode to more than %d bytes: %w", MaxSnapshotBytes-SnapshotFixedMax, ErrTooLarge)
		}
	}
	return nil
}

// checkSize holds a snapshot that is otherwise valid to the bounds.
func (s Snapshot) checkSize() error {
	var n int
	for _, sec := range s.Sections {
		n += len(sec.Settings)
	}
	if n > MaxSettings {
		return fmt.Errorf("config: snapshot: %d settings, more than %d: %w", n, MaxSettings, ErrTooLarge)
	}
	b, err := s.Encode()
	if err != nil {
		return fmt.Errorf("config: snapshot: %w", err)
	}
	if len(b) > MaxSnapshotBytes {
		return fmt.Errorf("config: snapshot: %d bytes encoded, more than %d: %w", len(b), MaxSnapshotBytes, ErrTooLarge)
	}
	return nil
}

// Validate checks every rule that can be checked from the snapshot alone.
// CheckAgainst checks it against its transcript.
func (s Snapshot) Validate() error {
	c := &check{}
	c.header(s.Schema, s.Kind, KindSnapshot, s.AssetID)
	if !uuidPattern.MatchString(s.InvocationID) {
		c.fail("invocation_id %q is not a lowercase UUID", s.InvocationID)
	}
	if !asset.ValidOperationID(s.OperationID) {
		c.fail("operation_id %q is not an operation ID", s.OperationID)
	}
	if s.Adapter.ID == "" || s.Adapter.Version == "" {
		c.fail("adapter id and version are required (EP-4)")
	}
	if s.RegisterVersion == 0 {
		c.fail("register_version is required: the register package that permitted the lines")
	}
	if s.Target != asset.DeviceObserved && s.Target != asset.Simulated {
		c.fail("target must be %q or %q", asset.DeviceObserved, asset.Simulated)
	}
	if !asset.ValidTime(s.RetrievedAt) {
		c.fail("retrieved_at must be an RFC 3339 UTC time")
	}
	e := s.Transcript
	if !hexSHA256.MatchString(e.SHA256) || e.Ref != "sha256:"+e.SHA256 || e.Length <= 0 {
		c.fail("transcript needs sha256, ref \"sha256:\" + sha256, and a positive length")
	}
	rule, ok := c.rule(s.Rule)
	if !ok {
		return c.err("snapshot")
	}
	if len(s.Sections) != len(rule.Classes) {
		c.fail("rule %s has %d classes and a snapshot holds every one, in order; this one has %d sections", rule.ID, len(rule.Classes), len(s.Sections))
	}
	var prevEnd int64
	for i, sec := range s.Sections {
		p := fmt.Sprintf("sections[%d]", i)
		if i < len(rule.Classes) {
			want := rule.Classes[i]
			if sec.Class != want.ID || sec.Command != want.Command {
				c.fail("%s: rule %s holds %s (%q) here, not %s (%q)", p, rule.ID, want.ID, want.Command, sec.Class, sec.Command)
			}
			if sec.Sensitive != want.Sensitive {
				c.fail("%s: sensitive is %v for %s under rule %s", p, want.Sensitive, want.ID, rule.ID)
			}
			if sec.State == Absent && !want.MayBeAbsent {
				c.fail("%s: %s cannot be absent under rule %s", p, want.ID, rule.ID)
			}
		}
		if sec.State != Present && sec.State != Absent {
			c.fail("%s.state %q is not present or absent", p, sec.State)
		}
		if !hexSHA256.MatchString(sec.SHA256) {
			c.fail("%s.sha256 is not a lowercase SHA-256", p)
		}
		sp := sec.Span
		if sp.Offset < 0 || sp.Length <= 0 || sp.Offset+sp.Length > e.Length {
			c.fail("%s.span lies outside the transcript", p)
		} else if sp.Offset < prevEnd {
			c.fail("%s.span comes before the end of the section before it; sections are in the order the run read them, and never overlap", p)
		}
		prevEnd = sp.Offset + sp.Length
		if sec.State == Absent && len(sec.Settings) > 0 {
			c.fail("%s: an absent section has no settings", p)
		}
		if sec.State == Present && len(sec.Settings) == 0 {
			c.fail("%s: a present section holds at least one setting; a reply with none fails the read", p)
		}
		seen := map[string]bool{}
		for j, st := range sec.Settings {
			q := fmt.Sprintf("%s.settings[%d]", p, j)
			if !settingName.MatchString(st.Name) {
				c.fail("%s: name %q is not a setting name", q, st.Name)
			}
			if seen[st.Name] {
				c.fail("%s: %s is printed twice in one section", q, st.Name)
			}
			seen[st.Name] = true
			if !valueText.MatchString(st.Value) || strings.Contains(st.Value, "  ") || strings.Contains(st.Value, ":=") {
				c.fail("%s: value must be printable ASCII with no space at either end, no two spaces together and no :=", q)
			}
		}
	}
	if err := c.err("snapshot"); err != nil {
		return err
	}
	return s.checkSize()
}

type check struct{ errs []error }

func (c *check) fail(f string, a ...any) { c.errs = append(c.errs, fmt.Errorf(f, a...)) }

func (c *check) err(what string) error {
	if len(c.errs) == 0 {
		return nil
	}
	return fmt.Errorf("config: %s: %w", what, errors.Join(c.errs...))
}

func (c *check) header(schema, kind, wantKind, assetID string) {
	id, err := version.Parse(schema)
	if err != nil || !self.Accepts(id) {
		c.fail("schema %q is not readable as %s", schema, Contract)
	}
	if kind != wantKind {
		c.fail("kind %q is not %q", kind, wantKind)
	}
	if !asset.ValidAssetID(assetID) {
		c.fail("asset_id %q is not a lowercase UUID", assetID)
	}
}

func (c *check) rule(id string) (Rule, bool) {
	r, ok := Rules[id]
	if !ok {
		c.fail("rule %q is not a rule of %s; a difference under an unknown rule cannot be computed", id, Contract)
	}
	return r, ok
}
