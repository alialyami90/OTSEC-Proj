package finding

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"otsec.local/otsec/contracts/asset"
	"otsec.local/otsec/contracts/event"
	"otsec.local/otsec/contracts/node"
	"otsec.local/otsec/contracts/version"
)

// Identifier is this contract's schema identifier.
const Identifier = "otsec.finding/0.1"

var self = version.ID{Name: "finding", Major: 0, Minor: 1}

// Known reports whether schema names a minor of this contract that this
// build reads. A reader refuses a finding of any other minor rather than skip
// it, so a node rolled back past a newer minor fails closed (D4-61).
func Known(schema string) bool { return schema == Identifier }

// Bounds on one record, so a finding always fits one store record.
const (
	MaxEvidence      = 16 // evidence IDs per identity, precondition or mitigation
	MaxPreconditions = 32
	MaxMitigations   = 16
)

// Class is a finding's class (R9.2). Closed list.
type Class string

const (
	ApplicableByVersion   Class = "applicable-by-version"
	Confirmed             Class = "confirmed"
	Mitigated             Class = "mitigated"
	NotApplicable         Class = "not-applicable"
	NotApplicableOperator Class = "not-applicable-operator"
	NotApplicablePassive  Class = "not-applicable-passive" // D4-49 Q6 (iii)
)

func (c Class) valid() bool {
	switch c {
	case ApplicableByVersion, Confirmed, Mitigated, NotApplicable, NotApplicableOperator, NotApplicablePassive:
		return true
	}
	return false
}

// Reason says why a finding is not applicable. It is set on the three
// not-applicable classes only. Closed list.
type Reason string

const (
	OutsideRange       Reason = "outside-range"        // the version is outside every affected range
	ProductNotNamed    Reason = "product-not-named"    // the advisory does not name the product
	PreconditionNotMet Reason = "precondition-not-met" // a device-read value shows a precondition does not hold (D4-49 Q5)
)

// Source is where an identity or a piece of evidence came from (V-M1 (e),
// R9 classes). Closed list; C1 0.3 is to use the same three.
type Source string

const (
	DeviceRead Source = "device-read" // read from the device through a registered read path
	Passive    Source = "passive"     // observed in the device's own traffic (R6.7)
	Operator   Source = "operator"    // entered by a person, in the audit chain
)

func (s Source) valid() bool { return s == DeviceRead || s == Passive || s == Operator }

// Evidence is one record a finding rests on. ID is a C2 invocation ID (a
// lowercase UUID) for a device read, an event.EventID string for a stored
// record, or audit:<node_id>:<seq> for an audit record.
// Stale marks evidence that is no longer current (docs/verification.md, "R9
// classes", point 3): a finding that fell from confirmed names it (D4-49 Q6
// (ii)).
type Evidence struct {
	Source Source `json:"source"`
	ID     string `json:"id"`
	Stale  bool   `json:"stale,omitempty"`
}

// Identity is the identity a finding was decided on: the product and the
// version exactly as read (for a SEL device, the product and the full FID).
// Evidence cites the identity record, by the invocation ID of the run that
// first read the value (C5 keeps its bytes). LatestRead is the latest run
// that read the same value. It shows the identity was current when this
// revision was decided. A later run that only confirms the value again
// records no new revision.
type Identity struct {
	Product    string     `json:"product"`
	Version    string     `json:"version"`
	Source     Source     `json:"source"`
	Evidence   []Evidence `json:"evidence"`
	LatestRead *Read      `json:"latest_read,omitempty"`
}

// Read is one run that read a value from the device: its C2 invocation ID
// and when it read it.
type Read struct {
	ID    string `json:"id"`
	AtUTC string `json:"at_utc"`
}

// State is a precondition's state. Closed list.
type State string

const (
	Evidenced State = "evidenced" // it holds, and the evidence shows it
	NotMet    State = "not-met"   // the evidence shows it does not hold
	Unread    State = "unread"    // nothing read shows it either way
)

// Precondition is one further condition the advisory names, by its name in
// the set (C11). Unread ones have no evidence.
type Precondition struct {
	Name     string     `json:"name"`
	State    State      `json:"state"`
	Evidence []Evidence `json:"evidence,omitempty"`
}

// Mitigation is one of the entry's mitigations in the signed set (C11), by
// its name there, that is evidenced. A mitigation the set does not list is
// never applied. OperatorAttested is true when every current piece of its
// evidence was entered by an operator.
type Mitigation struct {
	Name             string     `json:"name"`
	OperatorAttested bool       `json:"operator_attested"`
	Evidence         []Evidence `json:"evidence"`
}

// Set names the advisory set a finding was decided under (R9.3), by C11's
// set_id, version and issued_at.
type Set struct {
	ID       string `json:"id"`
	Version  uint64 `json:"version"`
	IssuedAt string `json:"issued_at"`
}

// Matcher names the matcher and its version, so the same input is shown to
// give the same finding.
type Matcher struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Finding is one asset matched against one advisory.
type Finding struct {
	Schema        string         `json:"schema"`
	AssetID       string         `json:"asset_id"`
	Advisory      string         `json:"advisory"`
	Set           Set            `json:"set"`
	Revision      int            `json:"revision"`
	Previous      string         `json:"previous,omitempty"` // Hash of revision - 1
	From          Class          `json:"from,omitempty"`     // revision - 1's class
	Class         Class          `json:"class"`
	Reason        Reason         `json:"reason,omitempty"`
	EvaluatedUTC  string         `json:"evaluated_utc"`
	Matcher       Matcher        `json:"matcher"`
	Identity      Identity       `json:"identity"`
	Preconditions []Precondition `json:"preconditions,omitempty"`
	Mitigations   []Mitigation   `json:"mitigations,omitempty"`
}

// Hash is a finding's hash: "sha256:" and the lowercase hex SHA-256 of b,
// the record's bytes exactly as stored. A later revision names it in
// Previous.
func Hash(b []byte) string {
	s := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(s[:])
}

// Code is a validation failure. Closed list.
type Code string

const (
	CodeSchema   Code = "schema"   // identifier missing, malformed, or another contract or major
	CodeMissing  Code = "missing"  // a required field is absent
	CodeForm     Code = "form"     // a field's value is not in its form
	CodeRange    Code = "range"    // a count outside its range
	CodeConflict Code = "conflict" // fields that must agree do not
)

// Error is one validation failure.
type Error struct {
	Code   Code
	Field  string
	Detail string
}

func (e *Error) Error() string {
	return fmt.Sprintf("finding: %s: %s: %s", e.Field, e.Code, e.Detail)
}

// Codes returns the codes of every *Error in err, which may be a join.
func Codes(err error) []Code {
	var out []Code
	if ve, ok := err.(*Error); ok {
		return append(out, ve.Code)
	}
	if j, ok := err.(interface{ Unwrap() []error }); ok {
		for _, x := range j.Unwrap() {
			out = append(out, Codes(x)...)
		}
	}
	return out
}

type checker struct{ errs []error }

func (c *checker) fail(code Code, field, format string, a ...any) {
	c.errs = append(c.errs, &Error{Code: code, Field: field, Detail: fmt.Sprintf(format, a...)})
}

var (
	sha256Ref = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	utcForm   = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$`)
	nameForm  = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,63}$`)
	idForm    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	setID     = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`) // C11 set_id
	// invocationID is a C2 invocation ID: a lowercase UUID of version 1 to 8
	// with the RFC variant, as contracts/adapter issues it (D4-57).
	invocationID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
)

func (c *checker) utc(field, s string) {
	if s == "" {
		c.fail(CodeMissing, field, "required")
		return
	}
	if _, err := time.Parse(time.RFC3339Nano, s); err != nil || !utcForm.MatchString(s) {
		c.fail(CodeForm, field, "%q is not RFC 3339 UTC with Z", s)
	}
}

// evidence checks a list of evidence, which must hold 1 to MaxEvidence
// entries when need is true and none when it is false.
func (c *checker) evidence(field string, ev []Evidence, need bool) {
	switch {
	case need && len(ev) == 0:
		c.fail(CodeMissing, field, "every class lists the evidence that made it so")
	case !need && len(ev) != 0:
		c.fail(CodeConflict, field, "an unread precondition has no evidence")
	case len(ev) > MaxEvidence:
		c.fail(CodeRange, field, "%d entries, above %d", len(ev), MaxEvidence)
	}
	for i, e := range ev {
		f := fmt.Sprintf("%s[%d]", field, i)
		if !e.Source.valid() {
			c.fail(CodeForm, f+".source", "%q is not a source", e.Source)
		}
		// The form of the ID is tied to the source, so an operator's entry
		// cannot stand as a device read (C6 on #440).
		_, err := event.ParseEventID(e.ID)
		switch {
		case e.Source == DeviceRead && !invocationID.MatchString(e.ID):
			c.fail(CodeForm, f+".id", "%q: a device read is cited by its invocation ID", e.ID)
		case e.Source == Passive && (err != nil || strings.HasPrefix(e.ID, "audit:")):
			// An audit reference is also a well-formed event ID, since a
			// node may be named "audit", so it is refused here by its
			// prefix (D4-57, C6's F-025).
			c.fail(CodeForm, f+".id", "%q: a passive observation is cited by its event ID, never an audit reference", e.ID)
		case e.Source == Operator && !validAuditRef(e.ID):
			c.fail(CodeForm, f+".id", "%q: an operator entry is cited as audit:<node_id>:<seq>", e.ID)
		}
	}
}

// Validate checks every rule of the contract that holds on one record.
func (f *Finding) Validate() error {
	c := &checker{}
	if got, err := version.Parse(f.Schema); err != nil || !self.Accepts(got) {
		c.fail(CodeSchema, "schema", "%q is not %s or another 0.x minor of it", f.Schema, Identifier)
	}
	if !asset.ValidAssetID(f.AssetID) {
		c.fail(CodeForm, "asset_id", "%q is not a lowercase UUID", f.AssetID)
	}
	if !idForm.MatchString(f.Advisory) {
		c.fail(CodeForm, "advisory", "%q is not an advisory ID", f.Advisory)
	}
	if !setID.MatchString(f.Set.ID) {
		c.fail(CodeForm, "set.id", "%q is not a set ID", f.Set.ID)
	}
	if f.Set.Version < 1 {
		c.fail(CodeRange, "set.version", "%d, below 1", f.Set.Version)
	}
	c.utc("set.issued_at", f.Set.IssuedAt)
	c.utc("evaluated_utc", f.EvaluatedUTC)
	if f.Matcher.Name == "" || f.Matcher.Version == "" {
		c.fail(CodeMissing, "matcher", "name and version are required")
	}
	switch {
	case f.Revision < 1:
		c.fail(CodeRange, "revision", "%d, below 1", f.Revision)
	case f.Revision == 1 && (f.Previous != "" || f.From != ""):
		c.fail(CodeConflict, "previous", "revision 1 replaces nothing")
	case f.Revision > 1 && (!sha256Ref.MatchString(f.Previous) || !f.From.valid()):
		c.fail(CodeMissing, "previous", "a later revision names the hash and class it replaces")
	}
	if !f.Class.valid() {
		c.fail(CodeForm, "class", "%q is not a class", f.Class)
	}

	id := f.Identity
	if id.Product == "" || id.Version == "" {
		c.fail(CodeMissing, "identity", "product and version are required")
	}
	if !id.Source.valid() {
		c.fail(CodeForm, "identity.source", "%q is not a source", id.Source)
	}
	c.evidence("identity.evidence", id.Evidence, true)
	if r := id.LatestRead; r != nil {
		if id.Source != DeviceRead {
			c.fail(CodeConflict, "identity.latest_read", "only a device-read identity has a read")
		}
		if !invocationID.MatchString(r.ID) {
			c.fail(CodeForm, "identity.latest_read.id", "%q is not an invocation ID", r.ID)
		}
		c.utc("identity.latest_read.at_utc", r.AtUTC)
	}
	for i, e := range id.Evidence {
		if e.Source != id.Source {
			c.fail(CodeConflict, fmt.Sprintf("identity.evidence[%d].source", i), "%s evidence for a %s identity", e.Source, id.Source)
		}
	}

	var unread, notMet, notMetRead, weak, stale int
	for _, e := range id.Evidence {
		if e.Stale {
			stale++
		}
	}
	seen := map[string]bool{}
	if len(f.Preconditions) > MaxPreconditions {
		c.fail(CodeRange, "preconditions", "%d entries, above %d", len(f.Preconditions), MaxPreconditions)
	}
	for i, p := range f.Preconditions {
		field := fmt.Sprintf("preconditions[%d]", i)
		if !nameForm.MatchString(p.Name) || seen[p.Name] {
			c.fail(CodeForm, field+".name", "%q is not a name, or is repeated", p.Name)
		}
		seen[p.Name] = true
		switch p.State {
		case Unread:
			unread++
		case NotMet:
			notMet++
			if all(p.Evidence, DeviceRead) && !anyStale(p.Evidence) {
				notMetRead++
			}
		case Evidenced:
		default:
			c.fail(CodeForm, field+".state", "%q is not a state", p.State)
		}
		c.evidence(field+".evidence", p.Evidence, p.State != Unread)
		for _, e := range p.Evidence {
			if e.Source == Operator {
				weak++
			}
			if e.Stale {
				stale++
			}
		}
	}
	seen = map[string]bool{}
	if len(f.Mitigations) > MaxMitigations {
		c.fail(CodeRange, "mitigations", "%d entries, above %d", len(f.Mitigations), MaxMitigations)
	}
	for i, m := range f.Mitigations {
		field := fmt.Sprintf("mitigations[%d]", i)
		if !nameForm.MatchString(m.Name) || seen[m.Name] {
			c.fail(CodeForm, field+".name", "%q is not a name, or is repeated", m.Name)
		}
		seen[m.Name] = true
		c.evidence(field+".evidence", m.Evidence, true)
		if len(m.Evidence) > 0 && !current(m.Evidence) {
			c.fail(CodeConflict, field+".evidence", "a mitigation holds only on current evidence")
		}
		if len(m.Evidence) > 0 && m.OperatorAttested != all(currentOnly(m.Evidence), Operator) {
			c.fail(CodeConflict, field+".operator_attested", "true exactly when every current piece of evidence is an operator's")
		}
	}

	// The classes (docs/verification.md, "R9 classes and what confirmed needs").
	na := f.Class == NotApplicable || f.Class == NotApplicableOperator || f.Class == NotApplicablePassive
	if na != (f.Reason != "") {
		c.fail(CodeConflict, "reason", "set on the not-applicable classes, and only there")
	}
	// D4-49 Q5: a precondition read as not met gives not-applicable on a
	// device-read identity, mitigated when the advisory names the setting as
	// a mitigation, and applicable-by-version on any other identity.
	if notMet > 0 && !(f.Class == NotApplicable && f.Reason == PreconditionNotMet) && f.Class != Mitigated &&
		!(f.Class == ApplicableByVersion && id.Source != DeviceRead) {
		c.fail(CodeConflict, "preconditions", "a precondition not met makes the finding not applicable, mitigated, or applicable-by-version on an identity not read from the device")
	}
	if unread > 0 && f.Class != ApplicableByVersion && f.Class != Mitigated {
		c.fail(CodeConflict, "preconditions", "an unread precondition leaves the finding applicable-by-version")
	}
	if len(f.Mitigations) > 0 && f.Class != Mitigated {
		c.fail(CodeConflict, "mitigations", "an evidenced mitigation makes the finding mitigated")
	}
	switch f.Class {
	case Confirmed:
		if id.Source != DeviceRead {
			c.fail(CodeConflict, "class", "confirmed needs a device-read identity, not %s", id.Source)
		}
		if id.LatestRead == nil {
			c.fail(CodeMissing, "identity.latest_read", "confirmed shows the read that made the identity current")
		}
		if weak > 0 {
			c.fail(CodeConflict, "class", "confirmed needs every precondition evidenced by a device read or a passive observation")
		}
		if stale > 0 {
			c.fail(CodeConflict, "class", "confirmed needs current evidence; stale evidence leaves applicable-by-version")
		}
	case Mitigated:
		if len(f.Mitigations) == 0 {
			c.fail(CodeMissing, "mitigations", "mitigated needs an evidenced mitigation")
		}
	case NotApplicable:
		if id.Source != DeviceRead {
			c.fail(CodeConflict, "class", "not-applicable needs a device-read identity, not %s", id.Source)
		}
	case NotApplicableOperator:
		if id.Source != Operator {
			c.fail(CodeConflict, "class", "not-applicable-operator is for an operator identity, not %s", id.Source)
		}
	case NotApplicablePassive:
		if id.Source != Passive {
			c.fail(CodeConflict, "class", "not-applicable-passive is for a passive identity, not %s", id.Source)
		}
	}
	switch f.Reason {
	case "", OutsideRange, ProductNotNamed:
	case PreconditionNotMet:
		if notMetRead == 0 || f.Class != NotApplicable {
			c.fail(CodeConflict, "reason", "precondition-not-met needs a device-read identity and a precondition shown not met by a current device read")
		}
	default:
		c.fail(CodeForm, "reason", "%q is not a reason", f.Reason)
	}
	return errors.Join(c.errs...)
}

// validAuditRef reports whether s is audit:<node_id>:<seq>, with a valid
// node ID (contracts/node) and a seq of 1 or more.
func validAuditRef(s string) bool {
	parts := strings.Split(s, ":")
	if len(parts) != 3 || parts[0] != "audit" || !node.ID(parts[1]).Valid() {
		return false
	}
	seq, err := strconv.ParseUint(parts[2], 10, 64)
	return err == nil && seq > 0 && strconv.FormatUint(seq, 10) == parts[2]
}

// anyStale reports whether any piece of ev is stale.
func anyStale(ev []Evidence) bool {
	for _, e := range ev {
		if e.Stale {
			return true
		}
	}
	return false
}

// currentOnly returns the pieces of ev that are not stale.
func currentOnly(ev []Evidence) []Evidence {
	var out []Evidence
	for _, e := range ev {
		if !e.Stale {
			out = append(out, e)
		}
	}
	return out
}

// current reports whether some piece of ev is current.
func current(ev []Evidence) bool {
	for _, e := range ev {
		if !e.Stale {
			return true
		}
	}
	return false
}

func all(ev []Evidence, s Source) bool {
	for _, e := range ev {
		if e.Source != s {
			return false
		}
	}
	return len(ev) > 0
}
