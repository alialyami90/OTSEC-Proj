package register

import (
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"

	"otsec.local/otsec/contracts/internal/strictjson"
)

// ContractID is the identifier this reader writes. A package carries it or
// an earlier minor in Readable; a later minor is invalid here, because the
// reader is strict (an unknown field is refused, never ignored).
const ContractID = "otsec.register/0.3"

// Readable lists the package contracts this reader decodes. A 0.1 package
// reads as before; only 0.2 and later may carry context, and only 0.3 may
// carry limits and runs.
var Readable = []string{"otsec.register/0.1", "otsec.register/0.2", ContractID}

// Classification of a register entry. The list an entry sits in fixes which
// value it may carry: operations are read-only, session lines are
// session-control, deny rules are state-changing or unknown.
type Classification string

const (
	ReadOnly       Classification = "read-only"
	SessionControl Classification = "session-control"
	StateChanging  Classification = "state-changing"
	Unknown        Classification = "unknown"
)

// EvidenceClass follows CLAUDE.md section 3, plus "inferred" for conclusions
// drawn from documents but not stated by them (for example firmware fix
// inheritance, accepted by the owner on 2026-10-23).
// TODO(C1): import the evidence class from contracts/asset once it merges.
type EvidenceClass string

const (
	HardwareVerified   EvidenceClass = "hardware-verified"
	DocumentedUntested EvidenceClass = "documented-untested"
	Simulated          EvidenceClass = "simulated"
	Inferred           EvidenceClass = "inferred"
	Unsupported        EvidenceClass = "unsupported"
	EvidenceUnknown    EvidenceClass = "unknown"
)

// Phase is a transport phase (A3 8.3). Session lines name the phases that may
// send them (probe, auth, close). Operations run in operate unless they list
// phases; an operation may also run in probe, before authentication (C3-1).
type Phase string

const (
	PhaseProbe   Phase = "probe"
	PhaseAuth    Phase = "auth"
	PhaseOperate Phase = "operate"
	PhaseClose   Phase = "close"
)

// ProbeAccessLevel is the only access level a probe operation may need: the
// level a session has before authentication (SEL ASCII Level 0, the only
// families in 0.x; C3-A2 note 5).
const ProbeAccessLevel = "0"

// Package is one register for one device family.
type Package struct {
	Contract string `json:"contract"`
	// Family is the C1 product family the package applies to, e.g. "sel-751".
	Family string `json:"family"`
	// Revision increases with every release. The node refuses a package whose
	// revision is below the highest it has accepted (C7, anti-rollback).
	Revision uint64   `json:"revision"`
	Issued   string   `json:"issued"` // YYYY-MM-DD
	Owner    string   `json:"owner"`
	Sources  []Source `json:"sources"`
	// Preconditions must all be confirmed in the current session before any
	// operation other than the ones they are read by (e.g. LANG := ENGLISH,
	// read with SHO P 1).
	Preconditions []SettingCheck `json:"preconditions"`
	// Warnings are posture checks that do not refuse: the collector reads
	// them and reports each by ID, then collects (ADR-0005 MAXACC ruling,
	// C3-2).
	Warnings []PostureWarning `json:"warnings,omitempty"`
	// Context lists settings an operation needs to be read correctly (DATE_F
	// for the SER's dates). Added in 0.2 (D3-2).
	Context    []ContextRead `json:"context,omitempty"`
	Operations []Operation   `json:"operations"`
	// Runs are named, ordered lists of operations sent in one session. Added
	// in 0.3 (P4-A2).
	Runs           []Run         `json:"runs,omitempty"`
	SessionControl []SessionLine `json:"session_control"`
	Denied         []DenyRule    `json:"denied"`
	Firmware       Firmware      `json:"firmware"`
	Notes          []string      `json:"notes,omitempty"`
}

// Source is a document the entries cite.
type Source struct {
	ID       string `json:"id"` // e.g. "S22"
	Title    string `json:"title"`
	DateCode string `json:"date_code,omitempty"`
}

// Citation points into a Source.
type Citation struct {
	Source string `json:"source"` // a Source ID in this package
	Ref    string `json:"ref"`    // table, figure or page, e.g. "Table 7.63 p.7.78"
}

// Evidence is an evidence class with an optional qualifier.
type Evidence struct {
	Class EvidenceClass `json:"class"`
	Note  string        `json:"note,omitempty"`
}

// Operation is an invocable, read-only line. C2 invocations name it by ID.
type Operation struct {
	ID             string         `json:"id"`
	Classification Classification `json:"classification"`
	// Line is the template: tokens of [A-Z0-9] separated by single spaces,
	// where a token may instead be "{name}" for a declared parameter.
	Line   string  `json:"line"`
	Params []Param `json:"params,omitempty"`
	// Phases lists where the transport may send the line: operate, probe or
	// both. Empty means operate only. A probe line is sent before
	// authentication, so it must be literal (no parameters).
	Phases      []Phase `json:"phases,omitempty"`
	AccessLevel string  `json:"access_level"`
	// Limits bound the reply to this line. Added in 0.3; required of every
	// step of a run.
	Limits      *Limits    `json:"limits,omitempty"`
	Citations   []Citation `json:"citations"`
	Evidence    Evidence   `json:"evidence"`
	SideEffects string     `json:"side_effects"`
	Notes       string     `json:"notes,omitempty"`
}

// Limits bound the reply to one line: the adapter ends a reply that passes
// either with failed.response_too_large or failed.timeout, and keeps the bytes
// read (C2). Both are required when Limits is present.
type Limits struct {
	MaxReplyBytes int64 `json:"max_reply_bytes"`
	TimeoutMS     int64 `json:"timeout_ms"`
}

// The ceilings a limit may not pass. They are C2's invocation ceilings
// (adapter.MaxResponseBytes, MaxStepTimeoutMS and MaxDeadlineMS); a test in
// contracts/adapter pins them to the same values, because register cannot
// import adapter.
const (
	MaxSessionBytes = 1 << 20
	MaxStepMS       = 60_000
	MaxDeadlineMS   = 600_000
	// MaxRunSteps is the most operations one run may send.
	MaxRunSteps = 32
	// MaxRunAccessLevel is the highest access level a step of a run may need:
	// a run reads, at the level a monitoring credential holds.
	MaxRunAccessLevel = 1
)

// Run is a named, ordered list of operations sent in one session (P4-A2,
// D4-13). It fails as a whole: when a step fails, the adapter sends QUI,
// keeps every byte read and reports the read failed, never a partial result
// presented as complete. A run's ID shares the namespace of operation IDs, so
// a C2 invocation may name it.
//
// A step is the ID of an operation that is read-only, literal (no
// parameters), runs in operate, needs access level MaxRunAccessLevel or lower
// and carries Limits. The steps lead with the reads that gate everything
// else: the precondition and firmware-condition reads, so LANG := ENGLISH is
// confirmed before any other line is sent. The reads of the package's
// warnings, and the context reads of each step, are steps too, a context read
// before the step it is for, so a run sends every line once and no line
// outside its steps.
type Run struct {
	ID    string   `json:"id"`
	Steps []string `json:"steps"`
	// MaxTotalBytes bounds the received bytes of the whole session, and
	// DeadlineMS its time. They are at most C2's ceilings.
	MaxTotalBytes int64      `json:"max_total_bytes"`
	DeadlineMS    int64      `json:"deadline_ms"`
	Citations     []Citation `json:"citations"`
	Evidence      Evidence   `json:"evidence"`
	SideEffects   string     `json:"side_effects"`
	Notes         string     `json:"notes,omitempty"`
}

// Run returns the run with this ID.
func (p *Package) Run(id string) *Run {
	for i := range p.Runs {
		if p.Runs[i].ID == id {
			return &p.Runs[i]
		}
	}
	return nil
}

// ParamKind is a closed list. A kind a reader does not know makes the whole
// package invalid.
type ParamKind string

const (
	ParamUint ParamKind = "uint"
	ParamEnum ParamKind = "enum"
)

// Param is a typed parameter of an operation.
type Param struct {
	Name   string    `json:"name"`
	Kind   ParamKind `json:"kind"`
	Min    *uint64   `json:"min,omitempty"`    // uint only
	Max    *uint64   `json:"max,omitempty"`    // uint only
	Values []string  `json:"values,omitempty"` // enum only, each [A-Z0-9]+
}

// SessionLine is a literal line only the transport may send, in the listed
// phases. It is never invocable (C-A2-1).
type SessionLine struct {
	ID             string         `json:"id"`
	Classification Classification `json:"classification"`
	Line           string         `json:"line"`
	Phases         []Phase        `json:"phases"`
	AccessLevel    string         `json:"access_level"`
	Citations      []Citation     `json:"citations"`
	Evidence       Evidence       `json:"evidence"`
	SideEffects    string         `json:"side_effects"`
	Notes          string         `json:"notes,omitempty"`
}

// DenyRule documents a known dangerous line. Pattern is an RE2 expression
// matched against the whole outgoing line (it is anchored when compiled).
type DenyRule struct {
	ID             string         `json:"id"`
	Classification Classification `json:"classification"`
	Pattern        string         `json:"pattern"`
	AccessLevel    string         `json:"access_level,omitempty"`
	Citations      []Citation     `json:"citations"`
	Evidence       Evidence       `json:"evidence"`
	SideEffects    string         `json:"side_effects"`
	Notes          string         `json:"notes,omitempty"`
}

// SettingCheck is a device setting that must hold, read with an operation in
// this package.
type SettingCheck struct {
	ID      string `json:"id"`
	Setting string `json:"setting"` // e.g. "LANG"
	Equals  string `json:"equals"`  // e.g. "ENGLISH"
	ReadBy  string `json:"read_by"` // an Operation ID
	Reason  string `json:"reason"`
}

// PostureWarning is a device setting the collector reads and warns about
// without refusing. Exactly one of Max and Equals is set: the warning is
// raised when the value is above Max, or differs from Equals.
type PostureWarning struct {
	ID      string  `json:"id"`      // the warning code C2 reports
	Setting string  `json:"setting"` // e.g. "MAXACC"
	Max     *uint64 `json:"max,omitempty"`
	Equals  string  `json:"equals,omitempty"`
	ReadBy  string  `json:"read_by"` // an Operation ID
	Reason  string  `json:"reason"`
}

// ContextRead is a device setting that the operations in For need to be read
// correctly, read with ReadBy before them in the same session (D3-2). It
// refuses nothing by itself and changes no line. It permits ReadBy's line in
// a session that runs an operation in For, which an operation outside For
// does not get. The read is a line like any other: it counts against the
// invocation's line and rate limits and is kept in the raw capture. A value
// outside Values, or a reply that does not name the setting, leaves the
// operation's output unreadable, never read with a guessed value.
type ContextRead struct {
	ID      string   `json:"id"`
	Setting string   `json:"setting"` // e.g. "DATE_F"
	ReadBy  string   `json:"read_by"` // an Operation ID
	For     []string `json:"for"`     // Operation IDs
	Values  []string `json:"values"`  // the values the consumer understands
	Reason  string   `json:"reason"`
}

// ContextFor returns the context reads an operation needs, in package order.
func (p *Package) ContextFor(op string) []ContextRead {
	var out []ContextRead
	for _, c := range p.Context {
		for _, f := range c.For {
			if f == op {
				out = append(out, c)
				break
			}
		}
	}
	return out
}

// Raised reports whether a value read from the device raises the warning. A
// value that is not a decimal number, against a Max, raises it: a reading
// the collector cannot interpret is reported, not passed. A setting missing
// from the reading is passed as "" and so always raises it (C3-A3 note).
func (w *PostureWarning) Raised(value string) bool {
	if w.Max == nil {
		return value != w.Equals
	}
	v, err := strconv.ParseUint(value, 10, 64)
	return err != nil || v > *w.Max
}

// InPhase reports whether the transport may send the operation's line in ph.
func (o *Operation) InPhase(ph Phase) bool {
	if len(o.Phases) == 0 {
		return ph == PhaseOperate
	}
	for _, p := range o.Phases {
		if p == ph {
			return true
		}
	}
	return false
}

// Firmware is the family's firmware allowlist. Matching is exact: a firmware
// ID must appear in Known, and its branch rule must allow its version.
// Anything else is refused (fail closed).
type Firmware struct {
	Known      []KnownFirmware `json:"known"`
	Branches   []BranchRule    `json:"branches"`
	NotCovered []string        `json:"not_covered,omitempty"`
}

// KnownFirmware is one firmware ID the sources list.
type KnownFirmware struct {
	FID      string   `json:"fid"`
	Branch   string   `json:"branch"`
	Version  uint64   `json:"version"`
	Citation Citation `json:"citation"`
}

// BranchStatus is a closed list.
type BranchStatus string

const (
	BranchAllow              BranchStatus = "allow"
	BranchAllowWithCondition BranchStatus = "allow-with-condition"
	BranchDeny               BranchStatus = "deny"
)

// BranchRule decides one firmware branch.
type BranchRule struct {
	Branch     string         `json:"branch"`
	Status     BranchStatus   `json:"status"`
	MinVersion uint64         `json:"min_version"`
	Conditions []SettingCheck `json:"conditions,omitempty"`
	Basis      string         `json:"basis"`
	Evidence   Evidence       `json:"evidence"`
}

// Envelope carries a package and its detached signature. C7 defines how the
// signature, key ID and revision are verified; until that passes, the
// payload must not be parsed for use.
type Envelope struct {
	Contract  string `json:"contract"`  // ContractID
	Algorithm string `json:"algorithm"` // "ed25519"
	KeyID     string `json:"key_id"`
	Payload   []byte `json:"payload"`   // the package's exact JSON bytes
	Signature []byte `json:"signature"` // over SigningDomain followed by Payload
}

// SigningDomain is prefixed to the payload before signing and verifying, so a
// register signature can never be valid for any other kind of signed message
// (A3 review C3-A3-1). C7 builds the signing input from it
// (authz.RegisterSigningInput). It is a fixed tag, not the package's version:
// it stays as it is in every minor, and the payload names its own contract
// inside the signed bytes.
const SigningDomain = "otsec.register/0.1 package\n"

// Decode parses and validates a package strictly: unknown fields, duplicate
// keys at any depth, anything after the package and any validation failure
// are errors.
func Decode(data []byte) (*Package, error) {
	// Strict reading: exact key spelling, no duplicate or case-variant keys,
	// no unknown fields, nothing after the package (A3 C3-A3-2, A6 review).
	var p Package
	if err := strictjson.Decode(data, &p); err != nil {
		return nil, fmt.Errorf("register: %w", err)
	}
	if err := checkNewKeys(data); err != nil {
		return nil, err
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return &p, nil
}

// checkNewKeys applies D4-16 as a general rule: a key introduced at a C3
// version is refused by its presence in any package below that version,
// whatever its value, [] and null included. An older reader refuses the key as
// unknown, so a newer reader that took an empty one would read a package an
// older reader refuses. Validate sees only the decoded package, where an empty
// value and a missing key look alike, so the keys are looked for in the bytes.
// The keys are context (0.2), runs and an operation's limits (0.3).
func checkNewKeys(data []byte) error {
	var raw struct {
		Contract   string          `json:"contract"`
		Context    json.RawMessage `json:"context"`
		Runs       json.RawMessage `json:"runs"`
		Operations []struct {
			ID     string          `json:"id"`
			Limits json.RawMessage `json:"limits"`
		} `json:"operations"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("register: %w", err)
	}
	i := slices.Index(Readable, raw.Contract)
	if i < 0 {
		return nil
	}
	minor := i + 1
	if raw.Context != nil && minor < 2 {
		return fmt.Errorf("register: context is new in 0.2, so a %s package cannot carry the key", raw.Contract)
	}
	if raw.Runs != nil && minor < 3 {
		return fmt.Errorf("register: runs are new in 0.3, so a %s package cannot carry the key", raw.Contract)
	}
	for _, o := range raw.Operations {
		if o.Limits != nil && minor < 3 {
			return fmt.Errorf("register: limits are new in 0.3, so operation %s cannot carry the key in a %s package", o.ID, raw.Contract)
		}
	}
	return nil
}

var (
	tokenRe   = regexp.MustCompile(`^[A-Z0-9]+$`)
	lineRe    = regexp.MustCompile(`^[A-Z0-9]+( [A-Z0-9]+)*$`)
	idRe      = regexp.MustCompile(`^[a-z0-9]+(\.[a-z0-9_]+)+$`)
	familyRe  = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)
	paramRe   = regexp.MustCompile(`^\{([a-z][a-z0-9_]*)\}$`)
	settingRe = regexp.MustCompile(`^[A-Z0-9_]+$`)
	dateRe    = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}$`)
)

// Validate checks every rule in the package's documentation. The first
// failure is returned.
func (p *Package) Validate() error {
	minor := -1
	for i, c := range Readable {
		if p.Contract == c {
			minor = i + 1
		}
	}
	if minor < 0 {
		return fmt.Errorf("register: contract %q, want one of %q", p.Contract, Readable)
	}
	if !familyRe.MatchString(p.Family) {
		return fmt.Errorf("register: family %q is not a product family ID", p.Family)
	}
	if p.Revision == 0 {
		return fmt.Errorf("register: revision must be at least 1")
	}
	if !dateRe.MatchString(p.Issued) {
		return fmt.Errorf("register: issued %q is not YYYY-MM-DD", p.Issued)
	}
	if p.Owner == "" {
		return fmt.Errorf("register: owner is empty")
	}
	sources := map[string]bool{}
	for _, s := range p.Sources {
		if s.ID == "" || s.Title == "" || sources[s.ID] {
			return fmt.Errorf("register: source %q is empty or duplicated", s.ID)
		}
		sources[s.ID] = true
	}
	ids := map[string]bool{}
	claim := func(id string) error {
		if !idRe.MatchString(id) {
			return fmt.Errorf("register: entry ID %q is not dotted lower case", id)
		}
		if ids[id] {
			return fmt.Errorf("register: entry ID %q is duplicated", id)
		}
		ids[id] = true
		return nil
	}
	lines := map[string]string{}
	if len(p.Operations) == 0 {
		return fmt.Errorf("register: no operations")
	}
	for i := range p.Operations {
		o := &p.Operations[i]
		if err := claim(o.ID); err != nil {
			return err
		}
		if o.Classification != ReadOnly {
			return fmt.Errorf("register: operation %s is %q; only read-only lines are invocable", o.ID, o.Classification)
		}
		if err := o.validateTemplate(); err != nil {
			return err
		}
		if err := o.validateLimits(minor); err != nil {
			return err
		}
		seen := map[Phase]bool{}
		for _, ph := range o.Phases {
			if (ph != PhaseProbe && ph != PhaseOperate) || seen[ph] {
				return fmt.Errorf("register: operation %s has unknown or repeated phase %q", o.ID, ph)
			}
			seen[ph] = true
		}
		if seen[PhaseProbe] && len(o.Params) != 0 {
			return fmt.Errorf("register: operation %s runs in probe and has parameters", o.ID)
		}
		if seen[PhaseProbe] && o.AccessLevel != ProbeAccessLevel {
			return fmt.Errorf("register: operation %s runs in probe at access level %q, want %q", o.ID, o.AccessLevel, ProbeAccessLevel)
		}
		if err := checkCommon(o.ID, o.AccessLevel, o.Citations, o.Evidence, o.SideEffects, sources, true); err != nil {
			return err
		}
		if prev, ok := lines[o.Line]; ok {
			return fmt.Errorf("register: %s and %s have the same line", prev, o.ID)
		}
		lines[o.Line] = o.ID
	}
	for i := range p.SessionControl {
		s := &p.SessionControl[i]
		if err := claim(s.ID); err != nil {
			return err
		}
		if s.Classification != SessionControl {
			return fmt.Errorf("register: session line %s is %q, want session-control", s.ID, s.Classification)
		}
		if !lineRe.MatchString(s.Line) {
			return fmt.Errorf("register: session line %s %q is not a literal line", s.ID, s.Line)
		}
		if prev, ok := lines[s.Line]; ok {
			return fmt.Errorf("register: %s and %s have the same line", prev, s.ID)
		}
		lines[s.Line] = s.ID
		if len(s.Phases) == 0 {
			return fmt.Errorf("register: session line %s has no phase", s.ID)
		}
		for _, ph := range s.Phases {
			if ph != PhaseProbe && ph != PhaseAuth && ph != PhaseClose {
				return fmt.Errorf("register: session line %s has unknown phase %q", s.ID, ph)
			}
			// An authentication line (ACC) elevates the session, so it may
			// not also be sent in probe or close (A6 C3 re-check). Which
			// line elevates is content, checked in A2's and A3's review.
			if ph == PhaseAuth && len(s.Phases) != 1 {
				return fmt.Errorf("register: session line %s is sent in auth and another phase", s.ID)
			}
		}
		if err := checkCommon(s.ID, s.AccessLevel, s.Citations, s.Evidence, s.SideEffects, sources, true); err != nil {
			return err
		}
	}
	for i := range p.Denied {
		d := &p.Denied[i]
		if err := claim(d.ID); err != nil {
			return err
		}
		if d.Classification != StateChanging && d.Classification != Unknown {
			return fmt.Errorf("register: deny rule %s is %q, want state-changing or unknown", d.ID, d.Classification)
		}
		if _, err := compileDeny(d.Pattern); err != nil {
			return fmt.Errorf("register: deny rule %s: %w", d.ID, err)
		}
		if err := checkCommon(d.ID, d.AccessLevel, d.Citations, d.Evidence, d.SideEffects, sources, false); err != nil {
			return err
		}
	}
	for _, c := range p.Preconditions {
		if err := p.checkSetting(c, ids); err != nil {
			return err
		}
	}
	for _, w := range p.Warnings {
		if err := claim(w.ID); err != nil {
			return err
		}
		if !settingRe.MatchString(w.Setting) || (w.Max == nil) == (w.Equals == "") || w.Reason == "" {
			return fmt.Errorf("register: warning %s is incomplete or sets both max and equals", w.ID)
		}
		if p.operation(w.ReadBy) == nil {
			return fmt.Errorf("register: warning %s is read by %q, which is not an operation", w.ID, w.ReadBy)
		}
	}
	if len(p.Context) != 0 && minor < 2 {
		return fmt.Errorf("register: context is new in 0.2, so a %s package cannot carry it", p.Contract)
	}
	for _, c := range p.Context {
		if err := p.checkContext(c, claim); err != nil {
			return err
		}
	}
	if err := p.validateFirmware(sources, ids); err != nil {
		return err
	}
	if len(p.Runs) != 0 && minor < 3 {
		return fmt.Errorf("register: runs are new in 0.3, so a %s package cannot carry them", p.Contract)
	}
	for i := range p.Runs {
		r := &p.Runs[i]
		if err := claim(r.ID); err != nil {
			return err
		}
		if err := p.validateRun(r, sources); err != nil {
			return err
		}
	}
	// Second barrier: no approved line may match a deny rule.
	m, err := p.compile()
	if err != nil {
		return err
	}
	for _, o := range p.Operations {
		for _, l := range o.sampleLines() {
			if id := m.denied(l); id != "" {
				return fmt.Errorf("register: operation %s line %q matches deny rule %s", o.ID, l, id)
			}
		}
	}
	for _, s := range p.SessionControl {
		if id := m.denied(s.Line); id != "" {
			return fmt.Errorf("register: session line %s %q matches deny rule %s", s.ID, s.Line, id)
		}
	}
	return nil
}

func checkCommon(id, level string, cites []Citation, ev Evidence, effects string, sources map[string]bool, needLevel bool) error {
	if needLevel && level == "" {
		return fmt.Errorf("register: %s has no access level", id)
	}
	if len(cites) == 0 {
		return fmt.Errorf("register: %s has no citation", id)
	}
	for _, c := range cites {
		if !sources[c.Source] || c.Ref == "" {
			return fmt.Errorf("register: %s cites unknown source %q or an empty reference", id, c.Source)
		}
	}
	if !validEvidence(ev.Class) {
		return fmt.Errorf("register: %s has evidence class %q", id, ev.Class)
	}
	if effects == "" {
		return fmt.Errorf("register: %s has no side_effects statement", id)
	}
	return nil
}

func validEvidence(c EvidenceClass) bool {
	switch c {
	case HardwareVerified, DocumentedUntested, Simulated, Inferred, Unsupported, EvidenceUnknown:
		return true
	}
	return false
}

func (p *Package) checkSetting(c SettingCheck, ids map[string]bool) error {
	if c.ID == "" || !settingRe.MatchString(c.Setting) || c.Equals == "" || c.Reason == "" {
		return fmt.Errorf("register: setting check %q is incomplete", c.ID)
	}
	if !ids[c.ReadBy] || p.operation(c.ReadBy) == nil {
		return fmt.Errorf("register: setting check %s is read by %q, which is not an operation", c.ID, c.ReadBy)
	}
	return nil
}

// checkContext applies A1's D3-2 conditions: read_by is an operation of this
// package that runs in operate, at an access level no higher than that of
// any operation in for, and it is not itself in for.
func (p *Package) checkContext(c ContextRead, claim func(string) error) error {
	if err := claim(c.ID); err != nil {
		return err
	}
	if !settingRe.MatchString(c.Setting) || c.Reason == "" || len(c.For) == 0 || len(c.Values) == 0 {
		return fmt.Errorf("register: context %s needs a setting, for, values and a reason", c.ID)
	}
	seen := map[string]bool{}
	for _, v := range c.Values {
		if !tokenRe.MatchString(v) || seen[v] {
			return fmt.Errorf("register: context %s value %q is not [A-Z0-9]+ or is repeated", c.ID, v)
		}
		seen[v] = true
	}
	by := p.operation(c.ReadBy)
	if by == nil || !by.InPhase(PhaseOperate) {
		return fmt.Errorf("register: context %s is read by %q, which is not an operation run in operate", c.ID, c.ReadBy)
	}
	needs := map[string]bool{}
	for _, f := range c.For {
		o := p.operation(f)
		if o == nil || needs[f] || f == c.ReadBy {
			return fmt.Errorf("register: context %s is for %q, which is not another operation or is repeated", c.ID, f)
		}
		needs[f] = true
		if !LevelAtMost(by.AccessLevel, o.AccessLevel) {
			return fmt.Errorf("register: context %s is read at access level %s, above %s's level %s", c.ID, by.AccessLevel, f, o.AccessLevel)
		}
	}
	return nil
}

// LevelAtMost reports whether access level a is no higher than b. Levels are
// compared as numbers; a level that is not a number is compared only for
// equality, so an order the format does not know is never assumed.
func LevelAtMost(a, b string) bool {
	x, errA := strconv.ParseUint(a, 10, 8)
	y, errB := strconv.ParseUint(b, 10, 8)
	if errA != nil || errB != nil {
		return a == b
	}
	return x <= y
}

func (p *Package) validateFirmware(sources, ids map[string]bool) error {
	f := &p.Firmware
	if len(f.Known) == 0 || len(f.Branches) == 0 {
		return fmt.Errorf("register: firmware allowlist is empty")
	}
	rules := map[string]bool{}
	for _, b := range f.Branches {
		if b.Branch == "" || rules[b.Branch] {
			return fmt.Errorf("register: firmware branch %q is empty or duplicated", b.Branch)
		}
		rules[b.Branch] = true
		switch b.Status {
		case BranchAllow, BranchDeny:
			if len(b.Conditions) != 0 {
				return fmt.Errorf("register: firmware branch %s is %s but has conditions", b.Branch, b.Status)
			}
		case BranchAllowWithCondition:
			if len(b.Conditions) == 0 {
				return fmt.Errorf("register: firmware branch %s is allow-with-condition with no condition", b.Branch)
			}
		default:
			return fmt.Errorf("register: firmware branch %s has status %q", b.Branch, b.Status)
		}
		for _, c := range b.Conditions {
			if err := p.checkSetting(c, ids); err != nil {
				return err
			}
		}
		if b.Basis == "" || !validEvidence(b.Evidence.Class) {
			return fmt.Errorf("register: firmware branch %s needs a basis and an evidence class", b.Branch)
		}
	}
	fids := map[string]bool{}
	for _, k := range f.Known {
		if k.FID == "" || fids[k.FID] {
			return fmt.Errorf("register: firmware ID %q is empty or duplicated", k.FID)
		}
		fids[k.FID] = true
		if !rules[k.Branch] {
			return fmt.Errorf("register: firmware ID %s is on branch %q, which has no rule", k.FID, k.Branch)
		}
		if !sources[k.Citation.Source] || k.Citation.Ref == "" {
			return fmt.Errorf("register: firmware ID %s has no valid citation", k.FID)
		}
	}
	return nil
}

// validateLimits checks an operation's limits: they are new in 0.3, and both
// numbers are positive and within the ceilings C2 holds an invocation to.
func (o *Operation) validateLimits(minor int) error {
	if o.Limits == nil {
		return nil
	}
	if minor < 3 {
		return fmt.Errorf("register: limits are new in 0.3, so operation %s cannot carry them in an earlier package", o.ID)
	}
	if l := o.Limits; l.MaxReplyBytes < 1 || l.MaxReplyBytes > MaxSessionBytes || l.TimeoutMS < 1 || l.TimeoutMS > MaxStepMS {
		return fmt.Errorf("register: operation %s limits %+v are outside max_reply_bytes 1..%d and timeout_ms 1..%d",
			o.ID, *l, MaxSessionBytes, MaxStepMS)
	}
	return nil
}

// validateRun applies the rules in Run's documentation.
func (p *Package) validateRun(r *Run, sources map[string]bool) error {
	if err := checkCommon(r.ID, "", r.Citations, r.Evidence, r.SideEffects, sources, false); err != nil {
		return err
	}
	if r.MaxTotalBytes < 1 || r.MaxTotalBytes > MaxSessionBytes {
		return fmt.Errorf("register: run %s max_total_bytes %d is outside 1..%d", r.ID, r.MaxTotalBytes, MaxSessionBytes)
	}
	if r.DeadlineMS < 1 || r.DeadlineMS > MaxDeadlineMS {
		return fmt.Errorf("register: run %s deadline_ms %d is outside 1..%d", r.ID, r.DeadlineMS, MaxDeadlineMS)
	}
	if len(r.Steps) == 0 || len(r.Steps) > MaxRunSteps {
		return fmt.Errorf("register: run %s has %d steps, want 1..%d", r.ID, len(r.Steps), MaxRunSteps)
	}
	at := map[string]int{}
	for i, id := range r.Steps {
		o := p.operation(id)
		switch {
		case o == nil:
			return fmt.Errorf("register: run %s step %q is not an operation", r.ID, id)
		case at[id] != 0:
			return fmt.Errorf("register: run %s sends %s twice", r.ID, id)
		case len(o.Params) != 0:
			return fmt.Errorf("register: run %s step %s has parameters; a step is a literal line", r.ID, id)
		case !o.InPhase(PhaseOperate):
			return fmt.Errorf("register: run %s step %s does not run in operate", r.ID, id)
		case !levelWithin(o.AccessLevel, MaxRunAccessLevel):
			return fmt.Errorf("register: run %s step %s needs access level %q, above %d", r.ID, id, o.AccessLevel, MaxRunAccessLevel)
		case o.Limits == nil:
			return fmt.Errorf("register: run %s step %s has no limits", r.ID, id)
		case o.Limits.MaxReplyBytes > r.MaxTotalBytes:
			return fmt.Errorf("register: run %s step %s max_reply_bytes %d is above the run's max_total_bytes %d", r.ID, id, o.Limits.MaxReplyBytes, r.MaxTotalBytes)
		case o.Limits.TimeoutMS > r.DeadlineMS:
			return fmt.Errorf("register: run %s step %s timeout_ms %d is above the run's deadline_ms %d", r.ID, id, o.Limits.TimeoutMS, r.DeadlineMS)
		}
		at[id] = i + 1
	}
	// The gate reads lead: every precondition and firmware condition is read
	// before any other line is sent, so a refusing setting stops the run before
	// it reads anything else.
	gate := map[string]bool{}
	for _, c := range p.Preconditions {
		gate[c.ReadBy] = true
	}
	for _, b := range p.Firmware.Branches {
		for _, c := range b.Conditions {
			gate[c.ReadBy] = true
		}
	}
	for id := range gate {
		if at[id] == 0 || at[id] > len(gate) {
			return fmt.Errorf("register: run %s must lead with the reads %s that gate it, and %s is not among its first %d steps", r.ID, sortedKeys(gate), id, len(gate))
		}
	}
	// Posture warnings are read in the run, and each step's context before it.
	for _, w := range p.Warnings {
		if at[w.ReadBy] == 0 {
			return fmt.Errorf("register: run %s does not send %s, which reads warning %s", r.ID, w.ReadBy, w.ID)
		}
	}
	for _, id := range r.Steps {
		for _, c := range p.ContextFor(id) {
			if at[c.ReadBy] == 0 || at[c.ReadBy] >= at[id] {
				return fmt.Errorf("register: run %s must send %s, which reads %s, before step %s", r.ID, c.ReadBy, c.Setting, id)
			}
		}
	}
	return nil
}

// levelWithin reports whether an access level is a decimal number no higher
// than max. A level that is not a number is never within: the order is not
// assumed.
func levelWithin(level string, max uint64) bool {
	n, err := strconv.ParseUint(level, 10, 8)
	return err == nil && n <= max
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func (p *Package) operation(id string) *Operation {
	for i := range p.Operations {
		if p.Operations[i].ID == id {
			return &p.Operations[i]
		}
	}
	return nil
}

func (o *Operation) validateTemplate() error {
	declared := map[string]*Param{}
	for i := range o.Params {
		pr := &o.Params[i]
		if !regexp.MustCompile(`^[a-z][a-z0-9_]*$`).MatchString(pr.Name) || declared[pr.Name] != nil {
			return fmt.Errorf("register: operation %s parameter %q is invalid or duplicated", o.ID, pr.Name)
		}
		declared[pr.Name] = pr
		switch pr.Kind {
		case ParamUint:
			if pr.Min == nil || pr.Max == nil || *pr.Min > *pr.Max || len(pr.Values) != 0 {
				return fmt.Errorf("register: operation %s parameter %s needs min <= max and no values", o.ID, pr.Name)
			}
		case ParamEnum:
			if len(pr.Values) == 0 || pr.Min != nil || pr.Max != nil {
				return fmt.Errorf("register: operation %s parameter %s needs values and no bounds", o.ID, pr.Name)
			}
			for _, v := range pr.Values {
				if !tokenRe.MatchString(v) {
					return fmt.Errorf("register: operation %s parameter %s value %q is not [A-Z0-9]+", o.ID, pr.Name, v)
				}
			}
		default:
			return fmt.Errorf("register: operation %s parameter %s has unknown kind %q", o.ID, pr.Name, pr.Kind)
		}
	}
	if o.Line == "" || strings.HasPrefix(o.Line, " ") || strings.HasSuffix(o.Line, " ") || strings.Contains(o.Line, "  ") {
		return fmt.Errorf("register: operation %s line %q is not single-space separated", o.ID, o.Line)
	}
	used := map[string]bool{}
	for i, tok := range strings.Split(o.Line, " ") {
		if m := paramRe.FindStringSubmatch(tok); m != nil {
			if declared[m[1]] == nil || used[m[1]] {
				return fmt.Errorf("register: operation %s uses undeclared or repeated parameter %q", o.ID, m[1])
			}
			if i == 0 {
				return fmt.Errorf("register: operation %s starts with a parameter", o.ID)
			}
			used[m[1]] = true
			continue
		}
		if !tokenRe.MatchString(tok) {
			return fmt.Errorf("register: operation %s token %q is not [A-Z0-9]+", o.ID, tok)
		}
	}
	if len(used) != len(declared) {
		return fmt.Errorf("register: operation %s declares a parameter its line does not use", o.ID)
	}
	return nil
}

// render produces the line for an operation from its template, or an error
// if any parameter is missing, extra or out of range. It does not apply the
// deny rules; Matcher.Render does.
func (o *Operation) render(args map[string]string) (string, error) {
	out := []string{}
	seen := 0
	for _, tok := range strings.Split(o.Line, " ") {
		m := paramRe.FindStringSubmatch(tok)
		if m == nil {
			out = append(out, tok)
			continue
		}
		v, ok := args[m[1]]
		if !ok {
			return "", fmt.Errorf("register: %s: parameter %s missing", o.ID, m[1])
		}
		if !o.param(m[1]).accepts(v) {
			return "", fmt.Errorf("register: %s: parameter %s value %q not allowed", o.ID, m[1], v)
		}
		out = append(out, v)
		seen++
	}
	if seen != len(args) {
		return "", fmt.Errorf("register: %s: unexpected parameters", o.ID)
	}
	return strings.Join(out, " "), nil
}

func (o *Operation) param(name string) *Param {
	for i := range o.Params {
		if o.Params[i].Name == name {
			return &o.Params[i]
		}
	}
	return nil
}

func (pr *Param) accepts(v string) bool {
	switch pr.Kind {
	case ParamUint:
		if v == "" || (len(v) > 1 && v[0] == '0') {
			return false
		}
		n, err := strconv.ParseUint(v, 10, 64)
		return err == nil && n >= *pr.Min && n <= *pr.Max
	case ParamEnum:
		for _, x := range pr.Values {
			if v == x {
				return true
			}
		}
	}
	return false
}

// sampleLines renders the operation at the boundary values of every
// parameter, for the deny-rule cross-check.
func (o *Operation) sampleLines() []string {
	lines := []string{""}
	for _, tok := range strings.Split(o.Line, " ") {
		vals := []string{tok}
		if m := paramRe.FindStringSubmatch(tok); m != nil {
			pr := o.param(m[1])
			if pr.Kind == ParamUint {
				vals = []string{strconv.FormatUint(*pr.Min, 10), strconv.FormatUint(*pr.Max, 10)}
			} else {
				vals = pr.Values
			}
		}
		var next []string
		for _, l := range lines {
			for _, v := range vals {
				if l == "" {
					next = append(next, v)
				} else {
					next = append(next, l+" "+v)
				}
			}
		}
		lines = next
	}
	return lines
}

func compileDeny(pattern string) (*regexp.Regexp, error) {
	if pattern == "" {
		return nil, fmt.Errorf("empty pattern")
	}
	return regexp.Compile(`^(?:` + pattern + `)$`)
}

// Decide applies the firmware allowlist to a firmware ID read from the
// device. It returns the branch rule only when the ID is listed exactly and
// its branch allows that version; the caller must then confirm every
// condition of the rule before collecting. Any other ID is refused.
func (f *Firmware) Decide(fid string) (*BranchRule, error) {
	for _, k := range f.Known {
		if k.FID != fid {
			continue
		}
		for i := range f.Branches {
			b := &f.Branches[i]
			if b.Branch != k.Branch {
				continue
			}
			if b.Status == BranchDeny {
				return nil, fmt.Errorf("register: firmware %s: branch %s is denied", fid, b.Branch)
			}
			if k.Version < b.MinVersion {
				return nil, fmt.Errorf("register: firmware %s: version %d is below branch %s minimum %d", fid, k.Version, b.Branch, b.MinVersion)
			}
			return b, nil
		}
		return nil, fmt.Errorf("register: firmware %s: no rule for branch %s", fid, k.Branch)
	}
	return nil, fmt.Errorf("register: firmware %q is not a known firmware ID", fid)
}
