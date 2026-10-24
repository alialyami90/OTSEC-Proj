package register

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"otsec.local/otsec/contracts/internal/strictjson"
)

// ContractID is the identifier every register package carries.
const ContractID = "otsec.register/0.1"

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
	Warnings       []PostureWarning `json:"warnings,omitempty"`
	Operations     []Operation      `json:"operations"`
	SessionControl []SessionLine    `json:"session_control"`
	Denied         []DenyRule       `json:"denied"`
	Firmware       Firmware         `json:"firmware"`
	Notes          []string         `json:"notes,omitempty"`
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
	Phases      []Phase    `json:"phases,omitempty"`
	AccessLevel string     `json:"access_level"`
	Citations   []Citation `json:"citations"`
	Evidence    Evidence   `json:"evidence"`
	SideEffects string     `json:"side_effects"`
	Notes       string     `json:"notes,omitempty"`
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
// (authz.RegisterSigningInput).
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
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return &p, nil
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
	if p.Contract != ContractID {
		return fmt.Errorf("register: contract %q, want %q", p.Contract, ContractID)
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
	if err := p.validateFirmware(sources, ids); err != nil {
		return err
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
