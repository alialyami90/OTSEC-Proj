package advisory

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"otsec.local/otsec/contracts/asset"
	"otsec.local/otsec/contracts/internal/strictjson"
)

// Identifier is the contract this reader writes and reads.
const Identifier = "otsec.advisory/0.1"

// Readable lists the set contracts this reader decodes.
var Readable = []string{Identifier}

// Limits (1.4).
const (
	// MaxSetPayload bounds the set's JSON bytes. The node stores the whole
	// signed file as one configuration record, so it stays at 1 MiB or less
	// while the set is one record (C5).
	MaxSetPayload = 1 << 20
	// MaxEnvelopeBytes is the base64 length of MaxSetPayload plus 1,024 bytes
	// for the envelope's other fields and whitespace. A test holds it under
	// the node's record cap less the record headroom.
	MaxEnvelopeBytes = (MaxSetPayload+2)/3*4 + 1024
	MaxEntries       = 2048

	MaxSources       = 16
	MaxProducts      = 64
	MaxRanges        = 64
	MaxVersions      = 256
	MaxPreconditions = 32
	MaxMitigations   = 16
	MaxValues        = 64

	MaxTitleBytes     = 256
	MaxPublisherBytes = 128
	MaxRefBytes       = 128 // ref, key and each value
	MaxURLBytes       = 512
)

// Purpose is a closed list.
type Purpose string

const (
	PurposeRelease Purpose = "release"
	PurposeTest    Purpose = "test"
)

// SourceKind is a closed list.
type SourceKind string

const (
	SourceVendorAdvisory   SourceKind = "vendor-advisory"
	SourceCVE              SourceKind = "cve"
	SourceNationalAdvisory SourceKind = "national-advisory"
	SourceOther            SourceKind = "other"
)

// Scheme names how versions compare. Closed list: a reader that meets
// another refuses the set. The comparison rules are the matcher's (C12).
type Scheme string

const (
	SchemeSELFID Scheme = "sel-fid"
	SchemeExact  Scheme = "exact"
)

// ItemKind is what a precondition or mitigation reads. Closed list.
type ItemKind string

const (
	KindSetting   ItemKind = "setting"   // a C9 setting name
	KindService   ItemKind = "service"   // a service seen on the asset
	KindAttribute ItemKind = "attribute" // a C1 0.3 identity attribute
	KindControl   ItemKind = "control"   // a recorded network control, mitigations only
)

// Op is a closed list.
type Op string

const (
	OpIn      Op = "in"
	OpNotIn   Op = "not-in"
	OpPresent Op = "present"
	OpAbsent  Op = "absent"
)

// ReservedFirmwareVersion is the precondition name the matcher uses for an
// FID it cannot place (C4). No entry may use it.
const ReservedFirmwareVersion = "firmware-version"

// Set is the signed payload (1.2).
type Set struct {
	Contract  string  `json:"contract"`
	SetID     string  `json:"set_id"`
	Version   uint64  `json:"version"`
	IssuedAt  string  `json:"issued_at"`
	Purpose   Purpose `json:"purpose"`
	Publisher string  `json:"publisher"`
	Entries   []Entry `json:"entries"`
}

// Entry is one advisory (1.3).
type Entry struct {
	ID            string     `json:"id"`
	TestOnly      bool       `json:"test_only"`
	Title         string     `json:"title"`
	Sources       []Source   `json:"sources"`
	Affected      []Affected `json:"affected"`
	Preconditions []Item     `json:"preconditions,omitempty"`
	Mitigations   []Item     `json:"mitigations,omitempty"`
}

// Source is one citation.
type Source struct {
	Kind      SourceKind `json:"kind"`
	Ref       string     `json:"ref"`
	URL       string     `json:"url,omitempty"`
	Published string     `json:"published"`
	Retrieved string     `json:"retrieved,omitempty"`
	SHA256    string     `json:"sha256,omitempty"`
}

// Affected is one product and the versions of it the entry covers.
type Affected struct {
	Vendor   string   `json:"vendor"`
	Product  string   `json:"product"`
	Scheme   Scheme   `json:"scheme"`
	Ranges   []Range  `json:"ranges,omitempty"`
	Versions []string `json:"versions,omitempty"`
}

// Range is half-open: Introduced is inclusive and Fixed exclusive, and
// either may be empty.
type Range struct {
	Introduced string `json:"introduced,omitempty"`
	Fixed      string `json:"fixed,omitempty"`
}

// Item is one precondition or mitigation.
type Item struct {
	Name   string   `json:"name"`
	Kind   ItemKind `json:"kind"`
	Key    string   `json:"key"`
	Op     Op       `json:"op"`
	Values []string `json:"values,omitempty"`
}

var (
	setIDRe    = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)
	entryIDRe  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	itemNameRe = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,63}$`)
	controlRe  = regexp.MustCompile(`^(tcp|udp)/([1-9][0-9]{0,4})$`)
	selVRe     = regexp.MustCompile(`^R([0-9]{3})-V([0-9]+)$`)
	selFIDRe   = regexp.MustCompile(`^SEL-[0-9A-Z]+-R[0-9]{3}-V[0-9]+-Z[0-9]{6}-D[0-9]{8}$`)
	// selProductRe is a FID's product, as the device-read model prints it
	// (C1 on #446, C6's proposal).
	selProductRe = regexp.MustCompile(`^SEL-[0-9A-Z]+$`)
	sha256Re     = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// ErrInvalid wraps every Validate and Decode failure. Its text names the
// rule and, for an entry, the entry's id, and nothing else from the file
// (1.5 step 4).
var ErrInvalid = errors.New("advisory: invalid set")

func invalid(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, a...))
}

// Decode parses a set's payload strictly (unknown fields, duplicate keys and
// trailing data are refused) and runs Validate.
func Decode(payload []byte) (*Set, error) {
	if len(payload) > MaxSetPayload {
		return nil, invalid("payload is over %d bytes", MaxSetPayload)
	}
	var s Set
	if err := strictjson.Decode(payload, &s); err != nil {
		return nil, invalid("payload does not decode strictly")
	}
	if err := s.Validate(); err != nil {
		return nil, err
	}
	return &s, nil
}

// Validate checks every rule in 1.2 to 1.4. The first failure is returned.
func (s *Set) Validate() error {
	if s.Contract != Identifier {
		return invalid("contract is not one this reader decodes")
	}
	if !setIDRe.MatchString(s.SetID) {
		return invalid("set_id is not a token")
	}
	if s.Version < 1 {
		return invalid("version is below 1")
	}
	if !isUTC(s.IssuedAt) {
		return invalid("issued_at is not RFC 3339 UTC with Z")
	}
	if s.Purpose != PurposeRelease && s.Purpose != PurposeTest {
		return invalid("purpose is not release or test")
	}
	if len(s.Publisher) > MaxPublisherBytes {
		return invalid("publisher is over %d bytes", MaxPublisherBytes)
	}
	if len(s.Entries) > MaxEntries {
		return invalid("more than %d entries", MaxEntries)
	}
	seen := make(map[string]bool, len(s.Entries))
	for i := range s.Entries {
		e := &s.Entries[i]
		if !entryIDRe.MatchString(e.ID) {
			return invalid("entry %d: id is not in its form", i)
		}
		if seen[e.ID] {
			return invalid("entry %s: id appears twice", e.ID)
		}
		seen[e.ID] = true
		if e.TestOnly && s.Purpose == PurposeRelease {
			return invalid("entry %s: test_only in a release set", e.ID)
		}
		if err := e.validate(); err != nil {
			return invalid("entry %s: %s", e.ID, err)
		}
	}
	return nil
}

func (e *Entry) validate() error {
	if len(e.Title) > MaxTitleBytes {
		return fmt.Errorf("title is over %d bytes", MaxTitleBytes)
	}
	if len(e.Sources) == 0 {
		return errors.New("no published source")
	}
	if len(e.Sources) > MaxSources {
		return fmt.Errorf("more than %d sources", MaxSources)
	}
	for i, src := range e.Sources {
		if err := src.validate(); err != nil {
			return fmt.Errorf("source %d: %s", i, err)
		}
	}
	if len(e.Affected) == 0 {
		return errors.New("no affected product")
	}
	if len(e.Affected) > MaxProducts {
		return fmt.Errorf("more than %d products", MaxProducts)
	}
	for i, a := range e.Affected {
		if err := a.validate(); err != nil {
			return fmt.Errorf("affected %d: %s", i, err)
		}
	}
	if len(e.Preconditions) > MaxPreconditions {
		return fmt.Errorf("more than %d preconditions", MaxPreconditions)
	}
	if len(e.Mitigations) > MaxMitigations {
		return fmt.Errorf("more than %d mitigations", MaxMitigations)
	}
	names := make(map[string]bool)
	for i, it := range e.Preconditions {
		if err := it.validate(false, names); err != nil {
			return fmt.Errorf("precondition %d: %s", i, err)
		}
	}
	for i, it := range e.Mitigations {
		if err := it.validate(true, names); err != nil {
			return fmt.Errorf("mitigation %d: %s", i, err)
		}
	}
	return nil
}

func (src Source) validate() error {
	switch src.Kind {
	case SourceVendorAdvisory, SourceCVE, SourceNationalAdvisory, SourceOther:
	default:
		return errors.New("kind is not in the closed list")
	}
	if src.Ref == "" || len(src.Ref) > MaxRefBytes {
		return fmt.Errorf("ref is empty or over %d bytes", MaxRefBytes)
	}
	if src.URL != "" && (len(src.URL) > MaxURLBytes || !strings.HasPrefix(src.URL, "https://")) {
		return fmt.Errorf("url is not https or is over %d bytes", MaxURLBytes)
	}
	if !isDate(src.Published) {
		return errors.New("published is not a date")
	}
	if src.Retrieved != "" && !isDate(src.Retrieved) {
		return errors.New("retrieved is not a date")
	}
	if src.SHA256 != "" && !sha256Re.MatchString(src.SHA256) {
		return errors.New("sha256 is not 64 lowercase hex digits")
	}
	return nil
}

func (a Affected) validate() error {
	if a.Vendor == "" || a.Product == "" {
		return errors.New("vendor or product is empty")
	}
	if len(a.Ranges) == 0 && len(a.Versions) == 0 {
		return errors.New("no range and no version")
	}
	if len(a.Ranges) > MaxRanges {
		return fmt.Errorf("more than %d ranges", MaxRanges)
	}
	if len(a.Versions) > MaxVersions {
		return fmt.Errorf("more than %d versions", MaxVersions)
	}
	switch a.Scheme {
	case SchemeSELFID:
		// The matcher compares product with the device-read model exactly,
		// so a typo here would make every device not-applicable without a
		// word. It is refused at load instead (C1 on #446).
		if !selProductRe.MatchString(a.Product) {
			return errors.New("sel-fid product is not SEL-<model>")
		}
		for i, r := range a.Ranges {
			if err := r.validateSELFID(); err != nil {
				return fmt.Errorf("range %d: %s", i, err)
			}
		}
		for i, v := range a.Versions {
			if !selFIDRe.MatchString(v) {
				return fmt.Errorf("version %d is not a full FID", i)
			}
			if !strings.HasPrefix(v, a.Product+"-R") {
				return fmt.Errorf("version %d is a FID of another product", i)
			}
		}
	case SchemeExact:
		// Exact compares strings and has no order, so a range under it can
		// only be the empty one, which covers every version.
		for i, r := range a.Ranges {
			if r.Introduced != "" || r.Fixed != "" {
				return fmt.Errorf("range %d has an endpoint, which exact cannot order", i)
			}
		}
		for i, v := range a.Versions {
			if v == "" || len(v) > MaxRefBytes {
				return fmt.Errorf("version %d is empty or over %d bytes", i, MaxRefBytes)
			}
		}
	default:
		return errors.New("scheme is not in the closed list")
	}
	return nil
}

// validateSELFID applies the per-branch rule: endpoints are R<branch>-V<n>,
// and a range with both has them on one branch with introduced's V below
// fixed's.
func (r Range) validateSELFID() error {
	var ib, fb string
	var iv, fv uint64
	var err error
	if r.Introduced != "" {
		if ib, iv, err = selBranchV(r.Introduced); err != nil {
			return fmt.Errorf("introduced: %s", err)
		}
	}
	if r.Fixed != "" {
		if fb, fv, err = selBranchV(r.Fixed); err != nil {
			return fmt.Errorf("fixed: %s", err)
		}
	}
	if r.Introduced != "" && r.Fixed != "" {
		if ib != fb {
			return errors.New("introduced and fixed are on different branches")
		}
		if iv >= fv {
			return errors.New("introduced is not below fixed")
		}
	}
	return nil
}

func selBranchV(s string) (string, uint64, error) {
	m := selVRe.FindStringSubmatch(s)
	if m == nil {
		return "", 0, errors.New("not R<branch>-V<n>")
	}
	v, err := strconv.ParseUint(m[2], 10, 64)
	if err != nil {
		return "", 0, errors.New("V is out of range")
	}
	return m[1], v, nil
}

func (it Item) validate(mitigation bool, names map[string]bool) error {
	if !itemNameRe.MatchString(it.Name) {
		return errors.New("name is not in its form")
	}
	if it.Name == ReservedFirmwareVersion {
		return errors.New("name is reserved for the matcher")
	}
	if names[it.Name] {
		return errors.New("name appears twice in the entry")
	}
	names[it.Name] = true
	switch it.Op {
	case OpIn, OpNotIn:
		if len(it.Values) == 0 || len(it.Values) > MaxValues {
			return fmt.Errorf("in and not-in take 1 to %d values", MaxValues)
		}
		for i, v := range it.Values {
			if len(v) > MaxRefBytes {
				return fmt.Errorf("value %d is over %d bytes", i, MaxRefBytes)
			}
		}
	case OpPresent, OpAbsent:
		if len(it.Values) != 0 {
			return errors.New("present and absent take no values")
		}
	default:
		return errors.New("op is not in the closed list")
	}
	if it.Key == "" || len(it.Key) > MaxRefBytes {
		return fmt.Errorf("key is empty or over %d bytes", MaxRefBytes)
	}
	switch it.Kind {
	case KindSetting, KindService:
	case KindAttribute:
		// An attribute is a C1 identity attribute (1.3). BFID and the IEC
		// 61850 configVersion, which the matcher reads but does not compare
		// in 0.1, are not C1 names, so they are refused here too (C4 on #446).
		if !asset.ValidAttributeName(it.Key) {
			return errors.New("attribute key is not a C1 attribute name")
		}
	case KindControl:
		if !mitigation {
			return errors.New("control is for mitigations only")
		}
		if it.Op != OpPresent {
			return errors.New("control takes op present only")
		}
		m := controlRe.FindStringSubmatch(it.Key)
		if m == nil {
			return errors.New("control key is not <tcp|udp>/<port>")
		}
		if p, _ := strconv.Atoi(m[2]); p > 65535 {
			return errors.New("control port is over 65535")
		}
	default:
		return errors.New("kind is not in the closed list")
	}
	return nil
}

func isUTC(s string) bool {
	if !strings.HasSuffix(s, "Z") {
		return false
	}
	_, err := time.Parse(time.RFC3339Nano, s)
	return err == nil
}

func isDate(s string) bool {
	_, err := time.Parse(time.DateOnly, s)
	return err == nil
}
