package netobs

import (
	"bytes"
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"otsec.local/otsec/contracts/internal/strictjson"
	"otsec.local/otsec/contracts/version"
)

// BaselineIdentifier is the network baseline document's schema, its first
// field (C13 §8).
const BaselineIdentifier = "otsec.netbaseline/0.1"

var baselineSelf = version.ID{Name: "netbaseline", Major: 0, Minor: 1}

// MaxBaselineBytes bounds a network baseline document, the learner's draft
// included. It is C10's MaxBytes, set at or below the configuration class's
// record cap less headroom, so a baseline that fits is never refused there.
const MaxBaselineBytes = 512 << 10

// Tie grace bounds (baseline note §4, §5): D4's choice. The default is 30.
const (
	DefaultTieGraceS = 30
	MaxTieGraceS     = 3600
)

// Baseline is the network baseline document (C13 §8, baseline note §2):
// one per sensor, learned from observations, with AuthorizedWriters filled
// in by a person and never learned. Its stored form is canonical (Encode):
// a draft has no writers; the accepted document differs from its draft only
// in AuthorizedWriters.
type Baseline struct {
	Schema            string             `json:"schema"`
	SensorID          string             `json:"sensor_id"`
	Version           int64              `json:"version"`
	FunctionTable     string             `json:"function_table"`
	Period            Period             `json:"period"`
	Params            BaselineParams     `json:"params"`
	Pairs             []Pair             `json:"pairs"`
	Services          []BaselineService  `json:"services"`
	Functions         []BaselineFunction `json:"functions"`
	Addresses         []Address          `json:"addresses"`
	AuthorizedWriters []Writer           `json:"authorized_writers"`
}

// Period is the learning period and what it folded. Observations counts
// the observations folded, by kind; Degraded and PlatformSession count
// those left out because the coverage was degraded or they were tied to
// the node's own sessions (baseline note §2.1).
type Period struct {
	StartUTC        string `json:"start_utc"`
	EndUTC          string `json:"end_utc"`
	Observations    Counts `json:"observations"`
	Degraded        int64  `json:"degraded"`
	PlatformSession int64  `json:"platform_session"`
}

// Counts are observation counts by kind.
type Counts struct {
	Flow      int64 `json:"flow"`
	Service   int64 `json:"service"`
	Function  int64 `json:"function"`
	Insecure  int64 `json:"insecure"`
	Encrypted int64 `json:"encrypted"`
	Identity  int64 `json:"identity"`
	Undecoded int64 `json:"undecoded"`
}

// BaselineParams are the rules' parameters, recorded in the baseline as
// C10 records its own.
type BaselineParams struct {
	TieGraceS       int64 `json:"tie_grace_s"`
	CoalesceWindowS int64 `json:"coalesce_window_s"`
}

// An endpoint is an asset ID, or "addr:<ip>" for an address that resolves
// to no asset (baseline note §2.1).

// Pair is a learned (client, server, l4, server port, protocol).
type Pair struct {
	Client   string `json:"client"`
	Server   string `json:"server"`
	L4       string `json:"l4"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
}

// BaselineService is a learned service. Basis "port" is kept apart from
// "content" and marked as such.
type BaselineService struct {
	Server   string `json:"server"`
	L4       string `json:"l4"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	Basis    string `json:"basis"`
}

// BaselineFunction is a learned (pair, code, sub, objects).
type BaselineFunction struct {
	Pair
	Code    int      `json:"code"`
	Sub     *int     `json:"sub,omitempty"`
	Objects []string `json:"objects"`
}

// Address is an endpoint's address as seen, with the VLANs (0 for
// untagged) and PRP LANs it was seen on, for own-session-unseen's coverage
// test.
type Address struct {
	IP       string   `json:"ip"`
	Endpoint string   `json:"endpoint"`
	VLANs    []int    `json:"vlans"`
	LANs     []string `json:"lans"`
}

// Writer is an authorized writer: a person's entry, never learned.
type Writer struct {
	Client string `json:"client"`
	Server string `json:"server"`
	Class  string `json:"class"`
}

// ValidEndpoint reports whether s is an asset ID or "addr:" and a
// canonical IP address.
func ValidEndpoint(s string) bool {
	if ValidUUID(s) {
		return true
	}
	ip, ok := strings.CutPrefix(s, "addr:")
	if !ok {
		return false
	}
	c := &checker{}
	c.addr("", ip)
	return len(c.errs) == 0
}

func (c *checker) endpoint(field, s string) {
	if !ValidEndpoint(s) {
		c.fail(CodeForm, field, "%q is not an asset ID or addr:<ip>", s)
	}
}

func (p *Pair) check(c *checker, f string) {
	c.endpoint(f+".client", p.Client)
	c.endpoint(f+".server", p.Server)
	if p.L4 != "tcp" && p.L4 != "udp" {
		c.fail(CodeForm, f+".l4", "%q is not tcp or udp", p.L4)
	}
	if p.Port < 0 || p.Port > 65535 {
		c.fail(CodeRange, f+".port", "%d not in [0, 65535]", p.Port)
	}
	c.token(f+".protocol", p.Protocol)
}

func comparePair(a, b Pair) int {
	return cmp.Or(strings.Compare(a.Client, b.Client), strings.Compare(a.Server, b.Server),
		strings.Compare(a.L4, b.L4), cmp.Compare(a.Port, b.Port), strings.Compare(a.Protocol, b.Protocol))
}

func compareService(a, b BaselineService) int {
	return cmp.Or(strings.Compare(a.Server, b.Server), strings.Compare(a.L4, b.L4), cmp.Compare(a.Port, b.Port),
		strings.Compare(a.Protocol, b.Protocol), strings.Compare(a.Basis, b.Basis))
}

func compareSub(a, b *int) int {
	switch {
	case a == nil && b == nil:
		return 0
	case a == nil:
		return -1
	case b == nil:
		return 1
	}
	return cmp.Compare(*a, *b)
}

func compareFunction(a, b BaselineFunction) int {
	return cmp.Or(comparePair(a.Pair, b.Pair), cmp.Compare(a.Code, b.Code), compareSub(a.Sub, b.Sub), slices.Compare(a.Objects, b.Objects))
}

func compareAddress(a, b Address) int {
	return cmp.Or(strings.Compare(a.IP, b.IP), strings.Compare(a.Endpoint, b.Endpoint))
}

func compareWriter(a, b Writer) int {
	return cmp.Or(strings.Compare(a.Client, b.Client), strings.Compare(a.Server, b.Server), strings.Compare(a.Class, b.Class))
}

// SortBaseline sorts every list of b into the canonical order and removes
// repeats, so a learner can fold in any order and Encode the result.
func SortBaseline(b *Baseline) {
	sortUniq(&b.Pairs, comparePair)
	sortUniq(&b.Services, compareService)
	for i := range b.Functions {
		sortUniq(&b.Functions[i].Objects, strings.Compare)
	}
	sortUniq(&b.Functions, compareFunction)
	for i := range b.Addresses {
		sortUniq(&b.Addresses[i].VLANs, cmp.Compare[int])
		sortUniq(&b.Addresses[i].LANs, strings.Compare)
	}
	sortUniq(&b.Addresses, compareAddress)
	sortUniq(&b.AuthorizedWriters, compareWriter)
}

func sortUniq[T any](s *[]T, f func(a, b T) int) {
	slices.SortFunc(*s, f)
	*s = slices.CompactFunc(*s, func(a, b T) bool { return f(a, b) == 0 })
}

// ascending fails c unless list is strictly increasing under f.
func ascending[T any](c *checker, field string, list []T, f func(a, b T) int) {
	for i := 1; i < len(list); i++ {
		if f(list[i-1], list[i]) >= 0 {
			c.fail(CodeOrder, fmt.Sprintf("%s[%d]", field, i), "sorted, without repeats")
		}
	}
}

// Validate checks every rule of C13 §8 and the baseline note §2 that holds
// on one document, including the canonical order of every list.
func (b *Baseline) Validate() error {
	c := &checker{}
	if got, err := version.Parse(b.Schema); err != nil || !baselineSelf.Accepts(got) {
		c.fail(CodeSchema, "schema", "%q is not %s or another 0.x minor of it", b.Schema, BaselineIdentifier)
	}
	c.uuid("sensor_id", b.SensorID)
	if b.Version < 1 {
		c.fail(CodeRange, "version", "%d is below 1", b.Version)
	}
	c.table("function_table", b.FunctionTable)
	start, ok1 := c.utc("period.start_utc", b.Period.StartUTC)
	end, ok2 := c.utc("period.end_utc", b.Period.EndUTC)
	if ok1 && ok2 && end.Before(start) {
		c.fail(CodeOrder, "period.end_utc", "before start_utc")
	}
	n := b.Period.Observations
	for _, x := range []int64{n.Flow, n.Service, n.Function, n.Insecure, n.Encrypted, n.Identity, n.Undecoded, b.Period.Degraded, b.Period.PlatformSession} {
		if x < 0 {
			c.fail(CodeRange, "period", "counts are not negative")
			break
		}
	}
	if p := b.Params; p.TieGraceS < 1 || p.TieGraceS > MaxTieGraceS {
		c.fail(CodeRange, "params.tie_grace_s", "%d not in [1, %d]", p.TieGraceS, MaxTieGraceS)
	}
	if p := b.Params; p.CoalesceWindowS < MinCoalesceWindowS || p.CoalesceWindowS > MaxCoalesceWindowS {
		c.fail(CodeRange, "params.coalesce_window_s", "%d not in [%d, %d]", p.CoalesceWindowS, MinCoalesceWindowS, MaxCoalesceWindowS)
	}
	for i := range b.Pairs {
		b.Pairs[i].check(c, fmt.Sprintf("pairs[%d]", i))
	}
	ascending(c, "pairs", b.Pairs, comparePair)
	for i, s := range b.Services {
		f := fmt.Sprintf("services[%d]", i)
		(&Pair{Client: s.Server, Server: s.Server, L4: s.L4, Port: s.Port, Protocol: s.Protocol}).check(c, f)
		if s.Basis != "content" && s.Basis != "port" {
			c.fail(CodeForm, f+".basis", "%q is not content or port", s.Basis)
		}
	}
	ascending(c, "services", b.Services, compareService)
	for i, fn := range b.Functions {
		f := fmt.Sprintf("functions[%d]", i)
		fn.Pair.check(c, f)
		if fn.Code < 0 || fn.Code > 255 {
			c.fail(CodeRange, f+".code", "%d not in [0, 255]", fn.Code)
		}
		// sub as on an observation (C13 §4.3): only on Modbus 8 and 43,
		// in range for its code, and possibly absent (D1 on #549).
		switch {
		case fn.Sub == nil:
		case fn.Protocol != "modbus" || (fn.Code != 8 && fn.Code != 43):
			c.fail(CodeConflict, f+".sub", "only on Modbus 8 and 43")
		case fn.Code == 8 && (*fn.Sub < 0 || *fn.Sub > 65535):
			c.fail(CodeRange, f+".sub", "Modbus 8's sub-function, in [0, 65535]")
		case fn.Code == 43 && (*fn.Sub < 0 || *fn.Sub > 255):
			c.fail(CodeRange, f+".sub", "Modbus 43's MEI type, in [0, 255]")
		}
		if len(fn.Objects) > MaxObjects {
			c.fail(CodeRange, f+".objects", "%d, above %d", len(fn.Objects), MaxObjects)
		}
		for j, ob := range fn.Objects {
			if !objectForm.MatchString(ob) {
				c.fail(CodeForm, fmt.Sprintf("%s.objects[%d]", f, j), "%q is not g<group>v<variation>", ob)
			}
		}
		ascending(c, f+".objects", fn.Objects, strings.Compare)
	}
	ascending(c, "functions", b.Functions, compareFunction)
	for i, a := range b.Addresses {
		f := fmt.Sprintf("addresses[%d]", i)
		c.addr(f+".ip", a.IP)
		c.endpoint(f+".endpoint", a.Endpoint)
		if ip, ok := strings.CutPrefix(a.Endpoint, "addr:"); ok && ip != a.IP {
			c.fail(CodeConflict, f+".endpoint", "an unresolved endpoint is its own address")
		}
		for _, v := range a.VLANs {
			if v < 0 || v > 4094 {
				c.fail(CodeRange, f+".vlans", "%d not in [0, 4094]; 0 is untagged", v)
			}
		}
		ascending(c, f+".vlans", a.VLANs, cmp.Compare[int])
		for _, l := range a.LANs {
			if l != "a" && l != "b" {
				c.fail(CodeForm, f+".lans", "%q is not a or b", l)
			}
		}
		ascending(c, f+".lans", a.LANs, strings.Compare)
	}
	ascending(c, "addresses", b.Addresses, compareAddress)
	for i, w := range b.AuthorizedWriters {
		f := fmt.Sprintf("authorized_writers[%d]", i)
		c.endpoint(f+".client", w.Client)
		c.endpoint(f+".server", w.Server)
		if w.Class != ClassWrite && w.Class != ClassControl {
			c.fail(CodeForm, f+".class", "%q is not %s or %s", w.Class, ClassWrite, ClassControl)
		}
	}
	ascending(c, "authorized_writers", b.AuthorizedWriters, compareWriter)
	return c.err()
}

// Encode validates b and encodes it canonically, as it is stored and
// hashed: json.Marshal of the Go type, fields in declared order, no
// insignificant whitespace, every list sorted without repeats, and an
// empty list as [] (C13 §8). It refuses a document above MaxBaselineBytes.
func (b *Baseline) Encode() ([]byte, error) {
	if err := b.Validate(); err != nil {
		return nil, err
	}
	e := *b
	e.Pairs = nonNil(e.Pairs)
	e.Services = nonNil(e.Services)
	e.Addresses = slices.Clone(nonNil(e.Addresses))
	for i := range e.Addresses {
		e.Addresses[i].VLANs = nonNil(e.Addresses[i].VLANs)
		e.Addresses[i].LANs = nonNil(e.Addresses[i].LANs)
	}
	e.Functions = slices.Clone(nonNil(e.Functions))
	for i := range e.Functions {
		e.Functions[i].Objects = nonNil(e.Functions[i].Objects)
	}
	e.AuthorizedWriters = nonNil(e.AuthorizedWriters)
	out, err := json.Marshal(&e)
	if err != nil {
		return nil, &Error{Code: CodeForm, Field: "baseline", Detail: err.Error()}
	}
	if len(out) > MaxBaselineBytes {
		return nil, &Error{Code: CodeRange, Field: "baseline", Detail: fmt.Sprintf("%d bytes encoded, above %d", len(out), MaxBaselineBytes)}
	}
	return out, nil
}

func nonNil[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

// DecodeBaseline reads one stored network baseline and validates it. This
// minor or an earlier one is read strictly; a later 0.x minor's added
// fields are ignored. Reading does not check the encoding is canonical:
// IsCanonical does, for adoption.
func DecodeBaseline(b []byte) (*Baseline, error) {
	if len(b) > MaxBaselineBytes {
		return nil, &Error{Code: CodeRange, Field: "baseline", Detail: fmt.Sprintf("%d bytes, above %d", len(b), MaxBaselineBytes)}
	}
	var r Baseline
	if err := strictjson.Forward(b, &r); err != nil {
		return nil, &Error{Code: CodeDecode, Field: "baseline", Detail: err.Error()}
	}
	if got, err := version.Parse(r.Schema); err == nil && got.Name == baselineSelf.Name && got.Minor <= baselineSelf.Minor {
		r = Baseline{}
		if err := strictjson.Decode(b, &r); err != nil {
			return nil, &Error{Code: CodeDecode, Field: "baseline", Detail: err.Error()}
		}
	}
	return &r, r.Validate()
}

// IsCanonical reports whether b is a valid network baseline in canonical
// encoding: decoded strictly and encoded again, it gives the same bytes
// (C13 §8). The node adopts only canonical bytes (baseline note §2.3).
//
// It does not pin the minor: a document labelled with another 0.x minor
// that decodes strictly is canonical too. Adoption pins it through the
// draft, which OnlyWritersAdded compares byte for byte (D5 on #549).
func IsCanonical(b []byte) bool {
	if len(b) > MaxBaselineBytes {
		return false
	}
	var r Baseline
	if err := strictjson.Decode(b, &r); err != nil {
		return false
	}
	out, err := r.Encode()
	return err == nil && bytes.Equal(out, b)
}

// Digest is a stored document's hash: "sha256:" and the hex SHA-256 of its
// exact bytes, as C9 and C10 hash theirs.
func Digest(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// OnlyWritersAdded reports whether accepted is draft with authorized
// writers filled in and nothing else changed: both are canonical, and
// accepted decoded, with its writers cleared and encoded again, is draft
// byte for byte (C7 0.10 §1.2's last check; D5 on #549). Equal bytes pass,
// the case where the person added no writer. It does not check the
// digests, the sensor or the size of a file read from disk; the node does.
func OnlyWritersAdded(draft, accepted []byte) bool {
	if !IsCanonical(draft) || !IsCanonical(accepted) {
		return false
	}
	b, err := DecodeBaseline(accepted)
	if err != nil {
		return false
	}
	b.AuthorizedWriters = nil
	again, err := b.Encode()
	return err == nil && bytes.Equal(again, draft)
}
