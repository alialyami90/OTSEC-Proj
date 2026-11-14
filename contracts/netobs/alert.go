package netobs

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"otsec.local/otsec/contracts/event"
	"otsec.local/otsec/contracts/version"
)

// HealthAlert is the C4 health type of a network alert (C13 §7.1).
const HealthAlert = event.HealthNetobsAlert

// MaxAlertBytes bounds an alert's Health body encoded as JSON. The worst
// alert Validate accepts is pinned by TestWorstAlertFits, with its capture,
// under the smallest record cap C5 allows.
const MaxAlertBytes = 24 << 10

// ClockCapture is an alert's clock: the sensor host's capture clock.
const ClockCapture = "capture"

// Rule is a detector rule (baseline note §4). Closed.
type Rule string

const (
	RuleUnknownPair             Rule = "unknown-pair"
	RuleNewService              Rule = "new-service"
	RuleNewFunction             Rule = "new-function"
	RuleUnauthorizedWrite       Rule = "unauthorized-write"
	RuleOwnSessionOutsideRecord Rule = "own-session-outside-record"
	RuleNodeAddressSpoofed      Rule = "node-address-spoofed"
	RuleOwnSessionUnseen        Rule = "own-session-unseen"
	RuleUnresolvedAddress       Rule = "unresolved-address"
	RuleSAFailed                Rule = "sa-failed"
	// RuleOwnSessionMismatch is new in 0.3 (CH-51): a tied flow whose
	// counts exceed its run's profile, or could not be judged. An alert of
	// a minor below 0.3 with it is refused, as a 0.2 reader refuses it.
	RuleOwnSessionMismatch Rule = "own-session-mismatch"
)

// Rules lists every Rule.
var Rules = []Rule{RuleUnknownPair, RuleNewService, RuleNewFunction, RuleUnauthorizedWrite,
	RuleOwnSessionOutsideRecord, RuleNodeAddressSpoofed, RuleOwnSessionUnseen, RuleUnresolvedAddress, RuleSAFailed,
	RuleOwnSessionMismatch}

// BaselineFree are the rules that run before any baseline is acknowledged
// (D4-68 ruling 10; CH-51). The other five judge against the acknowledged
// baseline.
var BaselineFree = []Rule{RuleOwnSessionOutsideRecord, RuleNodeAddressSpoofed, RuleOwnSessionUnseen, RuleSAFailed,
	RuleOwnSessionMismatch}

// ruleParams are the parameters each rule's alert shows, in order.
// own-session-mismatch shows none (CH-51, D1's ruling 5).
var ruleParams = map[Rule][]string{
	RuleUnknownPair: nil, RuleNewService: nil, RuleNewFunction: nil, RuleUnauthorizedWrite: nil,
	RuleOwnSessionOutsideRecord: {"tie_grace_s"}, RuleNodeAddressSpoofed: nil,
	RuleOwnSessionUnseen: {"tie_grace_s"}, RuleUnresolvedAddress: nil, RuleSAFailed: nil,
	RuleOwnSessionMismatch: nil,
}

// RuleParams returns the parameters rule r's alert shows, in order.
func RuleParams(r Rule) []string { return slices.Clone(ruleParams[r]) }

// Param is one parameter as the alert shows it: a decimal value.
type Param struct {
	Name  string
	Value string
}

// Cite is one cited observation's citation in an alert: its capture and up
// to MaxAlertFramesPerFlow of its frames in citation order, whichever flows
// they belong to (C13 0.2 CH-50), shown as "<capture_id> <n>=<sha256> ...".
type Cite struct {
	CaptureID string      `json:"capture_id"`
	Frames    []CiteFrame `json:"frames"`
}

// CiteFrame is one cited frame.
type CiteFrame struct {
	N      int64  `json:"n"`
	SHA256 string `json:"sha256"`
}

// Alert is a network alert, carried as a C4 telemetry-health event of type
// HealthAlert (C13 §7.1). It is the node's, never the sensor's.
type Alert struct {
	Schema  string
	Rule    Rule
	AssetID string // an asset ID, or AssetUnresolved: the coalescing key's asset
	// Baseline is the acknowledged network baseline's hash ("sha256:<hex>")
	// and BaselineVersion its version. A baseline-free rule raised before
	// any acknowledgement has neither.
	Baseline        string
	BaselineVersion int64
	KeyText         string
	Params          []Param
	BaselineValue   string
	Observation     string
	Clock           string
	// AtUTC is the triggering frame's capture time: for a summary, the last
	// hit's. WindowStartUTC is when the coalescing window began.
	AtUTC          string
	WindowStartUTC string
	// Hits counts the window's hits on the key: 1 on the first alert.
	// Sources counts their distinct source addresses.
	Hits    int64
	Sources int64
	// Related are the observation event IDs of the first MaxRelated hits;
	// RelatedTotal is Hits. own-session-unseen has none.
	Related      []event.EventID
	RelatedTotal int64
	// Cites are up to MaxAlertFlows flows; Capture is the alert's own C5
	// capture's SHA-256. own-session-unseen cites nothing and has none.
	Cites   []Cite
	Capture string
	// FramesMissing counts the cited frames whose bytes the node no longer
	// held, so the capture leaves them out. The cites still list every
	// frame, and the alert is never dropped for it (C13 §4.2, §7.1).
	FramesMissing int64
	Coverage      Coverage
	// Assets and AssetsTotal name what an alert under an aggregate key
	// covers: up to MaxAggregateAssets asset IDs, enrolled assets first,
	// and how many in all. Both are present exactly when AssetID is one of
	// AggregateKeys (new in 0.2, CH-47).
	Assets      []string
	AssetsTotal int64
}

var baselineHashForm = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// The aggregate keys C13 0.2 adds to an alert's asset_id (CH-47), each only
// for the two own-session rules: no tie was made for skew (CH-41); a
// backlog record untied after a break (CH-39); a tie the scheduler's wait
// could not make (#644 §1.9 items 4 and 9). This reader accepts them in an
// alert of 0.2 or later; at 0.1 they are refused.
const (
	AggregateClockSkew   = "clock-skew"
	AggregateRecordsLate = "sensor-records-late"
	AggregateHoldTimeout = "hold-timeout"
)

// AggregateKeys lists every aggregate key.
var AggregateKeys = []string{AggregateClockSkew, AggregateRecordsLate, AggregateHoldTimeout}

// MaxAggregateAssets bounds an aggregated alert's assets (CH-47).
const MaxAggregateAssets = 8

// Validate checks every rule of C13 that holds on one alert.
func (a *Alert) Validate() error {
	c := &checker{}
	c.storedSchema(a.Schema)
	want, ok := ruleParams[a.Rule]
	if ok && a.Rule == RuleOwnSessionMismatch && c.minor < 3 {
		ok = false
	}
	if !ok {
		c.fail(CodeForm, "rule", "%q is not a rule of a 0.%d alert", a.Rule, c.minor)
	}
	if ok && a.Rule == RuleOwnSessionMismatch && !validMismatchObservation(a.Observation) {
		c.fail(CodeForm, "observation", "%q does not match own-session-mismatch's head grammar (CH-51)", a.Observation)
	}
	aggregate := c.minor >= 2 && contains(AggregateKeys, a.AssetID)
	if a.AssetID != AssetUnresolved && !ValidUUID(a.AssetID) && !aggregate {
		c.fail(CodeForm, "asset_id", "%q is not an asset ID or %s", a.AssetID, AssetUnresolved)
	}
	a.checkAggregate(c, aggregate)
	switch {
	case a.Baseline == "" && ok && !contains(BaselineFree, a.Rule):
		c.fail(CodeMissing, "baseline", "rule %s judges against the acknowledged baseline", a.Rule)
	case a.Baseline == "" && a.BaselineVersion != 0:
		c.fail(CodeConflict, "baseline_version", "a version with no baseline")
	case a.Baseline != "" && !baselineHashForm.MatchString(a.Baseline):
		c.fail(CodeForm, "baseline", "%q is not sha256:<hex>", a.Baseline)
	case a.Baseline != "" && a.BaselineVersion < 1:
		c.fail(CodeRange, "baseline_version", "%d is below 1", a.BaselineVersion)
	}
	for _, t := range []struct{ f, v string }{{"key_text", a.KeyText}, {"baseline_value", a.BaselineValue}, {"observation", a.Observation}} {
		if t.v == "" || len(t.v) > ExplainMax {
			c.fail(CodeRange, t.f, "required, at most %d bytes", ExplainMax)
		}
	}
	if ok {
		var got []string
		for _, p := range a.Params {
			got = append(got, p.Name)
			if !decimalForm.MatchString(p.Value) {
				c.fail(CodeForm, "params", "%s = %q is not a decimal from 1", p.Name, p.Value)
			}
		}
		if !slices.Equal(got, want) {
			c.fail(CodeConflict, "params", "rule %s shows %v, not %v", a.Rule, want, got)
		}
	}
	if a.Clock != ClockCapture {
		c.fail(CodeForm, "clock", "%q is not %s", a.Clock, ClockCapture)
	}
	at, ok1 := c.utc("at_utc", a.AtUTC)
	ws, ok2 := c.utc("window_start_utc", a.WindowStartUTC)
	if ok1 && ok2 && at.Before(ws) {
		c.fail(CodeOrder, "at_utc", "before window_start_utc")
	}
	if a.Hits < 1 {
		c.fail(CodeRange, "hits", "%d: at least 1", a.Hits)
	}
	unseen := a.Rule == RuleOwnSessionUnseen
	switch {
	case unseen && (a.Sources != 0 || len(a.Related) != 0 || a.RelatedTotal != 0):
		c.fail(CodeConflict, "related", "own-session-unseen names a session record, no traffic")
	case !unseen && (a.Sources < 1 || a.Sources > a.Hits):
		c.fail(CodeRange, "sources", "%d not in [1, hits %d]", a.Sources, a.Hits)
	case !unseen && a.RelatedTotal != a.Hits:
		c.fail(CodeConflict, "related_total", "%d, but hits is %d: every hit's observation is related", a.RelatedTotal, a.Hits)
	}
	n := len(a.Related)
	if n > MaxRelated {
		c.fail(CodeRange, "related", "%d IDs, above %d", n, MaxRelated)
	}
	if a.RelatedTotal < int64(n) || (n < MaxRelated && a.RelatedTotal != int64(n)) {
		c.fail(CodeConflict, "related_total", "%d, but %d IDs are listed: the list holds the first min(total, %d)", a.RelatedTotal, n, MaxRelated)
	}
	for i, id := range a.Related {
		if !id.NodeID.Valid() || !id.Stream.Valid() || id.Seq == 0 {
			c.fail(CodeForm, fmt.Sprintf("related[%d]", i), "%v is not a valid event ID", id)
		}
	}
	switch {
	case unseen && (len(a.Cites) != 0 || a.Capture != ""):
		c.fail(CodeConflict, "cite", "own-session-unseen cites nothing")
	case !unseen && (len(a.Cites) == 0 || len(a.Cites) > MaxAlertFlows):
		c.fail(CodeRange, "cite", "%d flows, not in [1, %d]", len(a.Cites), MaxAlertFlows)
	case !unseen:
		c.sha256("capture", a.Capture)
	}
	frames := int64(0)
	for _, ct := range a.Cites {
		frames += int64(len(ct.Frames))
	}
	if a.FramesMissing < 0 || a.FramesMissing > frames {
		c.fail(CodeRange, "frames_missing", "%d not in [0, %d cited frames]", a.FramesMissing, frames)
	}
	for i, ct := range a.Cites {
		f := fmt.Sprintf("cite.%d", i+1)
		if !ValidCaptureID(ct.CaptureID) {
			c.fail(CodeForm, f, "%q is not a capture ID", ct.CaptureID)
		}
		if len(ct.Frames) == 0 || len(ct.Frames) > MaxAlertFramesPerFlow {
			c.fail(CodeRange, f, "%d frames, not in [1, %d]", len(ct.Frames), MaxAlertFramesPerFlow)
		}
		for j, fr := range ct.Frames {
			if fr.N < 1 || (j > 0 && fr.N <= ct.Frames[j-1].N) {
				c.fail(CodeOrder, f, "frame numbers from 1, ascending")
			}
			c.sha256(f, fr.SHA256)
		}
	}
	a.Coverage.check(c, "coverage")
	return c.err()
}

// checkAggregate applies CH-47: an aggregate key only under the two
// own-session rules, and assets and assets_total exactly with one, the
// assets at most MaxAggregateAssets distinct asset IDs and the total at
// least their number.
func (a *Alert) checkAggregate(c *checker, aggregate bool) {
	if aggregate && a.Rule != RuleOwnSessionUnseen && a.Rule != RuleOwnSessionOutsideRecord {
		c.fail(CodeConflict, "asset_id", "%s is a key only of %s and %s", a.AssetID, RuleOwnSessionUnseen, RuleOwnSessionOutsideRecord)
	}
	if !aggregate {
		if len(a.Assets) != 0 || a.AssetsTotal != 0 {
			c.fail(CodeConflict, "assets", "only under an aggregate key %v", AggregateKeys)
		}
		return
	}
	n := len(a.Assets)
	if n == 0 || n > MaxAggregateAssets {
		c.fail(CodeConflict, "assets", "%d assets, not in [1, %d]: an aggregated alert names what it covers", n, MaxAggregateAssets)
	}
	for i, id := range a.Assets {
		c.uuid(fmt.Sprintf("assets[%d]", i), id)
		if slices.Index(a.Assets, id) != i {
			c.fail(CodeOrder, "assets", "%q repeated", id)
		}
	}
	if a.AssetsTotal < int64(n) {
		c.fail(CodeConflict, "assets_total", "%d, below the %d assets listed", a.AssetsTotal, n)
	}
}

// The head grammar of an own-session-mismatch alert's observation (CH-51):
//
//	observation := head [ ": " free-text ]
//	head        := part ( " " part )*
//	part        := comparisons | unjudged | reasons | "no-profile"
//
// with at least one part, the parts in mismatchParts' order, each at most
// once, and each part but no-profile followed by at least one of its items,
// each at most once and in the item list's order.
type mismatchPart struct {
	word  string
	items []string
}

var mismatchParts = []mismatchPart{
	{"comparison", []string{"M1", "M2", "M3", "M4", "M5", "M6a", "M6b"}},
	{"unjudged", []string{"M2:incomplete", "M3:incomplete", "M5:incomplete", "M6a:incomplete", "M6b:incomplete", "M6b:no-profile"}},
	{"reason", []string{"prp-table-full", "prp-mismatched"}},
	{"no-profile", nil},
}

// validMismatchObservation reports whether the whole of s matches CH-51's
// production: the head, then the string's end or ": " and free text. The
// head holds no ": ", so it ends at the first one.
func validMismatchObservation(s string) bool {
	head, _, _ := strings.Cut(s, ": ")
	words := strings.Split(head, " ")
	part := -1
	for i := 0; i < len(words); {
		p := slices.IndexFunc(mismatchParts, func(x mismatchPart) bool { return x.word == words[i] })
		if p <= part {
			return false // an unknown word, or a part out of order or repeated
		}
		part = p
		i++
		item, n := -1, 0
		for ; i < len(words) && mismatchParts[p].items != nil; i++ {
			j := slices.Index(mismatchParts[p].items, words[i])
			if j < 0 {
				break // the next part's word, or an unknown word
			}
			if j <= item {
				return false // an item out of order or repeated
			}
			item, n = j, n+1
		}
		if mismatchParts[p].items != nil && n == 0 {
			return false // a part with no item
		}
	}
	return part >= 0
}

// Health is the alert as a C4 health event body: type HealthAlert, Related
// the hits' observations, and every other field as a detail (C13 §7.1).
// The detail keys are schema, rule, asset_id, baseline and
// baseline_version (when there is a baseline), key_text, param.<name>,
// baseline_value, observation, clock, at_utc, window_start_utc, hits,
// sources, related_total, cite.1 to cite.4 ("<capture_id> <n>=<sha256>
// ..."), capture (when there is one), frames_missing (when above 0), and
// the coverage statement flattened
// as coverage.* (flattenCoverage). AlertFromHealth reverses it.
func (a *Alert) Health() (event.Health, error) {
	if err := a.Validate(); err != nil {
		return event.Health{}, err
	}
	d := map[string]string{
		"schema": a.Schema, "rule": string(a.Rule), "asset_id": a.AssetID,
		"key_text": a.KeyText, "baseline_value": a.BaselineValue, "observation": a.Observation,
		"clock": a.Clock, "at_utc": a.AtUTC, "window_start_utc": a.WindowStartUTC,
		"hits": strconv.FormatInt(a.Hits, 10), "sources": strconv.FormatInt(a.Sources, 10),
		"related_total": strconv.FormatInt(a.RelatedTotal, 10),
	}
	if a.Baseline != "" {
		d["baseline"] = a.Baseline
		d["baseline_version"] = strconv.FormatInt(a.BaselineVersion, 10)
	}
	for _, p := range a.Params {
		d["param."+p.Name] = p.Value
	}
	for i, ct := range a.Cites {
		s := []string{ct.CaptureID}
		for _, fr := range ct.Frames {
			s = append(s, strconv.FormatInt(fr.N, 10)+"="+fr.SHA256)
		}
		d[fmt.Sprintf("cite.%d", i+1)] = strings.Join(s, " ")
	}
	if a.Capture != "" {
		d["capture"] = a.Capture
	}
	if a.FramesMissing > 0 {
		d["frames_missing"] = strconv.FormatInt(a.FramesMissing, 10)
	}
	if len(a.Assets) > 0 {
		d["assets"] = strings.Join(a.Assets, " ")
		d["assets_total"] = strconv.FormatInt(a.AssetsTotal, 10)
	}
	for k, v := range flattenCoverage(&a.Coverage) {
		d[k] = v
	}
	h := event.Health{Type: HealthAlert, Related: slices.Clone(a.Related), Details: d}
	if b, err := json.Marshal(h); err != nil || len(b) > MaxAlertBytes {
		return event.Health{}, &Error{Code: CodeRange, Field: "alert", Detail: fmt.Sprintf("health body %d bytes, above %d", len(b), MaxAlertBytes)}
	}
	return h, nil
}

// AlertFromEvent reads an alert back from a C4 telemetry-health event.
func AlertFromEvent(e *event.Event) (*Alert, error) {
	if e.Kind != event.KindHealth || e.Health == nil {
		return nil, &Error{Code: CodeType, Field: "kind", Detail: fmt.Sprintf("%q is not a %s event with health", e.Kind, event.KindHealth)}
	}
	return AlertFromHealth(*e.Health)
}

// AlertFromHealth reads an alert back from a C4 health body and validates
// it. A detail it does not know is an error unless the alert's schema is a
// later 0.x minor, which may add details.
func AlertFromHealth(h event.Health) (*Alert, error) {
	if h.Type != HealthAlert {
		return nil, &Error{Code: CodeType, Field: "health.type", Detail: fmt.Sprintf("%q is not %s", h.Type, HealthAlert)}
	}
	d := h.Details
	a := &Alert{
		Schema: d["schema"], Rule: Rule(d["rule"]), AssetID: d["asset_id"], Baseline: d["baseline"],
		KeyText: d["key_text"], BaselineValue: d["baseline_value"], Observation: d["observation"],
		Clock: d["clock"], AtUTC: d["at_utc"], WindowStartUTC: d["window_start_utc"],
		Capture: d["capture"], Related: slices.Clone(h.Related),
	}
	c := &checker{}
	known := map[string]bool{}
	num := func(name string, to *int64, optional bool) {
		known[name] = true
		v, present := d[name]
		if optional && !present {
			return
		}
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || strconv.FormatInt(n, 10) != v {
			c.fail(CodeForm, name, "%q is not a decimal", v)
		}
		*to = n
	}
	for _, k := range []string{"schema", "rule", "asset_id", "baseline", "key_text", "baseline_value", "observation", "clock", "at_utc", "window_start_utc", "capture"} {
		known[k] = true
	}
	num("hits", &a.Hits, false)
	num("sources", &a.Sources, false)
	num("related_total", &a.RelatedTotal, false)
	num("baseline_version", &a.BaselineVersion, true)
	num("frames_missing", &a.FramesMissing, true)
	if d["frames_missing"] == "0" {
		c.fail(CodeConflict, "frames_missing", "0 is left out")
	}
	got, perr := version.Parse(a.Schema)
	at02 := perr == nil && self.Accepts(got) && got.Minor >= 2
	if at02 {
		known["assets"] = true
		if v, ok := d["assets"]; ok {
			a.Assets = strings.Split(v, " ")
		}
		num("assets_total", &a.AssetsTotal, true)
		_, okA := d["assets"]
		if _, okT := d["assets_total"]; okA != okT {
			c.fail(CodeConflict, "assets_total", "present exactly with assets")
		}
	}
	for _, name := range ruleParams[a.Rule] {
		known["param."+name] = true
		if v, ok := d["param."+name]; ok {
			a.Params = append(a.Params, Param{Name: name, Value: v})
		}
	}
	for i := 1; i <= MaxAlertFlows; i++ {
		k := fmt.Sprintf("cite.%d", i)
		v, ok := d[k]
		if !ok {
			break
		}
		known[k] = true
		f := strings.Split(v, " ")
		ct := Cite{CaptureID: f[0]}
		for _, s := range f[1:] {
			ns, sha, _ := strings.Cut(s, "=")
			n, err := strconv.ParseInt(ns, 10, 64)
			if err != nil || strconv.FormatInt(n, 10) != ns {
				c.fail(CodeForm, k, "%q is not <n>=<sha256>", s)
			}
			ct.Frames = append(ct.Frames, CiteFrame{N: n, SHA256: sha})
		}
		a.Cites = append(a.Cites, ct)
	}
	cv, ckeys, err := unflattenCoverage(d)
	if err != nil {
		c.errs = append(c.errs, err)
	}
	a.Coverage = cv
	for _, k := range ckeys {
		known[k] = true
	}
	later := perr == nil && self.Accepts(got) && got.Minor > self.Minor
	for name := range d {
		if !known[name] && !later {
			c.fail(CodeConflict, "health.details", "%q is not a detail of rule %s", name, a.Rule)
		}
	}
	if err := a.Validate(); err != nil {
		c.errs = append(c.errs, err)
	}
	return a, errors.Join(c.errs...)
}

// flattenCoverage writes a coverage statement as alert details: each scalar
// under its path, a list of tokens or numbers space-separated (empty when
// the list is), and interface i (from 1) as "<name> <attachment> <lan>".
func flattenCoverage(cv *Coverage) map[string]string {
	ints := func(v []int) string {
		s := make([]string, len(v))
		for i, x := range v {
			s[i] = strconv.Itoa(x)
		}
		return strings.Join(s, " ")
	}
	d := map[string]string{
		"coverage.sensor_version":               cv.SensorVersion,
		"coverage.engine.name":                  cv.Engine.Name,
		"coverage.engine.version":               cv.Engine.Version,
		"coverage.prp.lans_seen":                strings.Join(cv.PRP.LANsSeen, " "),
		"coverage.prp.duplicates_discarded":     strconv.FormatBool(cv.PRP.DuplicatesDiscarded),
		"coverage.hsr":                          cv.HSR,
		"coverage.vlans_seen":                   ints(cv.VLANsSeen),
		"coverage.vlans_overflow":               strconv.FormatBool(cv.VLANsOverflow),
		"coverage.untagged_seen":                strconv.FormatBool(cv.UntaggedSeen),
		"coverage.decodes":                      strings.Join(cv.Decodes, " "),
		"coverage.degraded":                     strings.Join(cv.Degraded, " "),
		"coverage.settings.sa_reply_timeout_ms": strconv.Itoa(cv.Settings.SAReplyTimeoutMS),
		"coverage.settings.max_pending_dnp3":    strconv.Itoa(cv.Settings.MaxPendingDNP3),
		"coverage.settings.flow_idle_s":         strconv.Itoa(cv.Settings.FlowIdleS),
		"coverage.since_utc":                    cv.SinceUTC,
	}
	for i, in := range cv.Interfaces {
		d[fmt.Sprintf("coverage.interface.%d", i+1)] = in.Name + " " + in.Attachment + " " + in.LAN
	}
	// The two fields new in 0.2, each only when the statement has it.
	if cv.ConfigDigest != "" {
		d["coverage.config_digest"] = cv.ConfigDigest
	}
	if cv.Settings.PRPWindowMS != 0 {
		d["coverage.settings.prp_window_ms"] = strconv.Itoa(cv.Settings.PRPWindowMS)
	}
	return d
}

// unflattenCoverage reverses flattenCoverage, returning the keys it read.
func unflattenCoverage(d map[string]string) (Coverage, []string, error) {
	c := &checker{}
	var keys []string
	get := func(k string) string {
		keys = append(keys, k)
		v, ok := d[k]
		if !ok {
			c.fail(CodeMissing, k, "required")
		}
		return v
	}
	list := func(k string) []string {
		if v := get(k); v != "" {
			return strings.Split(v, " ")
		}
		return nil
	}
	boolean := func(k string) bool {
		v := get(k)
		if v != "true" && v != "false" {
			c.fail(CodeForm, k, "%q is not true or false", v)
		}
		return v == "true"
	}
	integer := func(k, v string) int {
		n, err := strconv.Atoi(v)
		if err != nil || strconv.Itoa(n) != v {
			c.fail(CodeForm, k, "%q is not a decimal", v)
		}
		return n
	}
	cv := Coverage{
		SensorVersion: get("coverage.sensor_version"),
		Engine:        Engine{Name: get("coverage.engine.name"), Version: get("coverage.engine.version")},
		PRP:           PRP{LANsSeen: list("coverage.prp.lans_seen"), DuplicatesDiscarded: boolean("coverage.prp.duplicates_discarded")},
		HSR:           get("coverage.hsr"),
		VLANsOverflow: boolean("coverage.vlans_overflow"),
		UntaggedSeen:  boolean("coverage.untagged_seen"),
		Decodes:       list("coverage.decodes"),
		Degraded:      list("coverage.degraded"),
		SinceUTC:      get("coverage.since_utc"),
	}
	for _, v := range list("coverage.vlans_seen") {
		cv.VLANsSeen = append(cv.VLANsSeen, integer("coverage.vlans_seen", v))
	}
	cv.Settings.SAReplyTimeoutMS = integer("coverage.settings.sa_reply_timeout_ms", get("coverage.settings.sa_reply_timeout_ms"))
	cv.Settings.MaxPendingDNP3 = integer("coverage.settings.max_pending_dnp3", get("coverage.settings.max_pending_dnp3"))
	cv.Settings.FlowIdleS = integer("coverage.settings.flow_idle_s", get("coverage.settings.flow_idle_s"))
	// Optional at every minor; Alert.Validate refuses them below 0.2.
	if v, ok := d["coverage.config_digest"]; ok {
		keys = append(keys, "coverage.config_digest")
		if cv.ConfigDigest = v; v == "" {
			c.fail(CodeForm, "coverage.config_digest", "empty; left out when there is none")
		}
	}
	if v, ok := d["coverage.settings.prp_window_ms"]; ok {
		keys = append(keys, "coverage.settings.prp_window_ms")
		if cv.Settings.PRPWindowMS = integer("coverage.settings.prp_window_ms", v); cv.Settings.PRPWindowMS == 0 {
			c.fail(CodeRange, "coverage.settings.prp_window_ms", "0; left out when there is none")
		}
	}
	for i := 1; i <= MaxInterfaces; i++ {
		k := fmt.Sprintf("coverage.interface.%d", i)
		v, ok := d[k]
		if !ok {
			break
		}
		keys = append(keys, k)
		f := strings.Split(v, " ")
		if len(f) != 3 {
			c.fail(CodeForm, k, "%q is not <name> <attachment> <lan>", v)
			continue
		}
		cv.Interfaces = append(cv.Interfaces, Interface{Name: f[0], Attachment: f[1], LAN: f[2]})
	}
	return cv, keys, c.err()
}
