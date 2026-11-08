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
)

// Rules lists every Rule.
var Rules = []Rule{RuleUnknownPair, RuleNewService, RuleNewFunction, RuleUnauthorizedWrite,
	RuleOwnSessionOutsideRecord, RuleNodeAddressSpoofed, RuleOwnSessionUnseen, RuleUnresolvedAddress, RuleSAFailed}

// BaselineFree are the rules that run before any baseline is acknowledged
// (D4-68 ruling 10). The other five judge against the acknowledged
// baseline.
var BaselineFree = []Rule{RuleOwnSessionOutsideRecord, RuleNodeAddressSpoofed, RuleOwnSessionUnseen, RuleSAFailed}

// ruleParams are the parameters each rule's alert shows, in order.
var ruleParams = map[Rule][]string{
	RuleUnknownPair: nil, RuleNewService: nil, RuleNewFunction: nil, RuleUnauthorizedWrite: nil,
	RuleOwnSessionOutsideRecord: {"tie_grace_s"}, RuleNodeAddressSpoofed: nil,
	RuleOwnSessionUnseen: {"tie_grace_s"}, RuleUnresolvedAddress: nil, RuleSAFailed: nil,
}

// RuleParams returns the parameters rule r's alert shows, in order.
func RuleParams(r Rule) []string { return slices.Clone(ruleParams[r]) }

// Param is one parameter as the alert shows it: a decimal value.
type Param struct {
	Name  string
	Value string
}

// Cite is one flow's citation in an alert: a capture and up to
// MaxAlertFramesPerFlow frames, shown as "<capture_id> <n>=<sha256> ...".
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
}

var baselineHashForm = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// Validate checks every rule of C13 that holds on one alert.
func (a *Alert) Validate() error {
	c := &checker{}
	c.storedSchema(a.Schema)
	want, ok := ruleParams[a.Rule]
	if !ok {
		c.fail(CodeForm, "rule", "%q is not a rule", a.Rule)
	}
	if a.AssetID != AssetUnresolved && !ValidUUID(a.AssetID) {
		c.fail(CodeForm, "asset_id", "%q is not an asset ID or %s", a.AssetID, AssetUnresolved)
	}
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
	got, perr := version.Parse(a.Schema)
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
