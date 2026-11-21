package event

import (
	"maps"
	"slices"
	"strconv"
	"strings"
	"time"

	"otsec.local/otsec/contracts/version"
)

// ObservationRefusedReasons are the reasons <r> of a
// detector.observation-refused event's reason.<r>, first_seq.<r> and
// last_seq.<r> details, closed at 0.6 (C4-0.6-1).
var ObservationRefusedReasons = []string{"later-minor", "malformed", "detector-refused"}

// BaselineRefusedCauses are the values of a detector.baseline-refused
// event's cause detail, closed at 0.6 (C4-0.6-2).
var BaselineRefusedCauses = []string{"later-minor", "not-canonical", "malformed"}

// BaselineSchemaUnreadable is the schema detail of a
// detector.baseline-refused event whose refused document's stamp did not
// parse (C4-0.6-2).
const BaselineSchemaUnreadable = "unreadable"

// minor06 is the minor that defines both detector.* types.
const minor06 = 6

// parseCount reads a count: a decimal from 1 to 2^64 - 1 with no leading
// zero, the form of runs_folded (C4-0.5-1).
func parseCount(s string) (uint64, bool) {
	if !runsFoldedForm.MatchString(s) {
		return 0, false
	}
	n, err := strconv.ParseUint(s, 10, 64)
	return n, err == nil
}

// detectorGate applies the rules both detector.* types share: refused
// below 0.6, and closed at or below this reader's minor. It reports
// whether the event is of a later minor than this reader's.
func detectorGate(c *checker, e *Event) (later bool) {
	v, err := version.Parse(e.Schema)
	if err == nil && v.Minor < minor06 {
		c.fail(CodeForbidden, "health.type", "%s is new in otsec.event/0.%d; this event is %s", e.Health.Type, minor06, e.Schema)
	}
	return err == nil && v.Minor > self.Minor
}

// checkObservationRefused checks a detector.observation-refused health
// event (C4-0.6-1): the durable counts of stored observations the network
// detector refused to judge, by reason, since since. Each detail's form is
// checked; a relation is checked only over present, well-formed details,
// so each refusal has one code. An unknown detail or reason is refused
// unless the event is of a later minor than this reader's, whose unknown
// reason.<r> is still summed into count and paired with its seqs.
func checkObservationRefused(c *checker, e *Event) {
	if e.Kind != KindHealth || e.Health == nil || e.Health.Type != HealthObservationRefused {
		return
	}
	later := detectorGate(c, e)
	d := e.Health.Details
	const f = "health.details."
	count := func(k string) (uint64, bool) {
		v, ok := d[k]
		if !ok {
			return 0, false
		}
		n, ok := parseCount(v)
		if !ok {
			c.fail(CodeEnum, f+k, "%q is not a count from 1 to 2^64 - 1 (C4-0.6-1)", v)
		}
		return n, ok
	}
	for _, k := range []string{"stream", "since", "through", "netobs", "count"} {
		if _, ok := d[k]; !ok {
			c.fail(CodeMissing, f+k, "required on %s (C4-0.6-1)", HealthObservationRefused)
		}
	}
	if v, ok := d["stream"]; ok && !Stream(v).Valid() {
		c.fail(CodeEnum, f+"stream", "%q is not a stream token", v)
	}
	if v, ok := d["since"]; ok {
		if _, err := time.Parse(time.RFC3339Nano, v); err != nil {
			c.fail(CodeTimeFormat, f+"since", "%q is not RFC 3339", v)
		}
	}
	if v, ok := d["netobs"]; ok {
		if id, err := version.Parse(v); err != nil || id.Name != "netobs" {
			c.fail(CodeEnum, f+"netobs", "%q is not an otsec.netobs identifier", v)
		}
	}
	through, throughOK := count("through")
	total, totalOK := count("count")

	// The reasons, each with its seq pair.
	reasons := map[string]bool{}
	for k := range d {
		for _, p := range []string{"reason.", "first_seq.", "last_seq."} {
			if r, ok := strings.CutPrefix(k, p); ok {
				reasons[r] = true
			}
		}
		switch {
		case slices.Contains([]string{"stream", "since", "through", "netobs", "count", "unsure"}, k):
		case strings.HasPrefix(k, "reason.") || strings.HasPrefix(k, "first_seq.") || strings.HasPrefix(k, "last_seq."):
		case !later:
			c.fail(CodeEnum, f+k, "not a detail of %s in %s", HealthObservationRefused, e.Schema)
		}
	}
	var sum uint64
	sumOK, nReasons := true, 0
	for _, r := range slices.Sorted(maps.Keys(reasons)) {
		if !later && !slices.Contains(ObservationRefusedReasons, r) {
			for _, p := range []string{"reason.", "first_seq.", "last_seq."} {
				if _, ok := d[p+r]; ok {
					c.fail(CodeEnum, f+p+r, "%q is not a reason of %s in %s", r, HealthObservationRefused, e.Schema)
				}
			}
			sumOK = false
			continue
		}
		_, hasReason := d["reason."+r]
		if !hasReason {
			for _, p := range []string{"first_seq.", "last_seq."} {
				if _, ok := d[p+r]; ok {
					c.fail(CodeForbidden, f+p+r, "only with reason.%s", r)
				}
			}
			continue
		}
		nReasons++
		n, ok := count("reason." + r)
		if !ok {
			sumOK = false
		} else if s := sum + n; s < sum {
			sumOK = false
			if totalOK {
				c.fail(CodeEnum, f+"count", "the sum of reason.* is above 2^64 - 1")
				totalOK = false
			}
		} else {
			sum = s
		}
		for _, p := range []string{"first_seq.", "last_seq."} {
			if _, ok := d[p+r]; !ok {
				c.fail(CodeMissing, f+p+r, "required with reason.%s", r)
			}
		}
		first, firstOK := count("first_seq." + r)
		last, lastOK := count("last_seq." + r)
		if firstOK && lastOK && first > last {
			c.fail(CodeEnum, f+"first_seq."+r, "%d is above last_seq.%s %d", first, r, last)
		}
		if lastOK && throughOK && last > through {
			c.fail(CodeEnum, f+"last_seq."+r, "%d is above through %d", last, through)
		}
	}
	if nReasons == 0 {
		c.fail(CodeMissing, f+"reason", "no reason.<r>")
	}
	if sumOK && totalOK && nReasons > 0 && total != sum {
		c.fail(CodeEnum, f+"count", "%d is not the sum of reason.*, %d", total, sum)
	}

	// unsure: <a>-<b>, two counts with a <= b <= through.
	if v, ok := d["unsure"]; ok {
		as, bs, cut := strings.Cut(v, "-")
		a, aOK := parseCount(as)
		b, bOK := parseCount(bs)
		switch {
		case !cut || !aOK || !bOK:
			c.fail(CodeEnum, f+"unsure", "%q is not a seq range <a>-<b>", v)
		case a > b:
			c.fail(CodeEnum, f+"unsure", "%q: its start is above its end", v)
		case throughOK && b > through:
			c.fail(CodeEnum, f+"unsure", "%q: its end is above through %d", v, through)
		}
	}
}

// checkBaselineRefused checks a detector.baseline-refused health event
// (C4-0.6-2): the approved network baseline was refused and the detector
// is off. Whether the cause is right is NewDetector's classification, not
// checked here.
func checkBaselineRefused(c *checker, e *Event) {
	if e.Kind != KindHealth || e.Health == nil || e.Health.Type != HealthBaselineRefused {
		return
	}
	later := detectorGate(c, e)
	d := e.Health.Details
	const f = "health.details."
	for _, k := range []string{"hash", "schema", "cause"} {
		if _, ok := d[k]; !ok {
			c.fail(CodeMissing, f+k, "required on %s (C4-0.6-2)", HealthBaselineRefused)
		}
	}
	for k := range d {
		if k != "hash" && k != "schema" && k != "cause" && !later {
			c.fail(CodeEnum, f+k, "not a detail of %s in %s", HealthBaselineRefused, e.Schema)
		}
	}
	if v, ok := d["hash"]; ok && !alignKeyFormat.MatchString(v) {
		c.fail(CodeEnum, f+"hash", "%q is not sha256:<64 lowercase hex>", v)
	}
	schema, schemaOK := d["schema"]
	if schemaOK && schema != BaselineSchemaUnreadable {
		if id, err := version.Parse(schema); err != nil || id.Name != "netbaseline" {
			c.fail(CodeEnum, f+"schema", "%q is neither %s nor an otsec.netbaseline identifier", schema, BaselineSchemaUnreadable)
			schemaOK = false
		}
	}
	cause, causeOK := d["cause"]
	if causeOK && !later && !slices.Contains(BaselineRefusedCauses, cause) {
		c.fail(CodeEnum, f+"cause", "%q is not a cause of %s in %s", cause, HealthBaselineRefused, e.Schema)
		causeOK = false
	}
	// Above self, cause is open but still a token, as evidence_class is
	// (D1-23, D4-121).
	if causeOK && later && !tokenPattern.MatchString(cause) {
		c.fail(CodeEnum, f+"cause", "%q is not a token", cause)
		causeOK = false
	}
	if causeOK && schemaOK && cause == "later-minor" && schema == BaselineSchemaUnreadable {
		c.fail(CodeEnum, f+"cause", "later-minor is known only from a stamp that parsed; schema is %s", BaselineSchemaUnreadable)
	}
}
