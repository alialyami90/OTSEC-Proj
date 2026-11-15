package contract

// C8 otsec.audit/0.13 (D4-92; docs/phase4/D3-sensor-link.md §11.2, in the
// forms of D1's ruling 6894226253 on #683, D4-107: S1, St1, null, T1, K1
// and F1), D6's contract tests for P4-4-CC deliverable 5: C8-1 to C8-4,
// C8-6, C8-8 and C8-9. Expected outcomes come from the clause text and the
// ruling, not from the code: the key lists and reason codes below are
// written from them. The records are D6's own; every value is constructed,
// and no key or host is behind a pin or an address. C8-1's fold test is
// D5's (platform/node), and C8-5, C8-7 and the node's writers are owed
// (brief P4-4-CC, "Owed"). Ground truth: GT-HAND. Evidence class: desk.

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"otsec.local/otsec/contracts/audit"
	"otsec.local/otsec/contracts/authz"
	"otsec.local/otsec/contracts/version"
)

const (
	c8v13Node  = "d6-node"
	c8v13A     = "5a3c2e10-7b4d-4c8e-9f1a-2b3c4d5e6f70"
	c8v13B     = "0d1e2f30-4a5b-4c6d-8e7f-a0b1c2d3e4f5"
	c8v13At    = "2026-11-15T10:00:00.000125Z"
	c8v13Admin = "admin@site-a"
	c8v13Enrol = "node.sensor_enrol"
	c8v13Rev   = "node.sensor_revoke"
)

var (
	c8v13P1    = c7v11Pin("d6 c8 0.13 sensor key 1")
	c8v13P2    = c7v11Pin("d6 c8 0.13 sensor key 2")
	c8v13N     = c7v11Pin("d6 c8 0.13 node link key")
	c8v13Nonce = base64.RawURLEncoding.EncodeToString([]byte("d6 c8 0.13 nonce"))
)

func c8v13Hash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// c8v13Keys is the sensor object's key set per action and per C8-6 kind,
// required then optional, as C8-2, C8-3, C8-4 and C8-6 list them (S1).
var c8v13Keys = map[string][2][]string{
	"sensor.enrolled": {{"decision_seq", "payload_sha256", "generation", "sensor_spki", "sensor_address", "node_spki", "node_address", "not_after", "reason"},
		{"previous_generation", "previous_spki", "previous_state"}},
	"sensor.revoked":      {{"decision_seq", "payload_sha256", "generation", "sensor_spki", "reason", "applied_at", "streams"}, {"suspect_from", "baseline_digest"}},
	"sensor.link_refused": {{"generation", "count"}, nil},
	c8v13Enrol:            {{"generation", "sensor_spki"}, nil},
	c8v13Rev:              {{"generation", "sensor_spki", "reason"}, {"suspect_from"}},
}

// c8v13Sample is a value of each key of the sensor object, valid in itself.
var c8v13Sample = map[string]any{
	"decision_seq": 30, "payload_sha256": c8v13Hash("d6 c8 payload"), "generation": "1", "sensor_spki": c8v13P1,
	"sensor_address": "192.0.2.10:8443", "node_spki": c8v13N, "node_address": "192.0.2.1", "not_after": "2027-11-15T00:00:00Z",
	"reason": "compromised", "suspect_from": "2026-11-14T00:00:00Z", "previous_generation": "1", "previous_spki": c8v13P2,
	"previous_state": "unknown", "applied_at": "2026-11-15T09:59:59Z", "streams": map[string]any{}, "baseline_digest": c7v11Pin("d6 c8 baseline"),
	"count": 1,
}

func c8v13Rec(action, outcome string, sensor map[string]any) map[string]any {
	return map[string]any{"contract": "otsec.audit/0.13", "node_id": c8v13Node, "seq": 40, "prev_hash": strings.Repeat("7", 64),
		"time":  map[string]any{"utc": c8v13At, "resolution_ns": 1000, "clock": map[string]any{"sync": "synchronized", "source": "chrony"}},
		"actor": map[string]any{"type": "node", "id": c8v13Node}, "action": action, "outcome": outcome,
		"target": map[string]any{"sensor_id": c8v13A}, "sensor": sensor}
}

func c8v13Enrolled() map[string]any {
	return c8v13Rec("sensor.enrolled", "succeeded", map[string]any{"decision_seq": 30, "payload_sha256": c8v13Hash("enrol"),
		"generation": "1", "sensor_spki": c8v13P1, "sensor_address": "192.0.2.10:8443", "node_spki": c8v13N,
		"node_address": "192.0.2.1", "not_after": "2027-11-15T00:00:00Z", "reason": "new"})
}

func c8v13Revoked() map[string]any {
	return c8v13Rec("sensor.revoked", "succeeded", map[string]any{"decision_seq": 31, "payload_sha256": c8v13Hash("revoke"),
		"generation": "1", "sensor_spki": c8v13P1, "reason": "compromised", "suspect_from": "2026-11-14T00:00:00Z",
		"applied_at": "2026-11-15T09:59:59.500000Z", "streams": map[string]any{"observation_through_seq": 1207, "alert_through_seq": 31},
		"baseline_digest": c7v11Pin("d6 c8 baseline")})
}

func c8v13Refused() map[string]any {
	m := c8v13Rec("sensor.link_refused", "denied", map[string]any{"generation": "1", "count": 1})
	m["reason_code"] = "peer_key"
	return m
}

// c8v13Verified is C7's acceptance of kind, as a collector.request names it.
func c8v13Verified(kind, payload string) map[string]any {
	return map[string]any{"admin_key_id": a6KeyID(a6AdminPriv), "principal": c8v13Admin, "nonce": c8v13Nonce,
		"payload_sha256": payload, "kind": kind, "keys_digest": c7v11Pin("d6 c8 key set")}
}

// c8v13Request is C8-6's allowed, verified collector.request of kind.
func c8v13Request(kind string) map[string]any {
	s := map[string]any{"generation": "1", "sensor_spki": c8v13P1}
	payload := c8v13Hash("enrol")
	if kind == c8v13Rev {
		s["reason"], s["suspect_from"] = "compromised", "2026-11-14T00:00:00Z"
		payload = c8v13Hash("revoke")
	}
	m := c8v13Rec("collector.request", "allowed", s)
	m["actor"] = map[string]any{"type": "human", "id": c8v13Admin, "role": "admin"}
	m["correlation_id"], m["collector_seq"], m["verified"] = "req-d6-c8", 30, c8v13Verified(kind, payload)
	return m
}

// c8v13Info is the node's info record of a request of kind: claimed, no
// target, no sensor object.
func c8v13Info(kind string) map[string]any {
	m := c8v13Request(kind)
	delete(m, "target")
	delete(m, "sensor")
	delete(m, "collector_seq")
	m["outcome"], m["claimed"] = "info", m["verified"]
	delete(m["claimed"].(map[string]any), "keys_digest")
	delete(m, "verified")
	return m
}

// c8v13Records are one valid record of each action and of C8-6.
func c8v13Records() map[string]func() map[string]any {
	return map[string]func() map[string]any{
		"sensor.enrolled": c8v13Enrolled, "sensor.revoked": c8v13Revoked, "sensor.link_refused": c8v13Refused,
		c8v13Enrol: func() map[string]any { return c8v13Request(c8v13Enrol) },
		c8v13Rev:   func() map[string]any { return c8v13Request(c8v13Rev) },
	}
}

func c8v13S(m map[string]any) map[string]any { return m["sensor"].(map[string]any) }

func c8v13Time(m map[string]any, utc string) { m["time"].(map[string]any)["utc"] = utc }

func c8v13Parse(t *testing.T, m map[string]any) error {
	t.Helper()
	_, err := audit.ParseRecord(a6JSON(t, m))
	return err
}

// c8v13Pending is m without its chain fields, as a writer hands it to Seal.
func c8v13Pending(t *testing.T, m map[string]any) []byte {
	t.Helper()
	p := maps.Clone(m)
	delete(p, "seq")
	delete(p, "prev_hash")
	return a6JSON(t, p)
}

// c8v13Both reads m with the reader and through the writer's Seal, and
// reports what each said.
func c8v13Both(t *testing.T, m map[string]any) (read, sealed error) {
	t.Helper()
	_, sealed = audit.Seal(c8v13Pending(t, m), 40, strings.Repeat("7", 64))
	return c8v13Parse(t, m), sealed
}

func c8v13Refuse(t *testing.T, name string, m map[string]any) {
	t.Helper()
	if err := c8v13Parse(t, m); !errors.Is(err, audit.ErrRecordRejected) {
		t.Errorf("%s: %v, want it refused", name, err)
	}
}

func c8v13Accept(t *testing.T, name string, m map[string]any) {
	t.Helper()
	if read, sealed := c8v13Both(t, m); read != nil || sealed != nil {
		t.Errorf("%s: read %v, sealed %v", name, read, sealed)
	}
}

// C8-1: three actions written by the node, gated at minor 13, naming the
// sensor and no asset. Readers go first: the writer's stamp is not 0.13.
func TestC8v13C81Actions(t *testing.T) {
	if audit.ReaderID != "otsec.audit/0.13" {
		t.Fatalf("ReaderID %q", audit.ReaderID)
	}
	if v, err := version.Parse(audit.ContractID); err != nil || v.Name != "audit" || v.Minor >= 13 {
		t.Errorf("ContractID %q: the reader ships before the first build that writes 0.13", audit.ContractID)
	}
	for _, action := range []string{"sensor.enrolled", "sensor.revoked", "sensor.link_refused"} {
		build := c8v13Records()[action]
		c8v13Accept(t, action, build())
		for name, edit := range map[string]func(m map[string]any){
			"stamped 0.12":               func(m map[string]any) { m["contract"] = "otsec.audit/0.12" },
			"stamped 0.4":                func(m map[string]any) { m["contract"] = "otsec.audit/0.4" },
			"without a target":           func(m map[string]any) { delete(m, "target") },
			"with an empty target":       func(m map[string]any) { m["target"] = map[string]any{} },
			"with an asset target":       func(m map[string]any) { m["target"] = map[string]any{"asset_id": a6Asset} },
			"with an asset and a sensor": func(m map[string]any) { m["target"].(map[string]any)["asset_id"] = a6Asset },
			"with a register family":     func(m map[string]any) { m["target"].(map[string]any)["family"] = "sel-751" },
			"written by a person": func(m map[string]any) {
				m["actor"] = map[string]any{"type": "human", "id": c8v13Admin, "role": "admin"}
			},
			"written by the collector":  func(m map[string]any) { m["actor"] = map[string]any{"type": "system", "id": "collector"} },
			"without the sensor object": func(m map[string]any) { delete(m, "sensor") },
		} {
			m := build()
			edit(m)
			c8v13Refuse(t, action+", "+name, m)
		}
		m := build()
		m["contract"] = "otsec.audit/0.12"
		if err := c8v13Parse(t, m); !strings.Contains(fmt.Sprint(err), action+" is new in 0.13") {
			t.Errorf("%s stamped 0.12: %v, want it named as new in 0.13", action, err)
		}
	}
	// The sensor object belongs to the sensor records and C8-6 only: not on
	// the 0.12 network records that name a sensor, nor on another kind's
	// acceptance.
	ack := c8v13Ack(c8v13A)
	c8v13Accept(t, "a network acknowledgement", ack)
	ack["sensor"] = map[string]any{"generation": "1", "sensor_spki": c8v13P1}
	c8v13Refuse(t, "a network acknowledgement with a sensor object", ack)
	other := c8v13Request(c8v13Enrol)
	other["verified"].(map[string]any)["kind"] = string(authz.KindNodeNetworkBaselineAck)
	c8v13Refuse(t, "node.network_baseline_ack's acceptance with a sensor target and object", other)
}

// c8v13Ack is a succeeded network baseline acknowledgement of sensor, in
// C8 0.12's form.
func c8v13Ack(sensor string) map[string]any {
	m := c8v13Rec("config.baseline_acknowledged", "succeeded", nil)
	delete(m, "sensor")
	m["actor"] = map[string]any{"type": "human", "id": c8v13Admin, "role": "admin"}
	m["target"] = map[string]any{"sensor_id": sensor}
	m["correlation_id"] = "req-d6-net-ack"
	m["config"] = map[string]any{"decision_seq": 12, "payload_sha256": c8v13Hash("net ack"), "kind": "network",
		"baseline_digest": c7v11Pin("d6 c8 baseline"), "draft_digest": c7v11Pin("d6 c8 draft")}
	return m
}

// S1: one sensor object per action, with exactly its keys.
func TestC8v13S1SensorKeys(t *testing.T) {
	for name, build := range c8v13Records() {
		keys := c8v13Keys[name]
		c8v13Accept(t, name, build())
		for _, k := range keys[0] {
			m := build()
			delete(c8v13S(m), k)
			c8v13Refuse(t, name+" without "+k, m)
		}
		for k, v := range c8v13Sample {
			if slices.Contains(keys[0], k) || slices.Contains(keys[1], k) {
				continue
			}
			m := build()
			c8v13S(m)[k] = v
			c8v13Refuse(t, name+" with "+k, m)
		}
		m := build()
		c8v13S(m)["sensor_id"] = c8v13A
		if read, sealed := c8v13Both(t, m); read == nil || sealed == nil {
			t.Errorf("%s with an unknown key: read %v, sealed %v, want both refused", name, read, sealed)
		}
	}
	if len(c8v13Sample) != 17 {
		t.Fatalf("%d sample keys", len(c8v13Sample))
	}
}

// C8-2 and F1: sensor.enrolled, its seven codes in underscore form, and
// what it replaces. The body's fields pass C7-2's own checks (S1-a).
func TestC8v13C82Enrolled(t *testing.T) {
	if !slices.Equal(audit.EnrolDeniedReasons, ccD0EnrolDeniedReasons) {
		t.Errorf("EnrolDeniedReasons %v, want C8-2's seven in its order: %v", audit.EnrolDeniedReasons, ccD0EnrolDeniedReasons)
	}
	denied := func(code string) map[string]any {
		m := c8v13Enrolled()
		m["outcome"], m["reason_code"] = "denied", code
		return m
	}
	for _, code := range ccD0EnrolDeniedReasons {
		c8v13Accept(t, "denied "+code, denied(code))
	}
	for _, code := range []string{"node-key", "revoked-key", "forked-key", "not-after", "asset-address", "peer_key", "run_forked", "denied", ""} {
		c8v13Refuse(t, fmt.Sprintf("denied %q", code), denied(code))
	}
	for name, edit := range map[string]func(m map[string]any){
		"succeeded with a reason code": func(m map[string]any) { m["reason_code"] = "generation" },
		"failed":                       func(m map[string]any) { m["outcome"], m["reason_code"] = "failed", "generation" },
		"info":                         func(m map[string]any) { m["outcome"] = "info" },
	} {
		m := c8v13Enrolled()
		edit(m)
		c8v13Refuse(t, name, m)
	}

	// What it replaces: previous_generation with previous_spki, or
	// previous_state unknown alone, or none of the three.
	for name, edit := range map[string]func(s map[string]any){
		"a previous enrolment": func(s map[string]any) {
			s["generation"], s["reason"], s["previous_generation"], s["previous_spki"] = "2", "rekey", "1", c8v13P2
		},
		"an unknown previous state": func(s map[string]any) {
			s["generation"], s["reason"], s["previous_state"] = "4", "replace", "unknown"
		},
	} {
		m := c8v13Enrolled()
		edit(c8v13S(m))
		c8v13Accept(t, name, m)
	}
	for name, edit := range map[string]func(s map[string]any){
		"previous_state with previous_generation": func(s map[string]any) { s["previous_state"], s["previous_generation"] = "unknown", "1" },
		"previous_state with previous_spki":       func(s map[string]any) { s["previous_state"], s["previous_spki"] = "unknown", c8v13P2 },
		"previous_state with both": func(s map[string]any) {
			s["previous_state"], s["previous_generation"], s["previous_spki"] = "unknown", "1", c8v13P2
		},
		"previous_state other than unknown": func(s map[string]any) { s["previous_state"] = "known" },
		"previous_generation alone":         func(s map[string]any) { s["previous_generation"] = "1" },
		"previous_spki alone":               func(s map[string]any) { s["previous_spki"] = c8v13P2 },
		"previous_generation 0":             func(s map[string]any) { s["previous_generation"], s["previous_spki"] = "0", c8v13P2 },
		"previous_spki not a pin":           func(s map[string]any) { s["previous_generation"], s["previous_spki"] = "1", "sha256:00" },
		// S1-a: C7-2's checks, on a denied record too.
		"port 0":                func(s map[string]any) { s["sensor_address"] = "192.0.2.10:0" },
		"a hostname":            func(s map[string]any) { s["sensor_address"] = "sensor-a.example:8443" },
		"equal pins":            func(s map[string]any) { s["node_spki"] = c8v13P1 },
		"an uppercase pin":      func(s map[string]any) { s["sensor_spki"] = strings.ToUpper(c8v13P1) },
		"generation 01":         func(s map[string]any) { s["generation"] = "01" },
		"not_after with offset": func(s map[string]any) { s["not_after"] = "2027-11-15T00:00:00+00:00" },
		"new at generation 2":   func(s map[string]any) { s["generation"] = "2" },
		"renew at generation 1": func(s map[string]any) { s["reason"] = "renew" },
		"a revocation's reason": func(s map[string]any) { s["reason"] = "compromised" },
		"payload_sha256 short":  func(s map[string]any) { s["payload_sha256"] = "abcd" },
		"decision_seq 0":        func(s map[string]any) { s["decision_seq"] = 0 },
	} {
		for _, outcome := range []string{"succeeded", "denied"} {
			m := c8v13Enrolled()
			if outcome == "denied" {
				m["outcome"], m["reason_code"] = "denied", "asset_address"
			}
			edit(c8v13S(m))
			c8v13Refuse(t, outcome+", "+name, m)
		}
	}
}

// C8-3 and T1: sensor.revoked is always succeeded, carries applied_at in the
// record's microsecond form, never after the record's time as an instant.
func TestC8v13C83Revoked(t *testing.T) {
	for name, edit := range map[string]func(m map[string]any){
		"denied":                     func(m map[string]any) { m["outcome"], m["reason_code"] = "denied", "reason" },
		"info":                       func(m map[string]any) { m["outcome"] = "info" },
		"succeeded with a code":      func(m map[string]any) { m["reason_code"] = "compromised" },
		"without applied_at":         func(m map[string]any) { delete(c8v13S(m), "applied_at") },
		"without streams":            func(m map[string]any) { delete(c8v13S(m), "streams") },
		"an enrolment's reason":      func(m map[string]any) { c8v13S(m)["reason"] = "renew" },
		"baseline_digest not a pin":  func(m map[string]any) { c8v13S(m)["baseline_digest"] = c8v13Hash("x") },
		"suspect_from with offset":   func(m map[string]any) { c8v13S(m)["suspect_from"] = "2026-11-14T00:00:00+00:00" },
		"applied_at 1 µs after time": func(m map[string]any) { c8v13S(m)["applied_at"] = "2026-11-15T10:00:00.000126Z" },
		"applied_at with offset":     func(m map[string]any) { c8v13S(m)["applied_at"] = "2026-11-15T09:59:59+00:00" },
		"applied_at with no zone":    func(m map[string]any) { c8v13S(m)["applied_at"] = "2026-11-15T09:59:59" },
		"applied_at, 7 digits":       func(m map[string]any) { c8v13S(m)["applied_at"] = "2026-11-15T09:59:59.9999999Z" },
		"applied_at, 9 digits":       func(m map[string]any) { c8v13S(m)["applied_at"] = "2026-11-15T09:59:59.999999999Z" },
		"applied_at not a time":      func(m map[string]any) { c8v13S(m)["applied_at"] = "yesterday" },
	} {
		m := c8v13Revoked()
		edit(m)
		c8v13Refuse(t, name, m)
	}
	for name, edit := range map[string]func(m map[string]any){
		"without suspect_from or baseline_digest": func(m map[string]any) {
			delete(c8v13S(m), "suspect_from")
			delete(c8v13S(m), "baseline_digest")
		},
		"applied_at at the record's time":   func(m map[string]any) { c8v13S(m)["applied_at"] = c8v13At },
		"applied_at 1 µs before":            func(m map[string]any) { c8v13S(m)["applied_at"] = "2026-11-15T10:00:00.000124Z" },
		"applied_at in whole seconds":       func(m map[string]any) { c8v13S(m)["applied_at"] = "2026-11-15T09:00:00Z" },
		"applied_at, 6 digits":              func(m map[string]any) { c8v13S(m)["applied_at"] = "2026-11-15T09:59:59.999999Z" },
		"applied_at long before, a restart": func(m map[string]any) { c8v13S(m)["applied_at"] = "2026-11-14T22:00:00.000001Z" },
		"lost":                              func(m map[string]any) { c8v13S(m)["reason"] = "lost" },
		"retired":                           func(m map[string]any) { c8v13S(m)["reason"] = "retired" },
	} {
		m := c8v13Revoked()
		edit(m)
		c8v13Accept(t, name, m)
	}

	// Never after, compared as instants (T1). The control: a string
	// comparison decides the first three pairs the other way.
	for _, c := range []struct {
		at, applied     string
		ok, stringWrong bool
	}{
		{"2026-11-15T10:00:00Z", "2026-11-15T10:00:00.5Z", false, true},
		{"2026-11-15T10:00:00.5Z", "2026-11-15T10:00:00Z", true, true},
		{"2026-11-15T10:00:00.500000Z", "2026-11-15T10:00:00.5Z", true, true},
		{"2026-11-15T10:00:00.5Z", "2026-11-15T10:00:00.500000Z", true, false},
		{"2026-11-15T10:00:00Z", "2026-11-15T10:00:00.000000Z", true, false},
	} {
		m := c8v13Revoked()
		c8v13Time(m, c.at)
		c8v13S(m)["applied_at"] = c.applied
		if err := c8v13Parse(t, m); (err == nil) != c.ok {
			t.Errorf("time %s, applied_at %s: %v, want accepted %v", c.at, c.applied, err, c.ok)
		}
		if byString := c.applied <= c.at; (byString != c.ok) != c.stringWrong {
			t.Errorf("control: a string comparison of %s with %s gives %v", c.applied, c.at, byString)
		}
	}
}

// St1: streams keyed by role, both or neither; {} and two zeros are two
// records, written byte for byte through Seal.
func TestC8v13St1Streams(t *testing.T) {
	with := func(st any) map[string]any {
		m := c8v13Revoked()
		c8v13S(m)["streams"] = st
		return m
	}
	c8v13Accept(t, "no link ended", with(map[string]any{}))
	c8v13Accept(t, "ended, both streams empty", with(map[string]any{"observation_through_seq": 0, "alert_through_seq": 0}))
	c8v13Accept(t, "ended, at 2^64-1", with(json.RawMessage(`{"observation_through_seq":18446744073709551615,"alert_through_seq":18446744073709551615}`)))
	for name, st := range map[string]any{
		"observation alone":          map[string]any{"observation_through_seq": 5},
		"alert alone":                map[string]any{"alert_through_seq": 5},
		"an unknown key":             map[string]any{"observation_through_seq": 5, "alert_through_seq": 1, "baseline_through_seq": 1},
		"a list":                     []any{},
		"a string":                   "{}",
		"observation -1":             json.RawMessage(`{"observation_through_seq":-1,"alert_through_seq":0}`),
		"alert 1.5":                  json.RawMessage(`{"observation_through_seq":0,"alert_through_seq":1.5}`),
		"observation \"1\"":          json.RawMessage(`{"observation_through_seq":"1","alert_through_seq":0}`),
		"alert 2^64":                 json.RawMessage(`{"observation_through_seq":0,"alert_through_seq":18446744073709551616}`),
		"a duplicate key":            json.RawMessage(`{"observation_through_seq":1,"observation_through_seq":2,"alert_through_seq":0}`),
		"a key that differs in case": json.RawMessage(`{"Observation_through_seq":1,"alert_through_seq":0}`),
	} {
		c8v13Refuse(t, name, with(st))
	}

	// The exact bytes of both forms, as Seal writes them, and what a reader
	// reads back from each.
	empty, err := audit.Seal(c8v13Pending(t, with(map[string]any{})), 40, strings.Repeat("7", 64))
	if err != nil {
		t.Fatal(err)
	}
	zeros, err := audit.Seal(c8v13Pending(t, with(map[string]any{"observation_through_seq": 0, "alert_through_seq": 0})), 40, strings.Repeat("7", 64))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(empty, []byte(`"streams":{}`)) || !bytes.Contains(zeros, []byte(`"streams":{"observation_through_seq":0,"alert_through_seq":0}`)) {
		t.Errorf("sealed: %s\n%s", empty, zeros)
	}
	re, err1 := audit.ParseRecord(empty)
	rz, err2 := audit.ParseRecord(zeros)
	if err1 != nil || err2 != nil {
		t.Fatal(err1, err2)
	}
	if s := re.Sensor.Streams; s == nil || s.ObservationThroughSeq != nil || s.AlertThroughSeq != nil {
		t.Errorf("{} reads back as %+v", s)
	}
	if s := rz.Sensor.Streams; s == nil || s.ObservationThroughSeq == nil || *s.ObservationThroughSeq != 0 || s.AlertThroughSeq == nil || *s.AlertThroughSeq != 0 {
		t.Errorf("two zeros read back as %+v", s)
	}
}

// The ruling's null rule (St1-b): JSON null is refused for the sensor object
// and for every key in it and in streams, by the reader at any minor and by
// Seal. The control: a decoder alone reads each null as absent.
func TestC8v13NullRefused(t *testing.T) {
	keys := slices.Sorted(maps.Keys(c8v13Sample))
	for name, build := range c8v13Records() {
		cases := map[string]func(m map[string]any){"sensor": func(m map[string]any) { m["sensor"] = nil }}
		for _, k := range keys {
			cases["sensor."+k] = func(m map[string]any) { c8v13S(m)[k] = nil }
		}
		if name == "sensor.revoked" {
			for _, k := range []string{"observation_through_seq", "alert_through_seq"} {
				cases["sensor.streams."+k] = func(m map[string]any) { c8v13S(m)["streams"].(map[string]any)[k] = nil }
			}
			// Both null would read as {}, a record of no link ended, which
			// the both-or-neither rule accepts: only the null rule refuses it.
			cases["sensor.streams, both keys"] = func(m map[string]any) {
				c8v13S(m)["streams"] = map[string]any{"observation_through_seq": nil, "alert_through_seq": nil}
			}
		}
		for key, edit := range cases {
			for _, stamp := range []string{"otsec.audit/0.13", "otsec.audit/0.14"} {
				m := build()
				m["contract"] = stamp
				edit(m)
				if read, sealed := c8v13Both(t, m); !errors.Is(read, audit.ErrRecordRejected) || (stamp == "otsec.audit/0.13" && !errors.Is(sealed, audit.ErrRecordRejected)) {
					t.Errorf("%s, %s null, stamped %s: read %v, sealed %v, want refused", name, key, stamp, read, sealed)
				}
			}
		}
	}
	// Control: the plain decoder takes "no link ended" from two nulls, and a
	// known state from previous_state null.
	m := c8v13Revoked()
	c8v13S(m)["streams"] = map[string]any{"observation_through_seq": nil, "alert_through_seq": nil}
	var r audit.Record
	if err := json.Unmarshal(a6JSON(t, m), &r); err != nil || r.Sensor.Streams == nil || r.Sensor.Streams.ObservationThroughSeq != nil {
		t.Errorf("control: the plain decoder: %v, %+v", err, r.Sensor)
	}
	m = c8v13Enrolled()
	c8v13S(m)["previous_state"] = nil
	r = audit.Record{}
	if err := json.Unmarshal(a6JSON(t, m), &r); err != nil || r.Sensor.PreviousState != "" {
		t.Errorf("control: the plain decoder on previous_state null: %v, %+v", err, r.Sensor)
	}
}

// C8-4, K1 and F1: sensor.link_refused, its six codes in underscore form,
// and count, at least 1.
func TestC8v13C84LinkRefused(t *testing.T) {
	if !slices.Equal(audit.LinkRefusedReasons, ccD0LinkRefusedReasons) {
		t.Errorf("LinkRefusedReasons %v, want C8-4's six: %v", audit.LinkRefusedReasons, ccD0LinkRefusedReasons)
	}
	with := func(code string, edit func(s map[string]any)) map[string]any {
		m := c8v13Refused()
		m["reason_code"] = code
		if edit != nil {
			edit(c8v13S(m))
		}
		return m
	}
	for _, code := range ccD0LinkRefusedReasons {
		c8v13Accept(t, code, with(code, nil))
	}
	for _, code := range []string{"handshake", "peer-key", "run-regressed", "run-forked", "sensor-id", "node_key", "asset_address", ""} {
		c8v13Refuse(t, fmt.Sprintf("reason_code %q", code), with(code, nil))
	}
	for name, edit := range map[string]func(m map[string]any){
		"succeeded":              func(m map[string]any) { m["outcome"] = "succeeded" },
		"succeeded with no code": func(m map[string]any) { m["outcome"] = "succeeded"; delete(m, "reason_code") },
		"warning":                func(m map[string]any) { m["outcome"] = "warning" },
	} {
		m := c8v13Refused()
		edit(m)
		c8v13Refuse(t, name, m)
	}
	for _, n := range []any{1, 3, json.Number("18446744073709551615")} {
		c8v13Accept(t, fmt.Sprintf("count %v", n), with("binding", func(s map[string]any) { s["count"] = n }))
	}
	for name, edit := range map[string]func(s map[string]any){
		"count 0":            func(s map[string]any) { s["count"] = 0 },
		"count -1":           func(s map[string]any) { s["count"] = -1 },
		"count 1.5":          func(s map[string]any) { s["count"] = 1.5 },
		"count \"3\"":        func(s map[string]any) { s["count"] = "3" },
		"without count":      func(s map[string]any) { delete(s, "count") },
		"generation 0":       func(s map[string]any) { s["generation"] = "0" },
		"generation 01":      func(s map[string]any) { s["generation"] = "01" },
		"without generation": func(s map[string]any) { delete(s, "generation") },
	} {
		c8v13Refuse(t, name, with("binding", edit))
	}
}

// C8-6: the relayed collector.request names the sensor target and a sensor
// object only when it is allowed and verified for a sensor kind.
func TestC8v13C86Request(t *testing.T) {
	for _, kind := range []string{c8v13Enrol, c8v13Rev} {
		c8v13Accept(t, kind, c8v13Request(kind))
		c8v13Accept(t, kind+", its info record", c8v13Info(kind))
		for name, edit := range map[string]func(m map[string]any){
			"without the target":        func(m map[string]any) { delete(m, "target") },
			"without the sensor object": func(m map[string]any) { delete(m, "sensor") },
			"with an asset target":      func(m map[string]any) { m["target"] = map[string]any{"asset_id": a6Asset} },
			"with an asset and a sensor": func(m map[string]any) {
				m["target"].(map[string]any)["asset_id"] = a6Asset
			},
			"with a target in detail only": func(m map[string]any) { delete(m, "target"); m["detail"] = "sensor_id=" + c8v13A },
			"stamped 0.12":                 func(m map[string]any) { m["contract"] = "otsec.audit/0.12" },
			"a generation of 0":            func(m map[string]any) { c8v13S(m)["generation"] = "0" },
			"an uppercase pin":             func(m map[string]any) { c8v13S(m)["sensor_spki"] = strings.ToUpper(c8v13P1) },
		} {
			m := c8v13Request(kind)
			edit(m)
			c8v13Refuse(t, kind+", "+name, m)
		}
		// The info record names no target, and neither does a denied one.
		info := c8v13Info(kind)
		info["target"] = map[string]any{"sensor_id": c8v13A}
		c8v13Refuse(t, kind+", info with a sensor target", info)
		info = c8v13Info(kind)
		info["sensor"] = map[string]any{"generation": "1", "sensor_spki": c8v13P1}
		c8v13Refuse(t, kind+", info with a sensor object", info)
		info = c8v13Info(kind)
		info["contract"] = "otsec.audit/0.12"
		c8v13Refuse(t, kind+", info stamped 0.12", info)
	}
	c8v13Refuse(t, "revoke, an unknown reason", func() map[string]any {
		m := c8v13Request(c8v13Rev)
		c8v13S(m)["reason"] = "stolen"
		return m
	}())
	c8v13Refuse(t, "revoke, suspect_from with offset", func() map[string]any {
		m := c8v13Request(c8v13Rev)
		c8v13S(m)["suspect_from"] = "2026-11-14T00:00:00+00:00"
		return m
	}())

	// A denied record and an allowed record with no verified name no sensor;
	// each is valid without one (the control), and refused with one.
	denied := c8v13Request(c8v13Enrol)
	delete(denied, "verified")
	delete(denied, "target")
	delete(denied, "sensor")
	denied["outcome"], denied["reason_code"] = "denied", "admin_unverified"
	c8v13Accept(t, "denied, no target", denied)
	plain := c8v13Request(c8v13Enrol)
	delete(plain, "verified")
	delete(plain, "target")
	delete(plain, "sensor")
	c8v13Accept(t, "allowed with no verified, no target", plain)
	for name, m := range map[string]map[string]any{"denied": denied, "allowed with no verified": plain} {
		for what, add := range map[string]func(m map[string]any){
			"a sensor target": func(m map[string]any) { m["target"] = map[string]any{"sensor_id": c8v13A} },
			"a sensor object": func(m map[string]any) { m["sensor"] = map[string]any{"generation": "1", "sensor_spki": c8v13P1} },
		} {
			c := maps.Clone(m)
			add(c)
			c8v13Refuse(t, name+" with "+what, c)
		}
	}
}

// c8v13KeySet is a policy.apply admin_keys record that lists the admin key
// with kinds, and its digest.
func c8v13KeySet(status authz.KeyStatus, kinds ...authz.RequestKind) (map[string]any, string) {
	slices.Sort(kinds)
	d := authz.AdminKeysDigest([]authz.AdminKeyEntry{{KeyID: a6KeyID(a6AdminPriv), Principal: c8v13Admin, Status: status, Kinds: kinds}})
	m := c8v13Rec("policy.apply", "info", nil)
	delete(m, "sensor")
	delete(m, "target")
	m["reason_code"] = "admin_keys"
	m["admin_keys"] = map[string]any{"digest": d, "keys": []any{map[string]any{"key_id": a6KeyID(a6AdminPriv),
		"principal": c8v13Admin, "status": string(status), "kinds": kinds}}}
	return m, d
}

// c8v13Chain is the pending records of a node's chain from seq 1 (C8-8):
// 0 the chain's start; 1 the key set; 2 and 3 the acceptance (30) and
// enrolment of sensor A at generation 1 under pin P1; 4 and 5 the acceptance
// (31) and revocation of that pin; 6 and 7 the acceptance (32) and rekey of
// A to generation 2 under pin P2.
func c8v13Chain() []map[string]any {
	start := c8v13Rec("audit.chain.start", "info", nil)
	delete(start, "sensor")
	delete(start, "target")
	start["actor"] = map[string]any{"type": "system", "id": "collector"}
	keys, digest := c8v13KeySet(authz.KeyActive, authz.KindNodeSensorEnrol, authz.KindNodeSensorRevoke)
	accept := func(kind string, seq int, payload string, s map[string]any) map[string]any {
		m := c8v13Request(kind)
		m["collector_seq"], m["correlation_id"], m["sensor"] = seq, fmt.Sprintf("req-d6-c88-%d", seq), s
		v := m["verified"].(map[string]any)
		v["payload_sha256"], v["keys_digest"] = payload, digest
		return m
	}
	enrol1, revoke1, enrol2 := c8v13Enrolled(), c8v13Revoked(), c8v13Enrolled()
	s := c8v13S(enrol2)
	s["decision_seq"], s["payload_sha256"], s["generation"], s["sensor_spki"], s["reason"] = 32, c8v13Hash("enrol 2"), "2", c8v13P2, "rekey"
	s["previous_generation"], s["previous_spki"] = "1", c8v13P1
	return []map[string]any{start, keys,
		accept(c8v13Enrol, 30, c8v13Hash("enrol"), map[string]any{"generation": "1", "sensor_spki": c8v13P1}), enrol1,
		accept(c8v13Rev, 31, c8v13Hash("revoke"), map[string]any{"generation": "1", "sensor_spki": c8v13P1, "reason": "compromised", "suspect_from": "2026-11-14T00:00:00Z"}), revoke1,
		accept(c8v13Enrol, 32, c8v13Hash("enrol 2"), map[string]any{"generation": "2", "sensor_spki": c8v13P2}), enrol2}
}

// c8v13Seal seals ms as seq 1 on, linked, and reads each back.
func c8v13Seal(t *testing.T, ms []map[string]any) ([][]byte, []*audit.Record) {
	t.Helper()
	prev := audit.GenesisPrevHash
	var stored [][]byte
	var recs []*audit.Record
	for i, m := range ms {
		b, err := audit.Seal(c8v13Pending(t, m), uint64(i+1), prev)
		if err != nil {
			t.Fatalf("seal %d (%v): %v", i+1, m["action"], err)
		}
		r, err := audit.ParseRecord(b)
		if err != nil {
			t.Fatal(err)
		}
		stored, recs, prev = append(stored, b), append(recs, r), audit.Hash(b)
	}
	return stored, recs
}

// c8v13Breaks are chains that each break one of C8-8's rules.
var c8v13Breaks = map[string]func(ms []map[string]any) []map[string]any{
	"a skipped generation": func(ms []map[string]any) []map[string]any {
		c8v13S(ms[6])["generation"], c8v13S(ms[7])["generation"] = "3", "3"
		return ms
	},
	"a first enrolment above 1": func(ms []map[string]any) []map[string]any {
		c8v13S(ms[2])["generation"], c8v13S(ms[3])["generation"], c8v13S(ms[3])["reason"] = "2", "2", "rekey"
		return ms[:4]
	},
	"the revoked pin enrolled under another sensor_id": func(ms []map[string]any) []map[string]any {
		for _, m := range ms[6:] {
			m["target"] = map[string]any{"sensor_id": c8v13B}
			c8v13S(m)["generation"], c8v13S(m)["sensor_spki"] = "1", c8v13P1
		}
		s := c8v13S(ms[7])
		s["reason"] = "new"
		delete(s, "previous_generation")
		delete(s, "previous_spki")
		return ms
	},
	"the revoked pin renewed": func(ms []map[string]any) []map[string]any {
		c8v13S(ms[6])["sensor_spki"], c8v13S(ms[7])["sensor_spki"], c8v13S(ms[7])["reason"] = c8v13P1, c8v13P1, "renew"
		return ms
	},
	"no acceptance": func(ms []map[string]any) []map[string]any {
		c8v13S(ms[7])["decision_seq"] = 99
		return ms
	},
	"a revocation with no acceptance": func(ms []map[string]any) []map[string]any {
		return slices.Delete(ms, 4, 5)
	},
	"an acceptance of another sensor": func(ms []map[string]any) []map[string]any {
		ms[6]["target"] = map[string]any{"sensor_id": c8v13B}
		return ms
	},
	"an acceptance of another payload": func(ms []map[string]any) []map[string]any {
		c8v13S(ms[7])["payload_sha256"] = c8v13Hash("another payload")
		return ms
	},
	"an acceptance after its record": func(ms []map[string]any) []map[string]any {
		ms[6], ms[7] = ms[7], ms[6]
		return ms
	},
	"two revocations under one decision": func(ms []map[string]any) []map[string]any {
		return append(ms, c8v13Revoked())
	},
	"the repeat's own collector_seq": func(ms []map[string]any) []map[string]any {
		repeat := maps.Clone(ms[6])
		repeat["collector_seq"], repeat["repeat_of"] = 33, 32
		c8v13S(ms[7])["decision_seq"] = 33
		return slices.Insert(ms, 7, repeat)
	},
	"a renew under another pin": func(ms []map[string]any) []map[string]any {
		c8v13S(ms[7])["reason"] = "renew"
		return slices.Delete(ms, 4, 6)
	},
	"a rekey under the same pin": func(ms []map[string]any) []map[string]any {
		c8v13S(ms[6])["sensor_spki"], c8v13S(ms[7])["sensor_spki"] = c8v13P1, c8v13P1
		return slices.Delete(ms, 4, 6)
	},
	"a key set without the enrolment's kind": func(ms []map[string]any) []map[string]any {
		return c8v13Rekeyed(ms, authz.KeyActive, authz.KindNodeSensorRevoke)
	},
	"a key set without the revocation's kind": func(ms []map[string]any) []map[string]any {
		return c8v13Rekeyed(ms, authz.KeyActive, authz.KindNodeSensorEnrol)
	},
	"a revoked admin key": func(ms []map[string]any) []map[string]any {
		return c8v13Rekeyed(ms, authz.KeyRevoked, authz.KindNodeSensorEnrol, authz.KindNodeSensorRevoke)
	},
	"a decision under another key set": func(ms []map[string]any) []map[string]any {
		ms[2]["verified"].(map[string]any)["keys_digest"] = c7v11Pin("d6 c8 an older key set")
		return ms
	},
	"no key set before the decision": func(ms []map[string]any) []map[string]any {
		return slices.Delete(ms, 1, 2)
	},
	// The kind (D1's ruling 6895174039 on #699): a sensor.enrolled names an
	// enrolment's acceptance, and a sensor.revoked a revocation's. The first
	// case differs in the kind alone.
	"an enrolment naming a revocation's acceptance": func(ms []map[string]any) []map[string]any {
		ms[2]["verified"].(map[string]any)["kind"] = c8v13Rev
		c8v13S(ms[2])["reason"] = "compromised"
		return ms[:4]
	},
	"a revocation naming an enrolment's acceptance": func(ms []map[string]any) []map[string]any {
		ms[4]["verified"].(map[string]any)["kind"] = c8v13Enrol
		delete(c8v13S(ms[4]), "reason")
		delete(c8v13S(ms[4]), "suspect_from")
		return ms[:6]
	},
	// Option (c) of that ruling: an enrolment is still judged at its own
	// place, so a key-set change or a collector reset between its acceptance
	// and its record breaks the chain; and one acceptance names at most one
	// revocation, across a reset.
	"a key-set change before an enrolment is applied": func(ms []map[string]any) []map[string]any {
		return []map[string]any{ms[0], ms[1], ms[2], c8v13Rotation(), ms[3]}
	},
	"a collector reset before an enrolment is applied": func(ms []map[string]any) []map[string]any {
		return []map[string]any{ms[0], ms[1], ms[2], c8v13Reset(), ms[3]}
	},
	"two revocations of one acceptance across a reset": func(ms []map[string]any) []map[string]any {
		return append(ms[:6], c8v13Reset(), c8v13Revoked())
	},
}

// c8v13Rotation is a policy.apply admin_keys record that follows the chain's
// key set and lists its one key as revoked.
func c8v13Rotation() map[string]any {
	_, old := c8v13KeySet(authz.KeyActive, authz.KindNodeSensorEnrol, authz.KindNodeSensorRevoke)
	m, _ := c8v13KeySet(authz.KeyRevoked, authz.KindNodeSensorEnrol, authz.KindNodeSensorRevoke)
	m["admin_keys"].(map[string]any)["previous_digest"] = old
	return m
}

// c8v13Reset is a collector.seq_reset after collector_seq 31: a new epoch.
func c8v13Reset() map[string]any {
	m := c8v13Rec("collector.seq_reset", "info", nil)
	delete(m, "sensor")
	delete(m, "target")
	m["previous_high"], m["install_key_id"] = 31, "site-a-node-1.collector-install.2"
	return m
}

// c8v13Rekeyed replaces the chain's key set, and names its digest on every
// acceptance, so that only the key set's content differs.
func c8v13Rekeyed(ms []map[string]any, status authz.KeyStatus, kinds ...authz.RequestKind) []map[string]any {
	keys, digest := c8v13KeySet(status, kinds...)
	ms[1] = keys
	for _, i := range []int{2, 4, 6} {
		ms[i]["verified"].(map[string]any)["keys_digest"] = digest
	}
	return ms
}

// C8-8: the chain rules, in a verifier of their own, as far as a view shows.
func TestC8v13C88Chain(t *testing.T) {
	stored, recs := c8v13Seal(t, c8v13Chain())
	if err := audit.VerifySensorFrom(recs, 1); err != nil {
		t.Fatalf("the valid chain: %v", err)
	}
	for name, edit := range c8v13Breaks {
		_, recs := c8v13Seal(t, edit(c8v13Chain()))
		if err := audit.VerifySensorFrom(recs, 1); !errors.Is(err, audit.ErrChainBroken) {
			t.Errorf("%s: %v, want a break", name, err)
		}
	}
	// Each rule's control: the case it allows. previous_state lifts the
	// generation rule; a repeat answer stands for its first decision, with
	// or without it in view (S1-b); a renew keeps its pin.
	for name, edit := range map[string]func(ms []map[string]any) []map[string]any{
		"a skipped generation, the state unknown": func(ms []map[string]any) []map[string]any {
			ms = c8v13Breaks["a skipped generation"](ms)
			s := c8v13S(ms[7])
			s["reason"], s["previous_state"] = "replace", "unknown"
			delete(s, "previous_generation")
			delete(s, "previous_spki")
			return ms
		},
		"a first enrolment above 1, the state unknown": func(ms []map[string]any) []map[string]any {
			ms = c8v13Breaks["a first enrolment above 1"](ms)
			c8v13S(ms[3])["previous_state"] = "unknown"
			return ms
		},
		"a decision named through its repeat": func(ms []map[string]any) []map[string]any {
			ms = c8v13Breaks["the repeat's own collector_seq"](ms)
			c8v13S(ms[8])["decision_seq"] = 32
			return ms
		},
		"a repeat in view, its first decision not": func(ms []map[string]any) []map[string]any {
			ms = c8v13Breaks["the repeat's own collector_seq"](ms)
			c8v13S(ms[8])["decision_seq"] = 32
			return slices.Delete(ms, 6, 7)
		},
		"a renew under the same pin": func(ms []map[string]any) []map[string]any {
			ms = c8v13Breaks["a rekey under the same pin"](ms)
			c8v13S(ms[5])["reason"] = "renew"
			return ms
		},
		// Option (c): a revocation written late is judged by the key set and
		// the epoch in force at its acceptance, so neither a key-set change
		// nor a collector reset after the acceptance breaks it.
		"a revocation applied after a key-set change": func(ms []map[string]any) []map[string]any {
			return []map[string]any{ms[0], ms[1], ms[2], ms[3], ms[4], c8v13Rotation(), ms[5]}
		},
		"a revocation applied after a collector reset": func(ms []map[string]any) []map[string]any {
			return []map[string]any{ms[0], ms[1], ms[2], ms[3], ms[4], c8v13Reset(), ms[5]}
		},
	} {
		_, recs := c8v13Seal(t, edit(c8v13Chain()))
		if err := audit.VerifySensorFrom(recs, 1); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}

	// A view that starts after the acceptance: the revocation's decision,
	// the key set and the sensor's last enrolment are before it, unknown and
	// not a break. Control: the same records from seq 1 without that
	// acceptance break.
	if err := audit.VerifySensorFrom(recs[5:], recs[5].Seq); err != nil {
		t.Errorf("a view from the revocation: %v", err)
	}
	if err := audit.VerifySensorFrom(recs[3:4], recs[3].Seq); err != nil {
		t.Errorf("a view of the enrolment alone: %v", err)
	}
	// Not in the start-up chain check: a chain these rules break is linked
	// and valid to VerifyChain, so a break here switches off no asset's
	// event baselines.
	broken, brecs := c8v13Seal(t, c8v13Breaks["the revoked pin renewed"](c8v13Chain()))
	if err := audit.VerifyChain(c8v13Node, broken, nil, nil); err != nil || audit.VerifySensorFrom(brecs, 1) == nil {
		t.Errorf("VerifyChain on a chain C8-8 breaks: %v", err)
	}
	if err := audit.VerifyChain(c8v13Node, stored, nil, nil); err != nil {
		t.Errorf("VerifyChain on the valid chain: %v", err)
	}
}

// C8-8, D1's option (a) of 6894951825 on #699: when the decision is in the
// view, sensor.revoked's generation, sensor_spki, reason and suspect_from,
// and a succeeded sensor.enrolled's generation and sensor_spki, equal the
// C8-6 record's. The control is TestC8v13C88Chain's valid chain, whose
// copies are equal.
func TestC8v13C88CopiedFields(t *testing.T) {
	for name, edit := range map[string]func(ms []map[string]any){
		"revoked, another generation":   func(ms []map[string]any) { c8v13S(ms[5])["generation"] = "2" },
		"revoked, another pin":          func(ms []map[string]any) { c8v13S(ms[5])["sensor_spki"] = c8v13P2 },
		"revoked, another reason":       func(ms []map[string]any) { c8v13S(ms[5])["reason"] = "lost" },
		"revoked, another suspect_from": func(ms []map[string]any) { c8v13S(ms[5])["suspect_from"] = "2026-11-13T00:00:00Z" },
		"revoked, suspect_from dropped": func(ms []map[string]any) { delete(c8v13S(ms[5]), "suspect_from") },
		"enrolled, another generation": func(ms []map[string]any) {
			c8v13S(ms[2])["generation"] = "2"
		},
		"enrolled, another pin": func(ms []map[string]any) { c8v13S(ms[2])["sensor_spki"] = c8v13P2 },
	} {
		ms := c8v13Chain()[:6]
		edit(ms)
		_, recs := c8v13Seal(t, ms)
		if err := audit.VerifySensorFrom(recs, 1); !errors.Is(err, audit.ErrChainBroken) {
			t.Errorf("%s: %v, want a break", name, err)
		}
	}
}

// C8-9: a network acknowledgement that precedes the latest sensor.revoked
// of its sensor is not in force; a reader's rule, not a break.
func TestC8v13C89AckInForce(t *testing.T) {
	read := func(ms ...map[string]any) []*audit.Record {
		var out []*audit.Record
		for i, m := range ms {
			m["seq"] = 10 + i
			r, err := audit.ParseRecord(a6JSON(t, m))
			if err != nil {
				t.Fatalf("record %d (%v): %v", i, m["action"], err)
			}
			out = append(out, r)
		}
		return out
	}
	other := c8v13Revoked()
	other["target"] = map[string]any{"sensor_id": c8v13B}
	for _, c := range []struct {
		name  string
		recs  []*audit.Record
		ack   int
		force bool
	}{
		{"acknowledged, then revoked", read(c8v13Ack(c8v13A), c8v13Revoked()), 0, false},
		{"revoked, then acknowledged (the control)", read(c8v13Revoked(), c8v13Ack(c8v13A)), 1, true},
		{"acknowledged, revoked, acknowledged again", read(c8v13Ack(c8v13A), c8v13Revoked(), c8v13Ack(c8v13A)), 2, true},
		{"acknowledged, then another sensor revoked", read(c8v13Ack(c8v13A), other), 0, true},
		{"acknowledged alone", read(c8v13Ack(c8v13A)), 0, true},
	} {
		if got := audit.NetworkAckInForce(c.recs, c.recs[c.ack]); got != c.force {
			t.Errorf("%s: in force %v, want %v", c.name, got, c.force)
		}
	}
	// Not a break: the chain with the acknowledgement before the revocation
	// passes C8-8's verifier.
	recs := read(c8v13Ack(c8v13A), c8v13Revoked())
	if err := audit.VerifySensorFrom(recs, recs[0].Seq); err != nil {
		t.Errorf("C8-8 on it: %v", err)
	}
}

// C8-9's schema leg: record.json gains the three actions, the sensor object
// with exactly the ruled keys, streams, applied_at, previous_state and the
// two code sets in underscore form.
func TestC8v13C89Schema(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "contracts", "audit", "schema", "record.json"))
	if err != nil {
		t.Fatal(err)
	}
	var schema map[string]any
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatal(err)
	}
	if schema["$id"] != "otsec.audit/0.13/record" {
		t.Errorf("$id %v", schema["$id"])
	}
	props := schema["properties"].(map[string]any)
	actions := c7v11Strings(props["action"].(map[string]any)["enum"])
	for _, a := range []string{"sensor.enrolled", "sensor.revoked", "sensor.link_refused"} {
		if !slices.Contains(actions, a) {
			t.Errorf("the action enum lacks %s", a)
		}
	}
	sensor := props["sensor"].(map[string]any)
	sp := sensor["properties"].(map[string]any)
	if sensor["additionalProperties"] != false || !c7v11SameSet(slices.Collect(maps.Keys(sp)), slices.Collect(maps.Keys(c8v13Sample))) {
		t.Errorf("sensor: %v, want exactly %v", slices.Sorted(maps.Keys(sp)), slices.Sorted(maps.Keys(c8v13Sample)))
	}
	streams := sp["streams"].(map[string]any)
	if streams["additionalProperties"] != false || !c7v11SameSet(slices.Collect(maps.Keys(streams["properties"].(map[string]any))), []string{"observation_through_seq", "alert_through_seq"}) {
		t.Errorf("streams: %v", streams)
	}
	dep, _ := json.Marshal(streams["dependentRequired"])
	if string(dep) != `{"alert_through_seq":["observation_through_seq"],"observation_through_seq":["alert_through_seq"]}` {
		t.Errorf("streams dependentRequired %s", dep)
	}
	if c, _ := sp["count"].(map[string]any)["minimum"].(float64); c != 1 {
		t.Errorf("count minimum %v", sp["count"])
	}
	if sp["previous_state"].(map[string]any)["const"] != "unknown" {
		t.Errorf("previous_state %v", sp["previous_state"])
	}
	pat, err := regexp.Compile(sp["applied_at"].(map[string]any)["pattern"].(string))
	if err != nil {
		t.Fatal(err)
	}
	for s, ok := range map[string]bool{"2026-11-15T09:59:59Z": true, "2026-11-15T09:59:59.5Z": true, "2026-11-15T09:59:59.999999Z": true,
		"2026-11-15T09:59:59.9999999Z": false, "2026-11-15T09:59:59+00:00": false} {
		if pat.MatchString(s) != ok {
			t.Errorf("applied_at pattern on %s: %v", s, !ok)
		}
	}
	// The code sets: every enum that holds one of C8-2's or C8-4's codes holds
	// exactly that set, and no enum holds a hyphen form.
	var enums [][]string
	var walk func(v any)
	walk = func(v any) {
		switch v := v.(type) {
		case map[string]any:
			if e, ok := v["enum"].([]any); ok {
				var s []string
				for _, x := range e {
					if x, ok := x.(string); ok {
						s = append(s, x)
					}
				}
				enums = append(enums, s)
			}
			for _, x := range v {
				walk(x)
			}
		case []any:
			for _, x := range v {
				walk(x)
			}
		}
	}
	walk(schema)
	found := map[string]bool{}
	for _, e := range enums {
		for marker, want := range map[string][]string{"node_key": ccD0EnrolDeniedReasons, "peer_key": ccD0LinkRefusedReasons} {
			if slices.Contains(e, marker) {
				found[marker] = true
				if !c7v11SameSet(e, want) {
					t.Errorf("an enum %v, want %v", e, want)
				}
			}
		}
		for _, x := range e {
			if slices.Contains([]string{"node-key", "revoked-key", "forked-key", "not-after", "asset-address", "peer-key", "run-regressed", "run-forked", "sensor-id"}, x) {
				t.Errorf("an enum holds the hyphen form %s", x)
			}
		}
	}
	if !found["node_key"] || !found["peer_key"] {
		t.Errorf("code sets found: %v", found)
	}
}
