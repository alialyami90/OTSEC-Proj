package contract

// C7 otsec.authz/0.11 (D4-92; docs/phase4/D3-sensor-link.md §11.1), D6's
// contract tests for P4-4-CC deliverable 5: C7-1, C7-2, C7-3 and C7-7.
// Expected outcomes come from the clause text, not from the code. Requests
// are signed with A6's alice key (c7_admin_test.go) over the credential
// golden's binding and times, as c7_v05_test.go builds them; the sensor ID,
// pins and addresses are D6's own test values (RFC 5737 and RFC 3849
// documentation addresses), and no key or host is behind them. C7-4 to C7-6
// are owed by later briefs (brief P4-4-CC, "Owed"). Ground truth: GT-HAND,
// from the approved text. Evidence class: desk.

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"otsec.local/otsec/contracts/authz"
)

const c7v11Sensor = "5a3c2e10-7b4d-4c8e-9f1a-2b3c4d5e6f70"

// c7v11Pin is a key's pin in C7-2's form, over a test string.
func c7v11Pin(s string) string {
	sum := sha256.Sum256([]byte(s))
	return "sha256:" + hex.EncodeToString(sum[:])
}

var (
	c7v11SensorPin = c7v11Pin("d6 c7 0.11 sensor key")
	c7v11NodePin   = c7v11Pin("d6 c7 0.11 node link key")
	c7v11Both      = []authz.RequestKind{authz.KindNodeSensorEnrol, authz.KindNodeSensorRevoke}
	c7v11Field     = map[authz.RequestKind]string{authz.KindNodeSensorEnrol: "node_sensor_enrol", authz.KindNodeSensorRevoke: "node_sensor_revoke"}
)

// c7v11Enrol is an enrolment body as C7-2 states it: a rekey to generation 2.
func c7v11Enrol() map[string]any {
	return map[string]any{"sensor_id": c7v11Sensor, "generation": "2", "sensor_spki": c7v11SensorPin,
		"sensor_address": "192.0.2.10:8443", "node_spki": c7v11NodePin, "node_address": "192.0.2.1",
		"not_after": "2027-10-26T00:00:00Z", "reason": "rekey"}
}

// c7v11Revoke is a revocation body as C7-3 states it.
func c7v11Revoke() map[string]any {
	return map[string]any{"sensor_id": c7v11Sensor, "generation": "2", "sensor_spki": c7v11SensorPin,
		"reason": "compromised", "suspect_from": "2026-10-26T12:00:00Z"}
}

func c7v11Body(kind authz.RequestKind) map[string]any {
	if kind == authz.KindNodeSensorEnrol {
		return c7v11Enrol()
	}
	return c7v11Revoke()
}

// c7v11Payload is a payload of kind carrying body, on the credential
// golden's binding and times.
func c7v11Payload(t *testing.T, kind authz.RequestKind, body map[string]any) map[string]any {
	t.Helper()
	p := a6Payload(t, authz.KindCredentialRevoke)
	delete(p, "credential_revoke")
	p["kind"] = string(kind)
	p[c7v11Field[kind]] = body
	return p
}

// c7v11Decode signs p as alice, stamps the request, and reads it as the
// collector does.
func c7v11Decode(t *testing.T, stamp string, kind authz.RequestKind, p map[string]any) (*authz.CollectorRequest, error) {
	t.Helper()
	req := a6Signed(a6AdminPriv, kind, kind, a6JSON(t, p))
	req.Contract = stamp
	return a6Decode(t, req)
}

// c7v11Verify verifies a 0.11 request of kind with body, alice holding the
// kinds given (nil: a key pinned without a list).
func c7v11Verify(t *testing.T, kind authz.RequestKind, body map[string]any, kinds []authz.RequestKind) (*authz.AdminRequest, error) {
	t.Helper()
	req, err := c7v11Decode(t, "otsec.authz/0.11", kind, c7v11Payload(t, kind, body))
	if err != nil {
		t.Fatalf("0.11 decode: %v", err)
	}
	keys := a6AdminKeys()
	keys[0].Kinds = kinds
	return authz.VerifyAdminRequest(req, keys, a6Bind, a6Now)
}

func TestC7v11Version(t *testing.T) {
	if authz.ContractID != "otsec.authz/0.11" {
		t.Errorf("ContractID %q", authz.ContractID)
	}
	// The payload format stays 0.4, so an older reader refuses the new body
	// as a payload error (C7-1).
	if authz.AdminRequestFormat != "otsec.authz.admin-request/0.4" {
		t.Errorf("AdminRequestFormat %q", authz.AdminRequestFormat)
	}
}

// C7-1: two kinds, each a grant of its own, gated at minor 11 and not in
// DefaultAdminKinds (SL-7).
func TestC7v11C71Grants(t *testing.T) {
	for _, kind := range c7v11Both {
		other := c7v11Both[0]
		if kind == other {
			other = c7v11Both[1]
		}
		t.Run(string(kind), func(t *testing.T) {
			if slices.Contains(authz.DefaultAdminKinds, kind) {
				t.Fatal("in DefaultAdminKinds")
			}
			if err := authz.ValidateAdminKinds([]authz.RequestKind{kind}); err != nil {
				t.Errorf("not an admin kind: %v", err)
			}
			for name, kinds := range map[string][]authz.RequestKind{
				"pinned without a list":           nil,
				"only node.network_baseline_ack":  {authz.KindNodeNetworkBaselineAck},
				"only the other sensor kind":      {other},
				"the 0.5 kinds, listed":           slices.Clone(authz.DefaultAdminKinds),
				"an empty list":                   {},
				"every kind but this one, listed": append(slices.Clone(authz.DefaultAdminKinds), authz.KindNodeChangeApproval, authz.KindNodeBaselineAck, authz.KindNodeNetworkBaselineAck, other),
			} {
				if _, err := c7v11Verify(t, kind, c7v11Body(kind), kinds); a6Check(err) != authz.AdminCheckAuthority {
					t.Errorf("%s: %v, want authority", name, err)
				}
			}
			// Control: the same request verifies once the list names the
			// kind, so the list alone refused it above.
			for name, kinds := range map[string][]authz.RequestKind{
				"the kind alone":             {kind},
				"the 0.5 kinds and the kind": append(slices.Clone(authz.DefaultAdminKinds), kind),
				"both sensor kinds":          c7v11Both,
			} {
				p, err := c7v11Verify(t, kind, c7v11Body(kind), kinds)
				if err != nil || p.Kind != kind {
					t.Errorf("%s: %v", name, err)
				}
			}
			// Gated at minor 11: stamped 0.10 or earlier the request is
			// refused before any check of the signature, as invalid; at
			// 0.11 and later it is read.
			p := c7v11Payload(t, kind, c7v11Body(kind))
			for _, stamp := range []string{"otsec.authz/0.10", "otsec.authz/0.6", "otsec.authz/0.4"} {
				if _, err := c7v11Decode(t, stamp, kind, p); refusalCode(err) != authz.RefuseInvalid {
					t.Errorf("stamped %s: %v, want invalid", stamp, err)
				}
			}
			for _, stamp := range []string{"otsec.authz/0.11", "otsec.authz/0.12"} {
				if _, err := c7v11Decode(t, stamp, kind, p); err != nil {
					t.Errorf("stamped %s: %v", stamp, err)
				}
			}
		})
	}
}

// C7-2: the enrolment body's shape, each refusal a payload error.
func TestC7v11C72EnrolShape(t *testing.T) {
	for name, edit := range map[string]func(b map[string]any){
		"IPv4":              func(b map[string]any) {},
		"IPv6":              func(b map[string]any) { b["sensor_address"], b["node_address"] = "[2001:db8::10]:8443", "2001:db8::1" },
		"new at 1":          func(b map[string]any) { b["generation"], b["reason"] = "1", "new" },
		"renew at 2":        func(b map[string]any) { b["reason"] = "renew" },
		"replace at 2":      func(b map[string]any) { b["reason"] = "replace" },
		"port 65535":        func(b map[string]any) { b["sensor_address"] = "192.0.2.10:65535" },
		"generation 2^64-1": func(b map[string]any) { b["generation"] = "18446744073709551615" },
	} {
		b := c7v11Enrol()
		edit(b)
		if _, err := c7v11Verify(t, authz.KindNodeSensorEnrol, b, c7v11Both); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	upper := "sha256:" + strings.ToUpper(strings.TrimPrefix(c7v11SensorPin, "sha256:"))
	refused := map[string]func(b map[string]any){
		"a hostname":                     func(b map[string]any) { b["sensor_address"] = "sensor-a.example:8443" },
		"port 0":                         func(b map[string]any) { b["sensor_address"] = "192.0.2.10:0" },
		"no port":                        func(b map[string]any) { b["sensor_address"] = "192.0.2.10" },
		"IPv6 with no brackets":          func(b map[string]any) { b["sensor_address"] = "2001:db8::10:8443" },
		"IPv6 with a zone":               func(b map[string]any) { b["sensor_address"] = "[fe80::10%eth0]:8443" },
		"node_address a hostname":        func(b map[string]any) { b["node_address"] = "node-a.example" },
		"node_address with a port":       func(b map[string]any) { b["node_address"] = "192.0.2.1:8443" },
		"node_address in brackets":       func(b map[string]any) { b["node_address"] = "[2001:db8::1]" },
		"node_address with a zone":       func(b map[string]any) { b["node_address"] = "fe80::1%eth0" },
		"an uppercase hex digit, sensor": func(b map[string]any) { b["sensor_spki"] = upper },
		"an uppercase hex digit, node":   func(b map[string]any) { b["node_spki"] = upper },
		"a pin with no sha256: prefix":   func(b map[string]any) { b["sensor_spki"] = strings.TrimPrefix(c7v11SensorPin, "sha256:") },
		"equal pins":                     func(b map[string]any) { b["node_spki"] = c7v11SensorPin },
		"an uppercase sensor_id":         func(b map[string]any) { b["sensor_id"] = strings.ToUpper(c7v11Sensor) },
		"generation 0":                   func(b map[string]any) { b["generation"] = "0" },
		"generation 01":                  func(b map[string]any) { b["generation"] = "01" },
		"generation 2^64":                func(b map[string]any) { b["generation"] = "18446744073709551616" },
		"generation as a number":         func(b map[string]any) { b["generation"] = 2 },
		"not_after with offset +00:00":   func(b map[string]any) { b["not_after"] = "2027-10-26T00:00:00+00:00" },
		"not_after with offset +01:00":   func(b map[string]any) { b["not_after"] = "2027-10-26T01:00:00+01:00" },
		"an unknown reason":              func(b map[string]any) { b["reason"] = "move" },
		"new at generation 2":            func(b map[string]any) { b["reason"] = "new" },
		"renew at generation 1":          func(b map[string]any) { b["generation"], b["reason"] = "1", "renew" },
		"an unknown field":               func(b map[string]any) { b["sensor_hostname"] = "sensor-a.example" },
	}
	for _, k := range []string{"sensor_id", "generation", "sensor_spki", "sensor_address", "node_spki", "node_address", "not_after", "reason"} {
		refused["without "+k] = func(b map[string]any) { delete(b, k) }
	}
	for name, edit := range refused {
		b := c7v11Enrol()
		edit(b)
		if _, err := c7v11Verify(t, authz.KindNodeSensorEnrol, b, c7v11Both); a6Check(err) != authz.AdminCheckPayload {
			t.Errorf("%s: %v, want payload", name, err)
		}
	}

	// Controls. A decoder that is not strict reads the body with the unknown
	// field, and the body then passes its own check: strictness alone
	// refused it. And RFC 3339 takes the offset form as the same instant:
	// the rule that the time ends in Z alone refused it.
	b := c7v11Enrol()
	b["sensor_hostname"] = "sensor-a.example"
	var lax authz.NodeSensorEnrolBody
	if err := json.Unmarshal(a6JSON(t, b), &lax); err != nil || lax.Validate() != nil {
		t.Errorf("control: a lax decode of the body with an unknown field: %v, %v", err, lax.Validate())
	}
	off, err1 := time.Parse(time.RFC3339, "2027-10-26T00:00:00+00:00")
	z, err2 := time.Parse(time.RFC3339, "2027-10-26T00:00:00Z")
	if err1 != nil || err2 != nil || !off.Equal(z) {
		t.Errorf("control: RFC 3339 reads the offset form: %v, %v", err1, err2)
	}
}

// C7-3: the revocation body's shape, and suspect_from not after issued_at,
// compared as instants.
func TestC7v11C73RevokeShape(t *testing.T) {
	issued, err := time.Parse(time.RFC3339, a6Payload(t, authz.KindCredentialRevoke)["issued_at"].(string))
	if err != nil {
		t.Fatal(err)
	}
	at := func(d time.Duration) string { return issued.Add(d).UTC().Format(time.RFC3339Nano) }
	accepted := map[string]func(b map[string]any){
		"with suspect_from":         func(b map[string]any) {},
		"without suspect_from":      func(b map[string]any) { delete(b, "suspect_from") },
		"suspect_from at issued_at": func(b map[string]any) { b["suspect_from"] = at(0) },
		"suspect_from 1 s before":   func(b map[string]any) { b["suspect_from"] = at(-time.Second) },
		"lost":                      func(b map[string]any) { b["reason"] = "lost" },
		"retired":                   func(b map[string]any) { b["reason"] = "retired" },
	}
	for name, edit := range accepted {
		b := c7v11Revoke()
		edit(b)
		if _, err := c7v11Verify(t, authz.KindNodeSensorRevoke, b, c7v11Both); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	late := map[string]string{"suspect_from 1 s after issued_at": at(time.Second), "suspect_from 0.5 s after issued_at": at(500 * time.Millisecond)}
	refused := map[string]func(b map[string]any){
		"an unknown reason":        func(b map[string]any) { b["reason"] = "stolen" },
		"an enrolment's reason":    func(b map[string]any) { b["reason"] = "renew" },
		"suspect_from with offset": func(b map[string]any) { b["suspect_from"] = "2026-10-26T12:00:00+00:00" },
		"generation 0":             func(b map[string]any) { b["generation"] = "0" },
		"an uppercase hex digit":   func(b map[string]any) { b["sensor_spki"] = strings.ToUpper(c7v11SensorPin) },
		"an unknown field":         func(b map[string]any) { b["applied_at"] = at(0) },
		"without reason":           func(b map[string]any) { delete(b, "reason") },
		"without sensor_spki":      func(b map[string]any) { delete(b, "sensor_spki") },
	}
	for name, v := range late {
		refused[name] = func(b map[string]any) { b["suspect_from"] = v }
	}
	for name, edit := range refused {
		b := c7v11Revoke()
		edit(b)
		if _, err := c7v11Verify(t, authz.KindNodeSensorRevoke, b, c7v11Both); a6Check(err) != authz.AdminCheckPayload {
			t.Errorf("%s: %v, want payload", name, err)
		}
	}
	// Control: each late suspect_from is a valid body on its own, so the
	// comparison with issued_at alone refused it.
	for name, v := range late {
		b := authz.NodeSensorRevokeBody{SensorID: c7v11Sensor, Generation: "2", SensorSPKI: c7v11SensorPin, Reason: authz.SensorRevokeCompromised, SuspectFrom: v}
		if err := b.Validate(); err != nil {
			t.Errorf("control, %s: the body alone: %v", name, err)
		}
	}
}

// C7-7: the schema gains the two kinds and bodies, with one golden of each,
// signed by the test admin key its README names.
func TestC7v11C77SchemaAndGoldens(t *testing.T) {
	sum := sha256.Sum256([]byte("otsec test admin key 1"))
	priv := ed25519.NewKeyFromSeed(sum[:])
	keys := []authz.AdminKey{{KeyID: a6KeyID(priv), PublicKey: priv.Public().(ed25519.PublicKey), Principal: "alice@site-a",
		Status: authz.KeyActive, Kinds: c7v11Both}}

	raw, err := os.ReadFile(filepath.Join("..", "..", "contracts", "authz", "schema", "admin-request.json"))
	if err != nil {
		t.Fatal(err)
	}
	var schema map[string]any
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatal(err)
	}
	if schema["$id"] != "otsec.authz/0.11/admin-request" {
		t.Errorf("$id %v", schema["$id"])
	}
	props := schema["properties"].(map[string]any)
	kinds, _ := props["kind"].(map[string]any)["enum"].([]any)
	for _, k := range c7v11Both {
		if !slices.Contains(kinds, any(string(k))) {
			t.Errorf("the kind enum lacks %s", k)
		}
	}
	oneOf, _ := json.Marshal(schema["oneOf"])

	// Each body, from §11.1: its required fields, its other fields, and its
	// reasons.
	for _, c := range []struct {
		kind     authz.RequestKind
		golden   string
		required []string
		optional []string
		reasons  []string
	}{
		{authz.KindNodeSensorEnrol, "admin-signed-node-sensor-enrol.json",
			[]string{"sensor_id", "generation", "sensor_spki", "sensor_address", "node_spki", "node_address", "not_after", "reason"}, nil,
			[]string{"new", "renew", "rekey", "replace"}},
		{authz.KindNodeSensorRevoke, "admin-signed-node-sensor-revoke.json",
			[]string{"sensor_id", "generation", "sensor_spki", "reason"}, []string{"suspect_from"},
			[]string{"compromised", "lost", "retired"}},
	} {
		t.Run(string(c.kind), func(t *testing.T) {
			field := c7v11Field[c.kind]
			body, _ := props[field].(map[string]any)
			if body == nil || body["additionalProperties"] != false {
				t.Fatalf("%s: %v, want an object with no other properties", field, body)
			}
			if got := c7v11Strings(body["required"]); !c7v11SameSet(got, c.required) {
				t.Errorf("required %v, want %v", got, c.required)
			}
			var names []string
			for k := range body["properties"].(map[string]any) {
				names = append(names, k)
			}
			if want := append(slices.Clone(c.required), c.optional...); !c7v11SameSet(names, want) {
				t.Errorf("properties %v, want %v", names, want)
			}
			reason := body["properties"].(map[string]any)["reason"].(map[string]any)
			if got := c7v11Strings(reason["enum"]); !c7v11SameSet(got, c.reasons) {
				t.Errorf("reasons %v, want %v", got, c.reasons)
			}
			if !strings.Contains(string(oneOf), `{"required":["`+field+`"]}`) {
				t.Errorf("oneOf does not name %s", field)
			}

			// The golden is read and verified, its kind and body are the
			// one the schema states, and it holds every required field.
			b, err := os.ReadFile(filepath.Join("..", "..", "contracts", "authz", "testdata", "requests", "valid", c.golden))
			if err != nil {
				t.Fatal(err)
			}
			req, err := authz.DecodeRequest(b)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if req.Contract != "otsec.authz/0.11" || req.Kind != c.kind {
				t.Errorf("contract %s, kind %s", req.Contract, req.Kind)
			}
			p, err := authz.VerifyAdminRequest(req, keys, a6Bind, a6Now)
			if err != nil {
				t.Fatalf("verify: %v", err)
			}
			if (p.NodeSensorEnrol != nil) != (c.kind == authz.KindNodeSensorEnrol) || (p.NodeSensorRevoke != nil) != (c.kind == authz.KindNodeSensorRevoke) {
				t.Errorf("the verified payload carries the wrong body")
			}
			var payload map[string]any
			if err := json.Unmarshal(req.AdminSigned.Payload, &payload); err != nil {
				t.Fatal(err)
			}
			gb, _ := payload[field].(map[string]any)
			for _, k := range c.required {
				if _, ok := gb[k]; !ok {
					t.Errorf("the golden lacks %s", k)
				}
			}
			for k := range gb {
				if !slices.Contains(names, k) {
					t.Errorf("the golden carries %s, which the schema does not hold", k)
				}
			}
		})
	}
}

func c7v11Strings(v any) []string {
	var out []string
	for _, s := range v.([]any) {
		out = append(out, s.(string))
	}
	return out
}

func c7v11SameSet(a, b []string) bool {
	a, b = slices.Clone(a), slices.Clone(b)
	slices.Sort(a)
	slices.Sort(b)
	return slices.Equal(a, b)
}
