package authz

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"
)

// testPin is "sha256:" and the SHA-256 of s: a test key's pin. No key has
// either pin below.
func testPin(s string) string {
	sum := sha256.Sum256([]byte(s))
	return "sha256:" + hex.EncodeToString(sum[:])
}

var (
	testSensorPin = testPin("otsec test sensor key")
	testNodePin   = testPin("otsec test node link key")
)

func testEnrolBody() *NodeSensorEnrolBody {
	return &NodeSensorEnrolBody{SensorID: testSensorID, Generation: "2", SensorSPKI: testSensorPin,
		SensorAddress: "192.0.2.10:8443", NodeSPKI: testNodePin, NodeAddress: "192.0.2.1",
		NotAfter: "2027-10-26T00:00:00Z", Reason: SensorEnrolRekey}
}

func testRevokeBody() *NodeSensorRevokeBody {
	return &NodeSensorRevokeBody{SensorID: testSensorID, Generation: "2", SensorSPKI: testSensorPin,
		Reason: SensorRevokeCompromised, SuspectFrom: "2026-10-26T12:00:00Z"}
}

func enrolRequest(t *testing.T, edit func(b *NodeSensorEnrolBody)) *CollectorRequest {
	t.Helper()
	p := adminPayload(t, KindNodeSensorEnrol)
	if edit != nil {
		edit(p.NodeSensorEnrol)
	}
	return signedRequest(t, testAdminPriv, p)
}

func revokeRequest(t *testing.T, edit func(b *NodeSensorRevokeBody)) *CollectorRequest {
	t.Helper()
	p := adminPayload(t, KindNodeSensorRevoke)
	if edit != nil {
		edit(p.NodeSensorRevoke)
	}
	return signedRequest(t, testAdminPriv, p)
}

// C7-2 and C7-3: the goldens' bodies verify, with an IPv4 and an IPv6
// address, and a revocation with and without suspect_from. These are the
// controls of the refusals below: each refused request differs from one of
// them in one field.
func TestSensorKindsVerify(t *testing.T) {
	for name, req := range map[string]*CollectorRequest{
		"enrol, IPv4": enrolRequest(t, nil),
		"enrol, IPv6": enrolRequest(t, func(b *NodeSensorEnrolBody) {
			b.SensorAddress, b.NodeAddress = "[2001:db8::10]:8443", "2001:db8::1"
		}),
		"enrol, new at 1":           enrolRequest(t, func(b *NodeSensorEnrolBody) { b.Generation, b.Reason = "1", SensorEnrolNew }),
		"enrol, renew":              enrolRequest(t, func(b *NodeSensorEnrolBody) { b.Reason = SensorEnrolRenew }),
		"enrol, replace":            enrolRequest(t, func(b *NodeSensorEnrolBody) { b.Reason = SensorEnrolReplace }),
		"revoke, suspect_from":      revokeRequest(t, nil),
		"revoke, from enrolment":    revokeRequest(t, func(b *NodeSensorRevokeBody) { b.SuspectFrom = "" }),
		"revoke, at issued_at":      revokeRequest(t, func(b *NodeSensorRevokeBody) { b.SuspectFrom = "2026-10-26T14:58:00Z" }),
		"revoke, lost":              revokeRequest(t, func(b *NodeSensorRevokeBody) { b.Reason = SensorRevokeLost }),
		"revoke, retired":           revokeRequest(t, func(b *NodeSensorRevokeBody) { b.Reason = SensorRevokeRetired }),
		"revoke, generation 2^64-1": revokeRequest(t, func(b *NodeSensorRevokeBody) { b.Generation = "18446744073709551615" }),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := VerifyAdminRequest(roundTrip(t, req), testAdminKeys(), testAdminBind, testAdminNow); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// C7-2: each of these is a payload error.
func TestSensorEnrolBodyRefused(t *testing.T) {
	for name, edit := range map[string]func(b *NodeSensorEnrolBody){
		"sensor_id uppercase":          func(b *NodeSensorEnrolBody) { b.SensorID = strings.ToUpper(b.SensorID) },
		"a hostname":                   func(b *NodeSensorEnrolBody) { b.SensorAddress = "sensor.example:8443" },
		"no port":                      func(b *NodeSensorEnrolBody) { b.SensorAddress = "192.0.2.10" },
		"port 0":                       func(b *NodeSensorEnrolBody) { b.SensorAddress = "192.0.2.10:0" },
		"port 65536":                   func(b *NodeSensorEnrolBody) { b.SensorAddress = "192.0.2.10:65536" },
		"IPv6 without brackets":        func(b *NodeSensorEnrolBody) { b.SensorAddress = "2001:db8::10:8443" },
		"IPv6 with a zone":             func(b *NodeSensorEnrolBody) { b.SensorAddress = "[fe80::10%eth0]:8443" },
		"IPv6 not in its written form": func(b *NodeSensorEnrolBody) { b.SensorAddress = "[2001:DB8::10]:8443" },
		"node_address with a port":     func(b *NodeSensorEnrolBody) { b.NodeAddress = "192.0.2.1:8443" },
		"node_address in brackets":     func(b *NodeSensorEnrolBody) { b.NodeAddress = "[2001:db8::1]" },
		"node_address with a zone":     func(b *NodeSensorEnrolBody) { b.NodeAddress = "fe80::1%eth0" },
		"node_address a hostname":      func(b *NodeSensorEnrolBody) { b.NodeAddress = "node.example" },
		"an uppercase hex digit":       func(b *NodeSensorEnrolBody) { b.SensorSPKI = strings.ToUpper(b.SensorSPKI[:8]) + b.SensorSPKI[8:] },
		"sensor_spki not a pin":        func(b *NodeSensorEnrolBody) { b.SensorSPKI = strings.TrimPrefix(b.SensorSPKI, "sha256:") },
		"node_spki absent":             func(b *NodeSensorEnrolBody) { b.NodeSPKI = "" },
		"equal pins":                   func(b *NodeSensorEnrolBody) { b.NodeSPKI = b.SensorSPKI },
		"generation 0":                 func(b *NodeSensorEnrolBody) { b.Generation = "0" },
		"generation 01":                func(b *NodeSensorEnrolBody) { b.Generation = "01" },
		"generation over 64 bits":      func(b *NodeSensorEnrolBody) { b.Generation = "18446744073709551616" },
		"not_after with an offset":     func(b *NodeSensorEnrolBody) { b.NotAfter = "2027-10-26T03:00:00+03:00" },
		"not_after absent":             func(b *NodeSensorEnrolBody) { b.NotAfter = "" },
		"an unknown reason":            func(b *NodeSensorEnrolBody) { b.Reason = "restore" },
		"new at generation 2":          func(b *NodeSensorEnrolBody) { b.Reason = SensorEnrolNew },
		"renew at generation 1":        func(b *NodeSensorEnrolBody) { b.Generation, b.Reason = "1", SensorEnrolRenew },
		"rekey at generation 1":        func(b *NodeSensorEnrolBody) { b.Generation = "1" },
	} {
		t.Run(name, func(t *testing.T) {
			req := roundTrip(t, enrolRequest(t, edit))
			if _, err := VerifyAdminRequest(req, testAdminKeys(), testAdminBind, testAdminNow); adminCheck(err) != AdminCheckPayload {
				t.Fatalf("%v, want payload", err)
			}
		})
	}
}

// C7-3: each of these is a payload error. suspect_from one second after
// issued_at is refused; at issued_at, it verifies (TestSensorKindsVerify).
func TestSensorRevokeBodyRefused(t *testing.T) {
	for name, edit := range map[string]func(b *NodeSensorRevokeBody){
		"an unknown reason":           func(b *NodeSensorRevokeBody) { b.Reason = "rotated" },
		"suspect_from after issued":   func(b *NodeSensorRevokeBody) { b.SuspectFrom = "2026-10-26T14:58:01Z" },
		"suspect_from with an offset": func(b *NodeSensorRevokeBody) { b.SuspectFrom = "2026-10-26T15:00:00+03:00" },
		"generation 01":               func(b *NodeSensorRevokeBody) { b.Generation = "01" },
		"sensor_spki absent":          func(b *NodeSensorRevokeBody) { b.SensorSPKI = "" },
		"sensor_id absent":            func(b *NodeSensorRevokeBody) { b.SensorID = "" },
	} {
		t.Run(name, func(t *testing.T) {
			req := roundTrip(t, revokeRequest(t, edit))
			if _, err := VerifyAdminRequest(req, testAdminKeys(), testAdminBind, testAdminNow); adminCheck(err) != AdminCheckPayload {
				t.Fatalf("%v, want payload", err)
			}
		})
	}
}

// C7-2: the payload is decoded strictly, so an unknown field in either body
// is a payload error. Control: the same bytes without it verify
// (TestSensorKindsVerify).
func TestSensorKindUnknownField(t *testing.T) {
	for _, kind := range []RequestKind{KindNodeSensorEnrol, KindNodeSensorRevoke} {
		t.Run(string(kind), func(t *testing.T) {
			p := adminPayload(t, kind)
			payload, err := json.Marshal(p)
			if err != nil {
				t.Fatal(err)
			}
			payload = bytes.Replace(payload, []byte(`"sensor_id":`), []byte(`"port":8443,"sensor_id":`), 1)
			env := &AdminSigned{KeyID: p.AdminKeyID, Algorithm: "ed25519", Payload: payload,
				Signature: ed25519.Sign(testAdminPriv, AdminSigningInput(kind, payload))}
			req := &CollectorRequest{Contract: ContractID, Kind: kind, RequestID: "req-20261026-0001",
				OnBehalfOf: p.Principal, PolicyVersion: 3, AdminSigned: env}
			if _, err := VerifyAdminRequest(roundTrip(t, req), testAdminKeys(), testAdminBind, testAdminNow); adminCheck(err) != AdminCheckPayload {
				t.Fatalf("%v, want payload", err)
			}
		})
	}
}

// C7-1: a request stamped 0.10 cannot ask for either kind. Control: the
// same request stamped 0.11 decodes.
func TestSensorKindsStamped010(t *testing.T) {
	for _, req := range []*CollectorRequest{enrolRequest(t, nil), revokeRequest(t, nil)} {
		t.Run(string(req.Kind), func(t *testing.T) {
			b, err := json.Marshal(req)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := DecodeRequest(b); err != nil {
				t.Fatalf("stamped %s: %v", req.Contract, err)
			}
			req.Contract = "otsec.authz/0.10"
			if b, err = json.Marshal(req); err != nil {
				t.Fatal(err)
			}
			if _, err := DecodeRequest(b); refusalCode(err) != RefuseInvalid {
				t.Fatalf("stamped 0.10: %v, want invalid", err)
			}
		})
	}
}

// C7-1 and SL-7: each kind is a grant of its own. A key pinned without a
// list, a key that holds only node.network_baseline_ack, and a key that
// holds only the other sensor kind are each refused (authority). Control: a
// key whose list names the kind signs it.
func TestSensorKindsAuthority(t *testing.T) {
	only := func(kinds ...RequestKind) []AdminKey {
		keys := testAdminKeys()
		keys[0].Kinds = kinds
		return keys
	}
	enrol, revoke := roundTrip(t, enrolRequest(t, nil)), roundTrip(t, revokeRequest(t, nil))
	for name, c := range map[string]struct {
		req  *CollectorRequest
		keys []AdminKey
	}{
		"unlisted key, enrol":      {enrol, only()},
		"unlisted key, revoke":     {revoke, func() []AdminKey { k := testAdminKeys(); k[0].Kinds = nil; return k }()},
		"network ack key, enrol":   {enrol, only(KindNodeNetworkBaselineAck)},
		"network ack key, revoke":  {revoke, only(KindNodeNetworkBaselineAck)},
		"revoke key signs enrol":   {enrol, only(KindNodeSensorRevoke)},
		"enrol key signs revoke":   {revoke, only(KindNodeSensorEnrol)},
		"0.5 default kinds, enrol": {enrol, only(DefaultAdminKinds...)},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := VerifyAdminRequest(c.req, c.keys, testAdminBind, testAdminNow); adminCheck(err) != AdminCheckAuthority {
				t.Fatalf("%v, want authority", err)
			}
		})
	}
	if _, err := VerifyAdminRequest(enrol, only(KindNodeSensorEnrol), testAdminBind, testAdminNow); err != nil {
		t.Fatalf("a key that lists enrol: %v", err)
	}
	if _, err := VerifyAdminRequest(revoke, only(KindNodeSensorRevoke), testAdminBind, testAdminNow); err != nil {
		t.Fatalf("a key that lists revoke: %v", err)
	}
	if slices.Contains(DefaultAdminKinds, KindNodeSensorEnrol) || slices.Contains(DefaultAdminKinds, KindNodeSensorRevoke) {
		t.Fatal("a sensor kind is in DefaultAdminKinds")
	}
}

// C7-7: the goldens are what the test key signs, and they verify.
func TestSensorKindGoldens(t *testing.T) {
	for path, req := range map[string]*CollectorRequest{
		"testdata/requests/valid/admin-signed-node-sensor-enrol.json":  enrolRequest(t, nil),
		"testdata/requests/valid/admin-signed-node-sensor-revoke.json": revokeRequest(t, nil),
	} {
		t.Run(path, func(t *testing.T) {
			want, err := json.MarshalIndent(req, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			want = append(want, '\n')
			if os.Getenv("OTSEC_UPDATE_GOLDEN") == "1" {
				if err := os.WriteFile(path, want, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			got, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("%s differs from what the test key signs; rerun with OTSEC_UPDATE_GOLDEN=1 if the change is intended", path)
			}
			dec, err := DecodeRequest(got)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := VerifyAdminRequest(dec, testAdminKeys(), testAdminBind, testAdminNow); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestValidGeneration(t *testing.T) {
	for s, want := range map[string]bool{
		"1": true, "2": true, "18446744073709551615": true,
		"": false, "0": false, "01": false, "+1": false, "-1": false, "1.0": false, " 1": false,
		"18446744073709551616": false,
	} {
		if got := ValidGeneration(s); got != want {
			t.Errorf("ValidGeneration(%q) = %v, want %v", s, got, want)
		}
	}
}
