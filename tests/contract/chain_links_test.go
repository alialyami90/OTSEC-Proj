package contract

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"otsec.local/otsec/contracts/asset"
	"otsec.local/otsec/contracts/authz"
	"otsec.local/otsec/contracts/register"
)

// Links of the chain in chain_test.go, one per merged contract. Inputs are
// A6's ground truth (gtID, gtSER) and the merged SEL-751 content (the C3
// register and the C1 capability profile), never an owner's examples.

// allowedFID is a firmware ID the merged register lists on an allowed
// branch (R501, no conditions). Figure 7.38's own FID is on R301, which the
// register denies, so the documented example can never be collected from.
const allowedFID = "SEL-751-R501-V0-Z104101-D20260910"

func chainC3(t *testing.T) {
	pkg := sel751Package(t)
	m, err := register.NewMatcher(pkg)
	if err != nil {
		t.Fatal(err)
	}
	for line, want := range map[string]string{"ID": "sel.id", "SER": "sel.ser.read_all"} {
		v, id := m.Match(line)
		if v != register.VerdictOperation || id != want {
			t.Errorf("%s: %s %s, want operation %s", line, v, id, want)
		}
	}
	for _, line := range []string{"ACC", "QUI"} {
		if v, _ := m.Match(line); v != register.VerdictSessionControl {
			t.Errorf("%s: %s, want session-control", line, v)
		}
		if _, _, err := m.Permit(register.PhaseOperate, line); err == nil {
			t.Errorf("%s permitted as an operation", line)
		}
	}
	if _, _, err := m.Permit(register.PhaseAuth, "ACC"); err != nil {
		t.Errorf("ACC in the auth phase: %v", err)
	}
	if _, err := pkg.Firmware.Decide(gtID[0].Value); err == nil {
		t.Errorf("Figure 7.38 FID %s (denied branch) allowed", gtID[0].Value)
	}
	if _, err := pkg.Firmware.Decide(gtSERHeader.FID); err == nil {
		t.Errorf("Figure 10.16 FID %s (denied branch) allowed", gtSERHeader.FID)
	}
	if _, err := pkg.Firmware.Decide(allowedFID); err != nil {
		t.Errorf("allowed FID %s refused: %v", allowedFID, err)
	}
}

const chainAsset = "0b6c2f4e-1d3a-4c5b-8e7f-9a0b1c2d3e4f"

func chainC7(t *testing.T) {
	pkg := sel751Package(t)
	m, err := register.NewMatcher(pkg)
	if err != nil {
		t.Fatal(err)
	}
	req, err := authz.DecodeRequest([]byte(c7Run))
	if err != nil {
		t.Fatalf("collector request: %v", err)
	}
	if req.Run == nil || req.Run.AssetID != chainAsset || req.Run.OperationID != "sel.ser.read_all" {
		t.Fatalf("decoded run: %+v", req.Run)
	}
	if err := req.Run.ValidateAgainst(m); err != nil {
		t.Errorf("run against the register: %v", err)
	}
	op, ok := m.Operation(req.Run.OperationID)
	if !ok {
		t.Fatal("operation not in the register")
	}
	if err := authz.CheckAccessLevel(pkg, op.AccessLevel); err != nil {
		t.Errorf("credential level for %s: %v", op.ID, err)
	}
	for name, bad := range map[string]string{
		"unknown field": strings.Replace(c7Run, `"params": {}`, `"params": {}, "line": "SER"`, 1),
		"raw secret":    strings.Replace(c7Run, `"credential_ref": "cred_a6a6a6a6"`, `"credential_ref": "cred_a6a6a6a6", "password": "Otter#2026"`, 1),
	} {
		if _, err := authz.DecodeRequest([]byte(bad)); refusalCode(err) != authz.RefuseUnknownField {
			t.Errorf("%s: got %v", name, err)
		}
	}
}

// chainC1 builds the identity record a collector would write from Figure
// 7.38, then checks the credential gate. Spans are byte offsets into the ID
// output as A6 transcribed it, lines joined with CRLF.
func chainC1(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "contracts", "asset", "testdata", "valid", "profile-sel-751-ascii.json"))
	if err != nil {
		t.Fatal(err)
	}
	prof, err := asset.DecodeProfile(b)
	if err != nil {
		t.Fatal(err)
	}
	out := strings.Join(readLines(t, "id-fig-7-38.txt"), "\r\n") + "\r\n"
	const session = "6f1c2b9e-3d4a-4c1e-9b7a-2f0e8d5c1a30"
	const at = "2026-10-24T12:00:00Z"
	fromID := func(name, field string) asset.Attribute {
		var value string
		for _, f := range gtID {
			if f.Field == field {
				value = f.Value
			}
		}
		off := strings.Index(out, `"`+field+"="+value+`"`)
		if value == "" || off < 0 {
			t.Fatalf("%s not in the ID output", field)
		}
		off += len(field) + 2
		return asset.Attribute{Name: name, Value: value, Confidence: asset.Confidence("single-source"),
			Observations: []asset.Observation{{Value: value, EvidenceClass: asset.EvidenceClass("simulated"),
				Source: asset.Source{Method: asset.SourceMethod("simulator-session"), Ref: session, ObservedAt: at,
					Span: &asset.Span{Offset: int64(off), Length: int64(len(value))}}}}}
	}
	declared := func(name, value string) asset.Attribute {
		return asset.Attribute{Name: name, Value: value, Confidence: asset.Confidence("single-source"),
			Observations: []asset.Observation{{Value: value, EvidenceClass: asset.EvidenceClass("operator-declared"),
				Source: asset.Source{Method: asset.SourceMethod("operator-entry"), Ref: "operator:a6-chain", ObservedAt: at}}}}
	}
	// A bound attribute needs an operator-declared value to compare the
	// device's report against (C1, AP-27): the commissioning sheet's FID.
	corroborated := func(at asset.Attribute) asset.Attribute {
		d := declared(at.Name, at.Value).Observations[0]
		at.Observations = append([]asset.Observation{d}, at.Observations...)
		at.Confidence = asset.Confidence("corroborated")
		return at
	}
	a := asset.Asset{
		Schema:  "otsec.asset/0.1",
		AssetID: chainAsset,
		NodeID:  "site-a6-node-1",
		Attributes: []asset.Attribute{
			declared("device_class", "protective-relay"),
			declared("vendor", "sel"),
			declared("product_family", "sel-751"),
			corroborated(fromID("firmware_id", "FID")),
			fromID("sel.cid", "CID"),
			declared("serial_number", "A6CHAIN000000001"),
			declared("ip_address", "192.0.2.61"),
		},
		Endpoints: []asset.Endpoint{{ID: "port1-telnet", Transport: asset.Transport("telnet"), Host: "192.0.2.61", Port: 23,
			DownstreamSecurity: asset.DownstreamSecurity{Level: asset.SecurityLevel("plaintext-unauthenticated"),
				Acknowledgement: &asset.Acknowledgement{By: "admin:a6", At: at, Reason: "A6 chain test, simulated, lab only", Scope: asset.AckScope("lab-only")}}}},
		IdentityBinding: asset.IdentityBinding{Method: asset.BindingMethod("device-reported"), Strength: asset.BindingStrength("spoofable"),
			Attributes: []string{"firmware_id", "serial_number"}, PreCredential: []string{"firmware_id"}},
		Profile: &asset.ProfileRef{ID: prof.ProfileID, Version: prof.Version},
	}
	if err := a.Validate(); err != nil {
		t.Fatalf("identity record from Figure 7.38: %v", err)
	}
	for _, f := range []struct{ name, field string }{{"firmware_id", "FID"}, {"sel.cid", "CID"}} {
		at, ok := a.Attribute(f.name)
		sp := at.Observations[len(at.Observations)-1].Source.Span
		if !ok || out[sp.Offset:sp.Offset+sp.Length] != at.Value {
			t.Errorf("%s: span does not cover the value in the ID output", f.name)
		}
	}
	if err := a.CredentialAllowed(prof); err != nil {
		t.Errorf("device-reported binding with a pre-credential FID: %v", err)
	}
	// AP-27: an asset bound by address only gets no credential.
	a.IdentityBinding = asset.IdentityBinding{Method: asset.BindingMethod("address-only"), Strength: asset.BindingStrength("spoofable"), Attributes: []string{}}
	if err := a.Validate(); err != nil {
		t.Fatalf("address-only record: %v", err)
	}
	if err := a.CredentialAllowed(prof); err == nil {
		t.Error("address-only asset allowed a credential")
	}
}
