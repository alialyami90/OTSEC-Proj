package authz

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// testKeyEntries are testAdminKeys as an accepted 0.10 reply names them.
func testKeyEntries() []AdminKeyEntry { return AdminKeyEntries(testAdminKeys()) }

func networkAck(t *testing.T, edit func(b *NodeNetworkBaselineAckBody)) *CollectorRequest {
	t.Helper()
	p := adminPayload(t, KindNodeNetworkBaselineAck)
	if edit != nil {
		edit(p.NodeNetworkBaselineAck)
	}
	return signedRequest(t, testAdminPriv, p)
}

func TestNetworkAckVerifies(t *testing.T) {
	for name, edit := range map[string]func(b *NodeNetworkBaselineAckBody){
		"writers added":    nil,
		"no writers added": func(b *NodeNetworkBaselineAckBody) { b.DraftDigest = b.BaselineDigest },
	} {
		t.Run(name, func(t *testing.T) {
			req := roundTrip(t, networkAck(t, edit))
			if _, err := VerifyAdminRequest(req, testAdminKeys(), testAdminBind, testAdminNow); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestNetworkAckBodyRefused(t *testing.T) {
	for name, edit := range map[string]func(b *NodeNetworkBaselineAckBody){
		"sensor_id absent":       func(b *NodeNetworkBaselineAckBody) { b.SensorID = "" },
		"sensor_id uppercase":    func(b *NodeNetworkBaselineAckBody) { b.SensorID = strings.ToUpper(b.SensorID) },
		"draft_digest absent":    func(b *NodeNetworkBaselineAckBody) { b.DraftDigest = "" },
		"draft_digest malformed": func(b *NodeNetworkBaselineAckBody) { b.DraftDigest = "sha256:" + strings.Repeat("A", 64) },
		"baseline_digest absent": func(b *NodeNetworkBaselineAckBody) { b.BaselineDigest = "" },
		"baseline_digest malformed": func(b *NodeNetworkBaselineAckBody) {
			b.BaselineDigest = strings.TrimPrefix(b.BaselineDigest, "sha256:")
		},
	} {
		t.Run(name, func(t *testing.T) {
			req := roundTrip(t, networkAck(t, edit))
			if _, err := VerifyAdminRequest(req, testAdminKeys(), testAdminBind, testAdminNow); adminCheck(err) != AdminCheckPayload {
				t.Fatalf("%v, want payload", err)
			}
		})
	}
}

// An unknown field in the body, such as an asset_id, is a payload error:
// the payload is decoded strictly.
func TestNetworkAckUnknownField(t *testing.T) {
	p := adminPayload(t, KindNodeNetworkBaselineAck)
	payload, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	payload = bytes.Replace(payload, []byte(`"sensor_id":`), []byte(`"asset_id":"2b7d4e10-8c3f-4a5b-9e21-7c4f0d6a8b13","sensor_id":`), 1)
	env := &AdminSigned{KeyID: p.AdminKeyID, Algorithm: "ed25519", Payload: payload,
		Signature: ed25519.Sign(testAdminPriv, AdminSigningInput(KindNodeNetworkBaselineAck, payload))}
	req := &CollectorRequest{Contract: ContractID, Kind: KindNodeNetworkBaselineAck, RequestID: "req-20261026-0001",
		OnBehalfOf: p.Principal, PolicyVersion: 3, AdminSigned: env}
	if _, err := VerifyAdminRequest(roundTrip(t, req), testAdminKeys(), testAdminBind, testAdminNow); adminCheck(err) != AdminCheckPayload {
		t.Fatalf("%v, want payload", err)
	}
}

// A 0.9 request cannot ask for the kind, and a 0.9 reader refuses its body
// as a payload field it does not know.
func TestNetworkAckStamped09(t *testing.T) {
	req := networkAck(t, nil)
	req.Contract = "otsec.authz/0.9"
	b, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeRequest(b); refusalCode(err) != RefuseInvalid {
		t.Fatalf("%v, want invalid", err)
	}
}

// D1 for D4-68: the network acknowledgement is its own grant. A key that
// holds only node.baseline_ack may not sign it, a key that holds only it
// may not sign node.baseline_ack, and a key pinned without a list may sign
// neither.
func TestNetworkAckAuthority(t *testing.T) {
	only := func(k RequestKind) []AdminKey {
		keys := testAdminKeys()
		keys[0].Kinds = []RequestKind{k}
		return keys
	}
	net := roundTrip(t, networkAck(t, nil))
	ack := roundTrip(t, signedRequest(t, testAdminPriv, adminPayload(t, KindNodeBaselineAck)))
	unlisted := testAdminKeys()
	unlisted[0].Kinds = nil
	for name, c := range map[string]struct {
		req  *CollectorRequest
		keys []AdminKey
	}{
		"baseline_ack key signs network":   {net, only(KindNodeBaselineAck)},
		"network key signs baseline_ack":   {ack, only(KindNodeNetworkBaselineAck)},
		"unlisted key signs network":       {net, unlisted},
		"0.5 default kinds do not hold it": {net, func() []AdminKey { k := testAdminKeys(); k[0].Kinds = DefaultAdminKinds; return k }()},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := VerifyAdminRequest(c.req, c.keys, testAdminBind, testAdminNow); adminCheck(err) != AdminCheckAuthority {
				t.Fatalf("%v, want authority", err)
			}
		})
	}
	if _, err := VerifyAdminRequest(net, only(KindNodeNetworkBaselineAck), testAdminBind, testAdminNow); err != nil {
		t.Fatalf("a key that lists the kind: %v", err)
	}
}

// node.baseline_ack never takes kind network: a network baseline is
// acknowledged only through its own kind.
func TestBaselineAckRefusesNetwork(t *testing.T) {
	p := adminPayload(t, KindNodeBaselineAck)
	p.NodeBaselineAck.Kind = BaselineNetwork
	req := roundTrip(t, signedRequest(t, testAdminPriv, p))
	if _, err := VerifyAdminRequest(req, testAdminKeys(), testAdminBind, testAdminNow); adminCheck(err) != AdminCheckPayload {
		t.Fatalf("%v, want payload", err)
	}
}

func TestNetworkAckGolden(t *testing.T) {
	const path = "testdata/requests/valid/admin-signed-node-network-baseline-ack.json"
	want, err := json.MarshalIndent(networkAck(t, nil), "", "  ")
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
}

// The digest changes when a key's kinds, status or principal change, and
// not when only the keys' order in the configuration changes.
func TestAdminKeysDigest(t *testing.T) {
	base := AdminKeysDigest(AdminKeyEntries(testAdminKeys()))
	reordered := testAdminKeys()
	reordered[0], reordered[1] = reordered[1], reordered[0]
	reordered[0].Kinds = []RequestKind{KindNodeSeqResetAck, KindCredentialInstall} // the 0.5 defaults' subset, unsorted
	reordered[1].Kinds = append([]RequestKind{}, reordered[1].Kinds...)
	for i, j := 0, len(reordered[1].Kinds)-1; i < j; i, j = i+1, j-1 {
		reordered[1].Kinds[i], reordered[1].Kinds[j] = reordered[1].Kinds[j], reordered[1].Kinds[i]
	}
	sameOrder := testAdminKeys()
	sameOrder[1].Kinds = []RequestKind{KindNodeSeqResetAck, KindCredentialInstall}
	if AdminKeysDigest(AdminKeyEntries(reordered)) != AdminKeysDigest(AdminKeyEntries(sameOrder)) {
		t.Fatal("the order of keys or kinds in the configuration changed the digest")
	}
	for name, edit := range map[string]func(k []AdminKey){
		"kinds":     func(k []AdminKey) { k[0].Kinds = k[0].Kinds[:len(k[0].Kinds)-1] },
		"status":    func(k []AdminKey) { k[1].Status = KeyRevoked },
		"principal": func(k []AdminKey) { k[1].Principal = "carol@site-a" },
		"a key":     func(k []AdminKey) {},
	} {
		t.Run(name, func(t *testing.T) {
			keys := testAdminKeys()
			if name == "a key" {
				keys = keys[:1]
			} else {
				edit(keys)
			}
			if AdminKeysDigest(AdminKeyEntries(keys)) == base {
				t.Fatal("the digest did not change")
			}
		})
	}
	// A key pinned without a list is written with the defaults it has.
	for _, e := range AdminKeyEntries(testAdminKeys()) {
		if e.Principal == "bob@site-a" && len(e.Kinds) != len(DefaultAdminKinds) {
			t.Fatalf("unlisted key written as %v", e.Kinds)
		}
	}
}

// When an acceptance carries the keys and their digest, the digest must be
// the one over the keys it carries, on a reply stamped 0.10 or later.
// Whether a 0.10 acceptance must carry them is the node's check where it
// orders the grant before the decision (ruling 9), which refuses one that
// does not.
func TestAdminAcceptanceKeys(t *testing.T) {
	req, ok := testAcceptance(t)
	if _, err := ok.AdminAcceptance(req); err != nil {
		t.Fatal(err)
	}
	for name, edit := range map[string]func(r *CollectorReply){
		"digest without keys":  func(r *CollectorReply) { r.Admin.Keys = nil },
		"keys without digest":  func(r *CollectorReply) { r.Admin.KeysDigest = "" },
		"digest of other keys": func(r *CollectorReply) { r.Admin.KeysDigest = AdminKeysDigest(r.Admin.Keys[:1]) },
		"keys out of order": func(r *CollectorReply) {
			r.Admin.Keys = []AdminKeyEntry{r.Admin.Keys[1], r.Admin.Keys[0]}
			r.Admin.KeysDigest = AdminKeysDigest(r.Admin.Keys)
		},
		"unknown kind": func(r *CollectorReply) {
			r.Admin.Keys = append([]AdminKeyEntry{}, r.Admin.Keys...)
			r.Admin.Keys[0].Kinds = []RequestKind{"run"}
			r.Admin.KeysDigest = AdminKeysDigest(r.Admin.Keys)
		},
		"reply stamped 0.9": func(r *CollectorReply) { r.Contract = "otsec.authz/0.9" },
	} {
		t.Run(name, func(t *testing.T) {
			r := ok
			a := *ok.Admin
			r.Admin = &a
			edit(&r)
			if _, err := r.AdminAcceptance(req); err == nil {
				t.Fatal("accepted")
			}
		})
	}
	// A 0.9 request's acceptance carries neither, as a 0.9 collector wrote.
	old := *req
	old.Contract = "otsec.authz/0.9"
	r := ok
	r.Admin = &AdminAccepted{AdminKeyID: ok.Admin.AdminKeyID, Principal: ok.Admin.Principal, Nonce: ok.Admin.Nonce,
		PayloadSHA256: ok.Admin.PayloadSHA256}
	if _, err := r.AdminAcceptance(&old); err != nil {
		t.Fatalf("0.9: %v", err)
	}
}
