package contract

// C7 0.5 (#184, A3; design docs/phase3/A5-signed-admin-files.md): A6's own
// cases for the two admin-signed node kinds, the repeat answer, what an
// acceptance names (CollectorReply.Admin), and the node's one check before
// it acts (AdminAcceptance). Expected outcomes come from the rule text: the
// package documentation ("The node kinds and the repeat answer",
// "Versions"), the #181 design and the #184 description. Keys and payloads
// are A6's (c7_admin_test.go); replies are written here as JSON and read
// through the reader the node uses (collectorwire.DecodeReply).

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"otsec.local/otsec/contracts/authz"
	"otsec.local/otsec/modules/security/collectorwire"
)

const (
	a6Asset    = "2b7d4e10-8c3f-4a5b-9e21-7c4f0d6a8b13"
	a6Manifest = "9f2c4e6a8b0d1f3e5a7c9e1b3d5f7a9c2e4f6a8b0c2d4e6f8a0b2c4d6e8f0a1b" // 64 lowercase hex, A6's
)

// a6NodePayload is a node kind's payload: the golden's binding and times,
// with body as the kind's field, or no body field when body is nil.
func a6NodePayload(t *testing.T, kind authz.RequestKind, body any) map[string]any {
	t.Helper()
	p := a6Payload(t, authz.KindCredentialRevoke)
	delete(p, "credential_revoke")
	p["kind"] = string(kind)
	field := map[authz.RequestKind]string{authz.KindNodeQuarantineClear: "node_quarantine_clear", authz.KindNodeSeqResetAck: "node_seq_reset_ack"}[kind]
	if body != nil {
		p[field] = body
	}
	return p
}

// a6Signed05 is a6Signed stamped 0.5.
func a6Signed05(t *testing.T, kind authz.RequestKind, p map[string]any) *authz.CollectorRequest {
	req := a6Signed(a6AdminPriv, kind, kind, a6JSON(t, p))
	req.Contract = "otsec.authz/0.5"
	return req
}

// a6Decode marshals req and reads it as the collector does.
func a6Decode(t *testing.T, req *authz.CollectorRequest) (*authz.CollectorRequest, error) {
	t.Helper()
	return authz.DecodeRequest(a6JSON(t, req))
}

func TestC7v05NodeKindsVerifyOnlyAt05(t *testing.T) {
	bodies := map[authz.RequestKind]any{
		authz.KindNodeQuarantineClear: map[string]any{"asset_id": a6Asset, "manifest_sha256": a6Manifest},
		authz.KindNodeSeqResetAck:     map[string]any{},
	}
	for kind, body := range bodies {
		t.Run(string(kind), func(t *testing.T) {
			req := a6Signed05(t, kind, a6NodePayload(t, kind, body))
			got, err := a6Decode(t, req)
			if err != nil {
				t.Fatalf("0.5: %v", err)
			}
			if _, err := authz.VerifyAdminRequest(got, a6AdminKeys(), a6Bind, a6Now); err != nil {
				t.Fatalf("0.5 verify: %v", err)
			}
			// The kind did not exist before 0.5: refused before any check
			// of the signature, as invalid.
			for _, c := range []string{"otsec.authz/0.4", "otsec.authz/0.3", "otsec.authz/0.1"} {
				old := *req
				old.Contract = c
				if _, err := a6Decode(t, &old); refusalCode(err) != authz.RefuseInvalid {
					t.Errorf("%s: %v, want invalid", c, err)
				}
			}
			// Never unsigned, whoever sends it.
			for _, by := range []authz.Principal{req.OnBehalfOf, {Type: authz.PrincipalNode, ID: "site-a-node-1"}} {
				u := *req
				u.AdminSigned, u.OnBehalfOf = nil, by
				if _, err := a6Decode(t, &u); refusalCode(err) != authz.RefuseInvalid {
					t.Errorf("unsigned on behalf of %s: %v, want invalid", by.Type, err)
				}
			}
			// The body exists only in the payload.
			b := a6JSON(t, req)
			for _, f := range []string{"node_quarantine_clear", "node_seq_reset_ack"} {
				bad := append(bytes.Clone(bytes.TrimSuffix(b, []byte("}"))), []byte(`,"`+f+`":{}}`)...)
				if _, err := authz.DecodeRequest(bad); refusalCode(err) != authz.RefuseUnknownField {
					t.Errorf("%s outside the payload: %v, want unknown_field", f, err)
				}
			}
		})
	}
}

// A node kind's signature is bound to its kind: the same payload bytes,
// signed for one node kind, never verify as the other, nor as a
// credential kind.
func TestC7v05NodeKindSignatureIsBoundToTheKind(t *testing.T) {
	p := a6NodePayload(t, authz.KindNodeSeqResetAck, map[string]any{})
	payload := a6JSON(t, p)
	for _, reqKind := range []authz.RequestKind{authz.KindNodeQuarantineClear, authz.KindCredentialRevoke} {
		req := a6Signed(a6AdminPriv, authz.KindNodeSeqResetAck, reqKind, payload)
		req.Contract = "otsec.authz/0.5"
		got, err := a6Decode(t, req)
		if err != nil {
			continue // refused before verification is refused
		}
		if _, err := authz.VerifyAdminRequest(got, a6AdminKeys(), a6Bind, a6Now); err == nil {
			t.Errorf("node.seq_reset_ack's signature verified as %s", reqKind)
		}
	}
}

func TestC7v05NodeBodies(t *testing.T) {
	q := func(asset, manifest any) map[string]any {
		m := map[string]any{}
		if asset != nil {
			m["asset_id"] = asset
		}
		if manifest != nil {
			m["manifest_sha256"] = manifest
		}
		return m
	}
	cases := []struct {
		name string
		kind authz.RequestKind
		p    func() map[string]any
	}{
		{"asset ID upper case", authz.KindNodeQuarantineClear, func() map[string]any {
			return a6NodePayload(t, authz.KindNodeQuarantineClear, q(strings.ToUpper(a6Asset), a6Manifest))
		}},
		{"asset ID version 0", authz.KindNodeQuarantineClear, func() map[string]any {
			return a6NodePayload(t, authz.KindNodeQuarantineClear, q("2b7d4e10-8c3f-0a5b-9e21-7c4f0d6a8b13", a6Manifest))
		}},
		{"asset ID a path", authz.KindNodeQuarantineClear, func() map[string]any {
			return a6NodePayload(t, authz.KindNodeQuarantineClear, q("../../store", a6Manifest))
		}},
		{"asset ID missing", authz.KindNodeQuarantineClear, func() map[string]any {
			return a6NodePayload(t, authz.KindNodeQuarantineClear, q(nil, a6Manifest))
		}},
		{"manifest 63 digits", authz.KindNodeQuarantineClear, func() map[string]any {
			return a6NodePayload(t, authz.KindNodeQuarantineClear, q(a6Asset, a6Manifest[:63]))
		}},
		{"manifest 65 digits", authz.KindNodeQuarantineClear, func() map[string]any {
			return a6NodePayload(t, authz.KindNodeQuarantineClear, q(a6Asset, a6Manifest+"0"))
		}},
		{"manifest upper case", authz.KindNodeQuarantineClear, func() map[string]any {
			return a6NodePayload(t, authz.KindNodeQuarantineClear, q(a6Asset, strings.ToUpper(a6Manifest)))
		}},
		{"manifest not hex", authz.KindNodeQuarantineClear, func() map[string]any {
			return a6NodePayload(t, authz.KindNodeQuarantineClear, q(a6Asset, "g"+a6Manifest[1:]))
		}},
		{"manifest missing", authz.KindNodeQuarantineClear, func() map[string]any {
			return a6NodePayload(t, authz.KindNodeQuarantineClear, q(a6Asset, nil))
		}},
		{"quarantine body with an extra field", authz.KindNodeQuarantineClear, func() map[string]any {
			b := q(a6Asset, a6Manifest)
			b["items"] = 3
			return a6NodePayload(t, authz.KindNodeQuarantineClear, b)
		}},
		{"quarantine body missing", authz.KindNodeQuarantineClear, func() map[string]any {
			return a6NodePayload(t, authz.KindNodeQuarantineClear, nil)
		}},
		{"reset body with a field", authz.KindNodeSeqResetAck, func() map[string]any {
			return a6NodePayload(t, authz.KindNodeSeqResetAck, map[string]any{"install_key_id": a6Bind.InstallKeyID})
		}},
		{"reset body missing", authz.KindNodeSeqResetAck, func() map[string]any {
			return a6NodePayload(t, authz.KindNodeSeqResetAck, nil)
		}},
		{"reset body null", authz.KindNodeSeqResetAck, func() map[string]any {
			p := a6NodePayload(t, authz.KindNodeSeqResetAck, nil)
			p["node_seq_reset_ack"] = nil
			return p
		}},
		{"both node bodies", authz.KindNodeSeqResetAck, func() map[string]any {
			p := a6NodePayload(t, authz.KindNodeSeqResetAck, map[string]any{})
			p["node_quarantine_clear"] = q(a6Asset, a6Manifest)
			return p
		}},
		{"a credential body on a node kind", authz.KindNodeSeqResetAck, func() map[string]any {
			p := a6NodePayload(t, authz.KindNodeSeqResetAck, nil)
			p["credential_revoke"] = map[string]any{"ref_id": "cred_7f3k2m9q4x", "reason": "rotated"}
			return p
		}},
		{"a node body on a credential kind", authz.KindCredentialRevoke, func() map[string]any {
			p := a6Payload(t, authz.KindCredentialRevoke)
			p["node_seq_reset_ack"] = map[string]any{}
			return p
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req := a6Signed05(t, c.kind, c.p())
			got, err := a6Decode(t, req)
			if err == nil {
				_, err = authz.VerifyAdminRequest(got, a6AdminKeys(), a6Bind, a6Now)
			}
			if err == nil {
				t.Fatal("accepted")
			}
			if ch := a6Check(err); ch != "" && ch != authz.AdminCheckPayload {
				t.Fatalf("check %q (%v), want payload", ch, err)
			}
		})
	}
}

// a6Reply is an accepted 0.5 reply to req, naming what the collector
// verified, as A6 computes it from the bytes sent.
func a6Reply(req *authz.CollectorRequest, seq uint64) map[string]any {
	sum := sha256.Sum256(req.AdminSigned.Payload)
	return map[string]any{"contract": "otsec.authz/0.5", "request_id": req.RequestID, "status": "accepted", "collector_seq": seq,
		"admin": map[string]any{"admin_key_id": req.AdminSigned.KeyID,
			"principal": map[string]any{"type": "human", "id": req.OnBehalfOf.ID},
			"nonce":     "a6a6a6a6a6a6a6a6a6a6aw", "payload_sha256": hex.EncodeToString(sum[:])}}
}

func a6NodeReq(t *testing.T) *authz.CollectorRequest {
	t.Helper()
	req := a6Signed05(t, authz.KindNodeQuarantineClear,
		a6NodePayload(t, authz.KindNodeQuarantineClear, map[string]any{"asset_id": a6Asset, "manifest_sha256": a6Manifest}))
	got, err := a6Decode(t, req)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func TestC7v05ReplyReader(t *testing.T) {
	req := a6NodeReq(t)
	edit := func(f func(m map[string]any)) []byte {
		m := a6Reply(req, 12)
		f(m)
		return a6JSON(t, m)
	}
	admin := func(m map[string]any) map[string]any { return m["admin"].(map[string]any) }
	valid := map[string][]byte{
		"accepted with admin":         edit(func(map[string]any) {}),
		"a repeat of 7":               edit(func(m map[string]any) { m["repeat_of"] = 7 }),
		"a repeat of 1":               edit(func(m map[string]any) { m["repeat_of"] = 1 }),
		"a repeat of 11 (just below)": edit(func(m map[string]any) { m["repeat_of"] = 11 }),
		"0.4 accepted, no fields": edit(func(m map[string]any) {
			m["contract"] = "otsec.authz/0.4"
			delete(m, "admin")
		}),
		"0.5 refused, no fields": edit(func(m map[string]any) {
			m["status"], m["refusal"] = "refused", map[string]any{"code": "admin_unverified", "check": "replay"}
			delete(m, "admin")
		}),
		"0.6 with admin": edit(func(m map[string]any) { m["contract"] = "otsec.authz/0.6" }),
	}
	for name, b := range valid {
		if _, err := collectorwire.DecodeReply(b); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	invalid := map[string][]byte{
		"admin at 0.4":     edit(func(m map[string]any) { m["contract"] = "otsec.authz/0.4" }),
		"repeat_of at 0.4": edit(func(m map[string]any) { m["contract"], m["repeat_of"] = "otsec.authz/0.4", 7; delete(m, "admin") }),
		"repeat at 0.3":    edit(func(m map[string]any) { m["contract"], m["repeat_of"] = "otsec.authz/0.3", 7 }),
		"admin on a refusal": edit(func(m map[string]any) {
			m["status"], m["refusal"] = "refused", map[string]any{"code": "admin_unverified", "check": "replay"}
		}),
		"repeat_of on a refusal": edit(func(m map[string]any) {
			m["status"], m["refusal"], m["repeat_of"] = "refused", map[string]any{"code": "admin_unverified", "check": "replay"}, 7
			delete(m, "admin")
		}),
		"accepted with a refusal and admin": edit(func(m map[string]any) {
			m["refusal"] = map[string]any{"code": "admin_unverified", "check": "replay"}
		}),
		"a repeat without admin":  edit(func(m map[string]any) { m["repeat_of"] = 7; delete(m, "admin") }),
		"a repeat of itself":      edit(func(m map[string]any) { m["repeat_of"] = 12 }),
		"a repeat of a later one": edit(func(m map[string]any) { m["repeat_of"] = 13 }),
		"admin key ID upper case": edit(func(m map[string]any) { admin(m)["admin_key_id"] = strings.ToUpper(req.AdminSigned.KeyID) }),
		"admin key ID short":      edit(func(m map[string]any) { admin(m)["admin_key_id"] = req.AdminSigned.KeyID[:20] }),
		"admin principal a node": edit(func(m map[string]any) {
			admin(m)["principal"] = map[string]any{"type": "node", "id": "site-a-node-1"}
		}),
		"admin principal no ID": edit(func(m map[string]any) {
			admin(m)["principal"] = map[string]any{"type": "human", "id": ""}
		}),
		"admin nonce 21":           edit(func(m map[string]any) { admin(m)["nonce"] = "a6a6a6a6a6a6a6a6a6a6a" }),
		"admin nonce padded":       edit(func(m map[string]any) { admin(m)["nonce"] = "a6a6a6a6a6a6a6a6a6a6a=" }),
		"admin payload 63":         edit(func(m map[string]any) { admin(m)["payload_sha256"] = a6Manifest[:63] }),
		"admin payload upper":      edit(func(m map[string]any) { admin(m)["payload_sha256"] = strings.ToUpper(a6Manifest) }),
		"admin with another field": edit(func(m map[string]any) { admin(m)["kind"] = "node.quarantine_clear" }),
		"admin null fields": edit(func(m map[string]any) {
			m["admin"] = map[string]any{}
		}),
	}
	for name, b := range invalid {
		if _, err := collectorwire.DecodeReply(b); err == nil {
			t.Errorf("%s: read as valid", name)
		}
	}
}

func TestC7v05AdminAcceptance(t *testing.T) {
	req := a6NodeReq(t)
	read := func(m map[string]any) authz.CollectorReply {
		r, err := collectorwire.DecodeReply(a6JSON(t, m))
		if err != nil {
			t.Fatalf("reply: %v", err)
		}
		return r
	}
	first := read(a6Reply(req, 12))
	a, err := first.AdminAcceptance(req)
	if err != nil {
		t.Fatalf("first acceptance: %v", err)
	}
	if a.PayloadSHA256 != authz.AdminPayloadSHA256(req.AdminSigned) || a.AdminKeyID != a6KeyID(a6AdminPriv) || a.Principal != req.OnBehalfOf {
		t.Fatalf("names %+v", a)
	}
	rep := a6Reply(req, 15)
	rep["repeat_of"] = 12
	if _, err := read(rep).AdminAcceptance(req); err != nil {
		t.Fatalf("repeat: %v", err)
	}

	other := func(f func(r *authz.CollectorRequest)) *authz.CollectorRequest {
		u := *req
		s := *req.AdminSigned
		u.AdminSigned = &s
		f(&u)
		return &u
	}
	type c struct {
		reply map[string]any
		sent  *authz.CollectorRequest
	}
	edit := func(f func(m map[string]any)) map[string]any {
		m := a6Reply(req, 12)
		f(m)
		return m
	}
	cases := map[string]c{
		"the request sent was stamped 0.4": {a6Reply(req, 12), other(func(r *authz.CollectorRequest) { r.Contract = "otsec.authz/0.4" })},
		"the request sent was not signed":  {a6Reply(req, 12), other(func(r *authz.CollectorRequest) { r.AdminSigned = nil })},
		"another request ID":               {edit(func(m map[string]any) { m["request_id"] = "req-a6-0002" }), req},
		"refused, no fields": {edit(func(m map[string]any) {
			m["status"], m["refusal"] = "refused", map[string]any{"code": "admin_unverified", "check": "replay"}
			delete(m, "admin")
		}), req},
		"not numbered":     {edit(func(m map[string]any) { delete(m, "collector_seq") }), req},
		"names nothing":    {edit(func(m map[string]any) { delete(m, "admin") }), req},
		"a 0.4 acceptance": {edit(func(m map[string]any) { m["contract"] = "otsec.authz/0.4"; delete(m, "admin") }), req},
		"other bytes (one payload byte)": {a6Reply(req, 12), other(func(r *authz.CollectorRequest) {
			p := bytes.Clone(r.AdminSigned.Payload)
			p[len(p)-2] ^= 1
			r.AdminSigned.Payload = p
		})},
		"another admin key": {a6Reply(req, 12), other(func(r *authz.CollectorRequest) {
			r.AdminSigned.KeyID = a6KeyID(a6BobPriv)
		})},
		// The reply's nonce must be the payload's (A6 on #184, fixed on #186).
		"another nonce": {edit(func(m map[string]any) {
			m["admin"].(map[string]any)["nonce"] = "b6b6b6b6b6b6b6b6b6b6bw"
		}), req},
		"another person": {a6Reply(req, 12), other(func(r *authz.CollectorRequest) {
			r.OnBehalfOf = authz.Principal{Type: authz.PrincipalHuman, ID: "bob@site-a"}
		})},
	}
	for name, cs := range cases {
		t.Run(name, func(t *testing.T) {
			r, err := collectorwire.DecodeReply(a6JSON(t, cs.reply))
			if err != nil {
				return // the reader refuses it, which is earlier still
			}
			if a, err := r.AdminAcceptance(cs.sent); err == nil {
				t.Fatalf("acted on: %+v", a)
			}
		})
	}
	if _, err := first.AdminAcceptance(nil); err == nil {
		t.Fatal("nil request accepted")
	}

	// AdminAcceptance is the node's one check, so it holds on its own
	// for a reply that never went through the reader.
	direct := map[string]func(r *authz.CollectorReply){
		"another contract's stamp":  func(r *authz.CollectorReply) { r.Contract = "otsec.audit/0.5" },
		"another major":             func(r *authz.CollectorReply) { r.Contract = "otsec.authz/1.5" },
		"not numbered":              func(r *authz.CollectorReply) { r.CollectorSeq = 0 },
		"a refusal naming no check": func(r *authz.CollectorReply) { r.Status = authz.ReplyRefused },
		"a malformed nonce":         func(r *authz.CollectorReply) { r.Admin.Nonce = "x" },
		"a repeat of itself":        func(r *authz.CollectorReply) { r.RepeatOf = r.CollectorSeq },
		"a repeat stamped 0.4":      func(r *authz.CollectorReply) { r.Contract, r.RepeatOf = "otsec.authz/0.4", 3 },
	}
	for name, f := range direct {
		r := first
		ad := *first.Admin
		r.Admin = &ad
		f(&r)
		if a, err := r.AdminAcceptance(req); err == nil {
			t.Errorf("%s: acted on %+v", name, a)
		}
	}
}

func TestC7v05AnswersRepeat(t *testing.T) {
	for c, want := range map[string]bool{
		"otsec.authz/0.4": false, "otsec.authz/0.3": false, "otsec.authz/0.5": true, "otsec.authz/0.6": true,
		"otsec.authz/0.10": true, "": false, "otsec.authz/0.5x": false, "authz/0.5": false,
	} {
		if got := authz.AnswersRepeat(c); got != want {
			t.Errorf("%q: %v, want %v", c, got, want)
		}
	}
}

// The 0.4 admin golden is unchanged and verifies under a 0.5 reader: a 0.4
// node's request still works (#184, "Reader for 0.4").
func TestC7v05GoldenFrom04StillVerifies(t *testing.T) {
	req, err := authz.DecodeRequest(a6Golden(t))
	if err != nil {
		t.Fatal(err)
	}
	if req.Contract != "otsec.authz/0.4" {
		t.Fatalf("golden stamped %q", req.Contract)
	}
	if authz.AnswersRepeat(req.Contract) {
		t.Fatal("a 0.4 request may get the repeat answer")
	}
	var p map[string]any
	if err := json.Unmarshal(req.AdminSigned.Payload, &p); err != nil || p["format"] != "otsec.authz.admin-request/0.4" {
		t.Fatalf("payload format %v (%v)", p["format"], err)
	}
}
