package authz

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"otsec.local/otsec/contracts/internal/strictjson"
)

// The node kinds need 0.5, and are sent admin-signed only: there is no body
// for them outside the payload.
func TestNodeKindsNeed05AndASignature(t *testing.T) {
	for _, kind := range []RequestKind{KindNodeQuarantineClear, KindNodeSeqResetAck} {
		t.Run(string(kind), func(t *testing.T) {
			req := signedRequest(t, testAdminPriv, adminPayload(t, kind))
			if _, err := VerifyAdminRequest(roundTrip(t, req), testAdminKeys(), testAdminBind, testAdminNow); err != nil {
				t.Fatalf("0.5: %v", err)
			}
			req.Contract = "otsec.authz/0.4"
			wantRefusal(t, req, RefuseInvalid, "needs otsec.authz/0.5")

			unsigned := `{"contract":"otsec.authz/0.5","kind":"` + string(kind) + `","request_id":"req-1",` +
				`"on_behalf_of":{"type":"human","id":"alice@site-a"},"policy_version":3}`
			if _, err := DecodeRequest([]byte(unsigned)); refusalCode(err) != RefuseInvalid {
				t.Fatalf("unsigned: %v", err)
			}
			for _, field := range []string{"node_quarantine_clear", "node_seq_reset_ack"} {
				b := strings.TrimSuffix(unsigned, "}") + `,"` + field + `":{}}`
				if _, err := DecodeRequest([]byte(b)); refusalCode(err) != RefuseUnknownField {
					t.Fatalf("a %s body outside the payload: %v", field, err)
				}
			}
		})
	}
}

// Each node body passes only its own rules, and only under its own kind.
func TestNodeKindBodies(t *testing.T) {
	cases := []struct {
		name string
		edit func(p *AdminRequest)
	}{
		{"asset ID not a C1 UUID", func(p *AdminRequest) { p.NodeQuarantineClear.AssetID = "../asset" }},
		{"asset ID upper case", func(p *AdminRequest) {
			p.NodeQuarantineClear.AssetID = strings.ToUpper(p.NodeQuarantineClear.AssetID)
		}},
		{"manifest digest short", func(p *AdminRequest) { p.NodeQuarantineClear.ManifestSHA256 = testManifestSHA256[:63] }},
		{"manifest digest upper case", func(p *AdminRequest) {
			p.NodeQuarantineClear.ManifestSHA256 = strings.ToUpper(testManifestSHA256)
		}},
		{"two bodies", func(p *AdminRequest) { p.NodeSeqResetAck = &NodeSeqResetAckBody{} }},
		{"another kind's body", func(p *AdminRequest) {
			p.NodeQuarantineClear, p.NodeSeqResetAck = nil, &NodeSeqResetAckBody{}
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := adminPayload(t, KindNodeQuarantineClear)
			c.edit(&p)
			req := roundTrip(t, signedRequest(t, testAdminPriv, p))
			_, err := VerifyAdminRequest(req, testAdminKeys(), testAdminBind, testAdminNow)
			if check := adminCheck(err); check != AdminCheckPayload {
				t.Fatalf("check %q (%v), want payload", check, err)
			}
		})
	}
}

// A 0.4 reader decodes the payload strictly, so a node body is a payload
// error there, not a request it could misread.
func TestNodeBodyIsAPayloadField(t *testing.T) {
	env, err := SignAdminRequest(testAdminPriv, adminPayload(t, KindNodeSeqResetAck))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(env.Payload, []byte(`"node_seq_reset_ack":{}`)) {
		t.Fatalf("payload %s", env.Payload)
	}
}

func testAcceptance(t *testing.T) (*CollectorRequest, CollectorReply) {
	t.Helper()
	req := roundTrip(t, signedRequest(t, testAdminPriv, adminPayload(t, KindNodeQuarantineClear)))
	return req, CollectorReply{Contract: ContractID, RequestID: req.RequestID, Status: ReplyAccepted, CollectorSeq: 12,
		Admin: &AdminAccepted{AdminKeyID: req.AdminSigned.KeyID, Principal: req.OnBehalfOf, Nonce: testAdminNonce,
			PayloadSHA256: AdminPayloadSHA256(req.AdminSigned)}}
}

func TestAdminAcceptance(t *testing.T) {
	req, ok := testAcceptance(t)
	if a, err := ok.AdminAcceptance(req); err != nil || a.Nonce != testAdminNonce {
		t.Fatalf("%+v %v", a, err)
	}
	repeat := ok
	repeat.RepeatOf = 7
	if _, err := repeat.AdminAcceptance(req); err != nil {
		t.Fatalf("repeat: %v", err)
	}
	other := roundTrip(t, signedRequest(t, testAdminPriv, adminPayload(t, KindNodeSeqResetAck)))
	cases := map[string]func(r *CollectorReply, sent **CollectorRequest){
		"refused": func(r *CollectorReply, _ **CollectorRequest) {
			r.Status, r.Refusal = ReplyRefused, AdminRefusal(AdminCheckReplay)
		},
		"no collector_seq":   func(r *CollectorReply, _ **CollectorRequest) { r.CollectorSeq = 0 },
		"another request ID": func(r *CollectorReply, _ **CollectorRequest) { r.RequestID = "req-other" },
		"names nothing":      func(r *CollectorReply, _ **CollectorRequest) { r.Admin = nil },
		"reply stamped 0.4":  func(r *CollectorReply, _ **CollectorRequest) { r.Contract = "otsec.authz/0.4" },
		"repeat without admin": func(r *CollectorReply, _ **CollectorRequest) {
			r.RepeatOf, r.Admin = 7, nil
		},
		"repeat of itself":      func(r *CollectorReply, _ **CollectorRequest) { r.RepeatOf = r.CollectorSeq },
		"repeat of a later one": func(r *CollectorReply, _ **CollectorRequest) { r.RepeatOf = r.CollectorSeq + 1 },
		// A1 on #184: a collector that answers a 0.4 request with admin
		// is misbehaving, and the node does not act on it.
		"request stamped 0.4": func(_ *CollectorReply, sent **CollectorRequest) {
			u := *req
			u.Contract = "otsec.authz/0.4"
			*sent = &u
		},
		"refusal with admin": func(r *CollectorReply, _ **CollectorRequest) {
			r.Status, r.Refusal = ReplyRefused, AdminRefusal(AdminCheckReplay)
		},
		"refusal with repeat_of": func(r *CollectorReply, _ **CollectorRequest) {
			r.Status, r.Refusal, r.RepeatOf = ReplyRefused, AdminRefusal(AdminCheckReplay), 7
		},
		"accepted status with a refusal and repeat_of": func(r *CollectorReply, _ **CollectorRequest) {
			r.Refusal, r.RepeatOf = AdminRefusal(AdminCheckReplay), 7
		},
		"other signed bytes": func(_ *CollectorReply, sent **CollectorRequest) { *sent = other },
		"another key": func(r *CollectorReply, _ **CollectorRequest) {
			a := *r.Admin
			a.AdminKeyID = "ed25519-0000000000000000"
			r.Admin = &a
		},
		"another person": func(r *CollectorReply, _ **CollectorRequest) {
			a := *r.Admin
			a.Principal.ID = "bob@site-a"
			r.Admin = &a
		},
		"malformed nonce": func(r *CollectorReply, _ **CollectorRequest) {
			a := *r.Admin
			a.Nonce = "x"
			r.Admin = &a
		},
		"unsigned request": func(_ *CollectorReply, sent **CollectorRequest) {
			u := *req
			u.AdminSigned = nil
			*sent = &u
		},
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			r, sent := ok, req
			edit(&r, &sent)
			if a, err := r.AdminAcceptance(sent); err == nil {
				t.Fatalf("accepted: %+v", a)
			}
		})
	}
}

// The reply fixtures: each file under testdata/replies/valid decodes
// strictly and validates; each under invalid/ decodes and fails Validate,
// with what its name says (A1 on #184: repeat and admin at 0.4 refused).
func TestGoldenReplies(t *testing.T) {
	for _, dir := range []string{"valid", "invalid"} {
		files, err := os.ReadDir("testdata/replies/" + dir)
		if err != nil {
			t.Fatal(err)
		}
		if len(files) == 0 {
			t.Fatalf("no %s replies", dir)
		}
		for _, f := range files {
			t.Run(dir+"/"+f.Name(), func(t *testing.T) {
				raw, err := os.ReadFile("testdata/replies/" + dir + "/" + f.Name())
				if err != nil {
					t.Fatal(err)
				}
				var r CollectorReply
				if err := strictjson.Decode(raw, &r); err != nil {
					t.Fatalf("decode: %v", err)
				}
				if err := r.Validate(); (err == nil) != (dir == "valid") {
					t.Fatalf("Validate: %v", err)
				}
			})
		}
	}
}

func TestReplyValidate(t *testing.T) {
	_, ok := testAcceptance(t)
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	plain := CollectorReply{Contract: "otsec.authz/0.4", RequestID: "req-1", Status: ReplyAccepted, CollectorSeq: 3}
	if err := plain.Validate(); err != nil {
		t.Fatalf("a 0.4 reply with neither field: %v", err)
	}
	for name, edit := range map[string]func(r *CollectorReply){
		"admin at 0.4":         func(r *CollectorReply) { r.Contract = "otsec.authz/0.4" },
		"repeat at 0.4":        func(r *CollectorReply) { r.Contract, r.RepeatOf = "otsec.authz/0.4", 7 },
		"repeat without admin": func(r *CollectorReply) { r.RepeatOf, r.Admin = 7, nil },
		"repeat of itself":     func(r *CollectorReply) { r.RepeatOf = r.CollectorSeq },
		"repeat_of on a refusal": func(r *CollectorReply) {
			r.Status, r.Refusal, r.RepeatOf, r.Admin = ReplyRefused, AdminRefusal(AdminCheckReplay), 7, nil
		},
		"admin on a refusal": func(r *CollectorReply) {
			r.Status, r.Refusal = ReplyRefused, AdminRefusal(AdminCheckReplay)
		},
		"key ID malformed":       func(r *CollectorReply) { a := *r.Admin; a.AdminKeyID = "rsa-1"; r.Admin = &a },
		"principal not a person": func(r *CollectorReply) { a := *r.Admin; a.Principal.Type = PrincipalNode; r.Admin = &a },
		"nonce malformed":        func(r *CollectorReply) { a := *r.Admin; a.Nonce = "x"; r.Admin = &a },
		"payload hash upper": func(r *CollectorReply) {
			a := *r.Admin
			a.PayloadSHA256 = strings.ToUpper(a.PayloadSHA256)
			r.Admin = &a
		},
	} {
		r := ok
		edit(&r)
		if err := r.Validate(); err == nil {
			t.Errorf("%s: valid", name)
		}
	}
}

func TestAnswersRepeat(t *testing.T) {
	for contract, want := range map[string]bool{
		"otsec.authz/0.5": true, "otsec.authz/0.6": true,
		"otsec.authz/0.4": false, "otsec.authz/0.1": false, "": false, "otsec.authz/x": false,
	} {
		if got := AnswersRepeat(contract); got != want {
			t.Errorf("%q: %v, want %v", contract, got, want)
		}
	}
}

// The second golden: a signed quarantine clear stamped 0.5.
func TestNodeQuarantineClearGolden(t *testing.T) {
	const path = "testdata/requests/valid/admin-signed-node-quarantine-clear.json"
	req := signedRequest(t, testAdminPriv, adminPayload(t, KindNodeQuarantineClear))
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
}

func refusalCode(err error) RefusalCode {
	var ref *Refusal
	if !errors.As(err, &ref) {
		return ""
	}
	return ref.Code
}

func adminCheck(err error) AdminCheck {
	var rej *AdminRejected
	if !errors.As(err, &rej) {
		return ""
	}
	return rej.Check
}

// wantRefusal sends req through the wire format and wants DecodeRequest to
// refuse it with code, its detail containing detail.
func wantRefusal(t *testing.T, req *CollectorRequest, code RefusalCode, detail string) {
	t.Helper()
	b, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	_, err = DecodeRequest(b)
	var ref *Refusal
	if !errors.As(err, &ref) || ref.Code != code || !strings.Contains(ref.Detail, detail) {
		t.Fatalf("got %v, want %s with %q", err, code, detail)
	}
}
