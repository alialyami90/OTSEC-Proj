package authz

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

// The configuration kinds need 0.6, and are sent admin-signed only: there
// is no body for them outside the payload.
func TestConfigKindsNeed06AndASignature(t *testing.T) {
	for _, kind := range []RequestKind{KindNodeChangeApproval, KindNodeBaselineAck} {
		t.Run(string(kind), func(t *testing.T) {
			req := signedRequest(t, testAdminPriv, adminPayload(t, kind))
			if _, err := VerifyAdminRequest(roundTrip(t, req), testAdminKeys(), testAdminBind, testAdminNow); err != nil {
				t.Fatalf("0.6: %v", err)
			}
			req.Contract = "otsec.authz/0.5"
			wantRefusal(t, req, RefuseInvalid, "needs otsec.authz/0.6")

			unsigned := `{"contract":"otsec.authz/0.6","kind":"` + string(kind) + `","request_id":"req-1",` +
				`"on_behalf_of":{"type":"human","id":"alice@site-a"},"policy_version":3}`
			if _, err := DecodeRequest([]byte(unsigned)); refusalCode(err) != RefuseInvalid {
				t.Fatalf("unsigned: %v", err)
			}
			for _, field := range []string{"node_change_approval", "node_baseline_ack"} {
				b := strings.TrimSuffix(unsigned, "}") + `,"` + field + `":{}}`
				if _, err := DecodeRequest([]byte(b)); refusalCode(err) != RefuseUnknownField {
					t.Fatalf("a %s body outside the payload: %v", field, err)
				}
			}
		})
	}
}

// Each configuration body passes only its own rules, and only under its
// own kind: every case is a payload error, so the nonce is not spent.
func TestConfigKindBodies(t *testing.T) {
	approval := func(edit func(b *NodeChangeApprovalBody)) func(p *AdminRequest) {
		return func(p *AdminRequest) { edit(p.NodeChangeApproval) }
	}
	ack := func(edit func(b *NodeBaselineAckBody)) func(p *AdminRequest) {
		return func(p *AdminRequest) { edit(p.NodeBaselineAck) }
	}
	cases := []struct {
		name string
		kind RequestKind
		edit func(p *AdminRequest)
	}{
		{"approval: asset ID not a C1 UUID", KindNodeChangeApproval, approval(func(b *NodeChangeApprovalBody) { b.AssetID = "../asset" })},
		{"approval: digest without its prefix", KindNodeChangeApproval, approval(func(b *NodeChangeApprovalBody) {
			b.BaselineDigest = strings.TrimPrefix(b.BaselineDigest, "sha256:")
		})},
		{"approval: digest upper case", KindNodeChangeApproval, approval(func(b *NodeChangeApprovalBody) {
			b.BaselineDigest = "sha256:" + strings.ToUpper(strings.TrimPrefix(b.BaselineDigest, "sha256:"))
		})},
		{"approval: digest short", KindNodeChangeApproval, approval(func(b *NodeChangeApprovalBody) { b.BaselineDigest = b.BaselineDigest[:70] })},
		{"approval: window start not UTC", KindNodeChangeApproval, approval(func(b *NodeChangeApprovalBody) {
			b.WindowStart = "2026-10-26T18:00:00+02:00"
		})},
		{"approval: window end not canonical", KindNodeChangeApproval, approval(func(b *NodeChangeApprovalBody) {
			b.WindowEnd = "2026-10-26T20:00:00.000Z"
		})},
		{"approval: window ends at its start", KindNodeChangeApproval, approval(func(b *NodeChangeApprovalBody) { b.WindowEnd = b.WindowStart })},
		{"approval: window ends before its start", KindNodeChangeApproval, approval(func(b *NodeChangeApprovalBody) {
			b.WindowStart, b.WindowEnd = b.WindowEnd, b.WindowStart
		})},
		{"approval: window one second over 24 hours", KindNodeChangeApproval, approval(func(b *NodeChangeApprovalBody) {
			b.WindowEnd = "2026-10-27T16:00:01Z"
		})},
		{"approval: no reason", KindNodeChangeApproval, approval(func(b *NodeChangeApprovalBody) { b.Reason = "" })},
		{"approval: reason over 256 bytes", KindNodeChangeApproval, approval(func(b *NodeChangeApprovalBody) { b.Reason = strings.Repeat("é", 129) })},
		{"approval: reason with a line break", KindNodeChangeApproval, approval(func(b *NodeChangeApprovalBody) { b.Reason = "ok\nALARM CLEARED" })},
		{"approval: reason with an escape", KindNodeChangeApproval, approval(func(b *NodeChangeApprovalBody) { b.Reason = "ok\x1b[2J" })},
		{"approval: reason with a line separator", KindNodeChangeApproval, approval(func(b *NodeChangeApprovalBody) { b.Reason = "ok next" })},
		{"ack: asset ID upper case", KindNodeBaselineAck, ack(func(b *NodeBaselineAckBody) { b.AssetID = strings.ToUpper(b.AssetID) })},
		{"ack: unknown kind", KindNodeBaselineAck, ack(func(b *NodeBaselineAckBody) { b.Kind = "config" })},
		{"ack: no kind", KindNodeBaselineAck, ack(func(b *NodeBaselineAckBody) { b.Kind = "" })},
		{"ack: bare hex digest", KindNodeBaselineAck, ack(func(b *NodeBaselineAckBody) {
			b.BaselineDigest = strings.TrimPrefix(b.BaselineDigest, "sha256:")
		})},
		{"two bodies", KindNodeChangeApproval, func(p *AdminRequest) {
			p.NodeBaselineAck = adminPayload(t, KindNodeBaselineAck).NodeBaselineAck
		}},
		{"another kind's body", KindNodeBaselineAck, func(p *AdminRequest) {
			p.NodeBaselineAck, p.NodeChangeApproval = nil, adminPayload(t, KindNodeChangeApproval).NodeChangeApproval
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := adminPayload(t, c.kind)
			c.edit(&p)
			req := roundTrip(t, signedRequest(t, testAdminPriv, p))
			_, err := VerifyAdminRequest(req, testAdminKeys(), testAdminBind, testAdminNow)
			if check := adminCheck(err); check != AdminCheckPayload {
				t.Fatalf("check %q (%v), want payload", check, err)
			}
		})
	}
}

// The window's bounds are inclusive where the contract says so: exactly
// 24 hours long, ending one second after the collector's clock, and
// starting exactly seven days ahead are all accepted.
func TestApprovalWindowBounds(t *testing.T) {
	for name, w := range map[string][2]string{
		"exactly 24 hours":            {"2026-10-26T16:00:00Z", "2026-10-27T16:00:00Z"},
		"ends one second from now":    {"2026-10-26T11:00:01Z", "2026-10-26T15:00:01Z"},
		"started before the approval": {"2026-10-26T14:00:00Z", "2026-10-26T18:00:00Z"},
		"starts exactly 7 days ahead": {"2026-11-02T15:00:00Z", "2026-11-02T19:00:00Z"},
	} {
		t.Run(name, func(t *testing.T) {
			p := adminPayload(t, KindNodeChangeApproval)
			p.NodeChangeApproval.WindowStart, p.NodeChangeApproval.WindowEnd = w[0], w[1]
			got, err := VerifyAdminRequest(roundTrip(t, signedRequest(t, testAdminPriv, p)), testAdminKeys(), testAdminBind, testAdminNow)
			if err != nil {
				t.Fatal(err)
			}
			start, end := got.NodeChangeApproval.Window()
			if start.Format(time.RFC3339) != w[0] || end.Format(time.RFC3339) != w[1] {
				t.Fatalf("window %v %v", start, end)
			}
		})
	}
}

// A key pinned without a list keeps the 0.5 kinds and nothing more (D4-2).
func TestAdminKeyAllows(t *testing.T) {
	var none AdminKey
	for _, k := range DefaultAdminKinds {
		if !none.Allows(k) {
			t.Errorf("a key without a list may not sign %s", k)
		}
	}
	for _, k := range []RequestKind{KindNodeChangeApproval, KindNodeBaselineAck, KindRun, "exec"} {
		if none.Allows(k) {
			t.Errorf("a key without a list may sign %s", k)
		}
	}
	if (&AdminKey{Kinds: []RequestKind{}}).Allows(KindCredentialInstall) {
		t.Error("an empty list allows a kind")
	}
	approver := AdminKey{Kinds: []RequestKind{KindNodeChangeApproval}}
	if !approver.Allows(KindNodeChangeApproval) || approver.Allows(KindCredentialInstall) || approver.Allows(KindNodeBaselineAck) {
		t.Error("a list allows other than what it names")
	}
	// DefaultAdminKinds is the 0.5 set: every admin kind older than 0.6.
	for k := range adminKinds {
		if older := kindSince[k] < configKindsSince; older != none.Allows(k) {
			t.Errorf("%s: added in 0.%d, allowed without a list: %v", k, kindSince[k], none.Allows(k))
		}
	}
}

func TestValidateAdminKinds(t *testing.T) {
	if err := ValidateAdminKinds(allAdminKinds()); err != nil {
		t.Fatal(err)
	}
	if err := ValidateAdminKinds(nil); err != nil {
		t.Fatal(err)
	}
	for name, kinds := range map[string][]RequestKind{
		"run":     {KindRun},
		"unknown": {"node.restore"},
		"twice":   {KindNodeBaselineAck, KindNodeBaselineAck},
	} {
		if err := ValidateAdminKinds(kinds); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// A reader before 0.6 does not know the authority check: it reads it as
// key, and the refusal it was given is unchanged.
func TestAuthorityRefusalForOlderRequests(t *testing.T) {
	r := AdminRefusal(AdminCheckAuthority)
	for contract, want := range map[string]AdminCheck{
		"otsec.authz/0.6": AdminCheckAuthority, "otsec.authz/0.7": AdminCheckAuthority,
		"otsec.authz/0.5": AdminCheckKey, "otsec.authz/0.4": AdminCheckKey, "otsec.authz/0.3": "",
	} {
		got := r.ForRequest(contract)
		if got.Check != want || got.Detail != r.Detail {
			t.Errorf("%s: %+v, want check %q", contract, got, want)
		}
	}
	if r.Check != AdminCheckAuthority {
		t.Error("ForRequest changed the refusal it was given")
	}
	// Other checks are not rewritten.
	if got := AdminRefusal(AdminCheckReplay).ForRequest("otsec.authz/0.5"); got.Check != AdminCheckReplay {
		t.Errorf("replay at 0.5: %+v", got)
	}
}

// The goldens for the two kinds, stamped 0.6, signed by the test key that
// lists every kind.
func TestConfigKindGoldens(t *testing.T) {
	for path, kind := range map[string]RequestKind{
		"testdata/requests/valid/admin-signed-node-change-approval.json": KindNodeChangeApproval,
		"testdata/requests/valid/admin-signed-node-baseline-ack.json":    KindNodeBaselineAck,
	} {
		t.Run(string(kind), func(t *testing.T) {
			req := signedRequest(t, testAdminPriv, adminPayload(t, kind))
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
			// The same key pinned without a list refuses the same bytes on
			// authority (D4-2).
			keys := testAdminKeys()
			keys[0].Kinds = nil
			if _, err := VerifyAdminRequest(dec, keys, testAdminBind, testAdminNow); adminCheck(err) != AdminCheckAuthority {
				t.Fatalf("without a list: %v", err)
			}
		})
	}
}
