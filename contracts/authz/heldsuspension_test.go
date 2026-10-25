package authz

import (
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"

	"otsec.local/otsec/contracts/asset"
)

const heldRef = "6f1c2e8a-0000-4000-8000-0000000000a1"

// asset_suspended and the suspension it names (0.3, A6 on #120): the node
// adopts a suspension only the collector holds, so it must be checkable.
func TestHeldSuspension(t *testing.T) {
	held := &HeldSuspension{Reason: asset.SuspendIdentityMismatch, Ref: heldRef}
	reply := func(code RefusalCode, h *HeldSuspension) CollectorReply {
		return CollectorReply{Contract: ContractID, RequestID: "r1", Status: ReplyRefused, CollectorSeq: 7,
			Refusal: &Refusal{Code: code, Detail: "d", Suspension: h}}
	}
	for _, c := range []struct {
		name  string
		reply CollectorReply
		want  *HeldSuspension
		err   string
	}{
		{"asset_suspended names it", reply(RefuseAssetSuspended, held), held, ""},
		{"a mismatch names the one held", reply(RefuseSuspensionMismatch, held), held, ""},
		{"a mismatch with none held", reply(RefuseSuspensionMismatch, nil), nil, ""},
		{"another refusal", reply(RefuseRateLimited, nil), nil, ""},
		{"accepted", CollectorReply{Contract: ContractID, RequestID: "r1", Status: ReplyAccepted, CollectorSeq: 7}, nil, ""},
		{"asset_suspended naming none", reply(RefuseAssetSuspended, nil), nil, "names no suspension"},
		{"a suspension on another code", reply(RefuseAssetNotEnrolled, held), nil, "a suspension on refusal asset_not_enrolled"},
		{"an unknown reason", reply(RefuseAssetSuspended, &HeldSuspension{Reason: "tired", Ref: heldRef}), nil, "not a C1 suspension reason"},
		{"an upper-case ref", reply(RefuseAssetSuspended, &HeldSuspension{Reason: asset.SuspendAuthFailed, Ref: strings.ToUpper(heldRef)}), nil, "not an invocation ID"},
		{"an empty ref", reply(RefuseAssetSuspended, &HeldSuspension{Reason: asset.SuspendAuthFailed}), nil, "not an invocation ID"},
	} {
		t.Run(c.name, func(t *testing.T) {
			got, err := c.reply.HeldSuspension()
			if c.err != "" {
				if err == nil || !strings.Contains(err.Error(), c.err) {
					t.Fatalf("err %v, want %q", err, c.err)
				}
				return
			}
			if err != nil || (got == nil) != (c.want == nil) || (got != nil && *got != *c.want) {
				t.Fatalf("got %+v, %v; want %+v", got, err, c.want)
			}
		})
	}
}

// A request stamped before 0.3 gets what a 0.2 collector replied: its
// reader decodes replies strictly and knows neither the code nor the field.
func TestRefusalForRequest(t *testing.T) {
	held := &HeldSuspension{Reason: asset.SuspendAuthFailed, Ref: heldRef}
	suspended := &Refusal{Code: RefuseAssetSuspended, Detail: "asset is suspended", Suspension: held}
	mismatch := &Refusal{Code: RefuseSuspensionMismatch, Detail: "another invocation", Suspension: held}
	other := &Refusal{Code: RefuseBusy, Detail: "busy"}
	for _, c := range []struct {
		contract string
		in       *Refusal
		want     Refusal
	}{
		{"otsec.authz/0.3", suspended, *suspended},
		{"otsec.authz/0.4", suspended, *suspended},
		{"otsec.authz/0.2", suspended, Refusal{Code: RefuseAssetNotEnrolled, Detail: "asset is suspended"}},
		{"otsec.authz/0.1", suspended, Refusal{Code: RefuseAssetNotEnrolled, Detail: "asset is suspended"}},
		{"otsec.authz/0.3", mismatch, *mismatch},
		{"otsec.authz/0.2", mismatch, Refusal{Code: RefuseSuspensionMismatch, Detail: "another invocation"}},
		{"otsec.authz/0.1", other, *other},
	} {
		got := c.in.ForRequest(c.contract)
		if got.Code != c.want.Code || got.Detail != c.want.Detail || (got.Suspension == nil) != (c.want.Suspension == nil) {
			t.Errorf("%s %s: got %+v, want %+v", c.contract, c.in.Code, got, c.want)
		}
	}
	if suspended.Code != RefuseAssetSuspended || suspended.Suspension == nil {
		t.Error("ForRequest changed the refusal it was given")
	}
	var nilRefusal *Refusal
	if nilRefusal.ForRequest("otsec.authz/0.1") != nil {
		t.Error("a nil refusal became one")
	}
}

// The reply schema lists exactly RefusalCodes, and its suspension the C1
// reasons HeldSuspension accepts.
func TestReplySchemaRefusals(t *testing.T) {
	raw, err := os.ReadFile("schema/collector-reply.json")
	if err != nil {
		t.Fatal(err)
	}
	var s struct {
		Properties struct {
			Refusal struct {
				Properties struct {
					Code       struct{ Enum []RefusalCode }
					Suspension struct {
						Properties struct {
							Reason struct{ Enum []asset.SuspensionReason }
						}
					}
				}
			}
		}
	}
	if err := json.Unmarshal(raw, &s); err != nil {
		t.Fatal(err)
	}
	p := s.Properties.Refusal.Properties
	if got := slices.Sorted(slices.Values(p.Code.Enum)); !slices.Equal(got, slices.Sorted(slices.Values(RefusalCodes))) {
		t.Errorf("schema refusal codes %v, want %v", got, RefusalCodes)
	}
	reasons := p.Suspension.Properties.Reason.Enum
	if len(reasons) == 0 {
		t.Fatal("the schema lists no suspension reasons")
	}
	for _, r := range reasons {
		if err := (HeldSuspension{Reason: r, Ref: heldRef}).Validate(); err != nil {
			t.Errorf("schema reason %q: %v", r, err)
		}
	}
	if err := (HeldSuspension{Reason: "tired", Ref: heldRef}).Validate(); err == nil {
		t.Error("an unknown reason validated")
	}
}
