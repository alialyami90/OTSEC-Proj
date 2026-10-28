package contract

// C7 0.6 (#250, B3): the approver role, from D4-2's text. A key pinned
// before 0.6 has no list and must not sign the two new kinds, so an
// installed key fails closed; only a key whose list names a new kind may
// sign it; a list that names a non-admin kind or a kind twice is refused.
// Ground truth: independent (D4-2). Evidence class: desk.

import (
	"testing"

	"otsec.local/otsec/contracts/authz"
)

func TestC7V06B6ApproverRole(t *testing.T) {
	newKinds := []authz.RequestKind{authz.KindNodeChangeApproval, authz.KindNodeBaselineAck}
	installed := authz.AdminKey{KeyID: "b6-05", Principal: vm2Person}
	for _, k := range newKinds {
		if installed.Allows(k) {
			t.Errorf("a key pinned without a list may sign %s", k)
		}
	}
	for _, k := range authz.DefaultAdminKinds {
		if !installed.Allows(k) {
			t.Errorf("a key pinned without a list may no longer sign %s, a 0.5 kind", k)
		}
	}
	approver := authz.AdminKey{KeyID: "b6-06", Principal: vm2Person, Kinds: []authz.RequestKind{authz.KindNodeChangeApproval}}
	if !approver.Allows(authz.KindNodeChangeApproval) || approver.Allows(authz.KindNodeBaselineAck) || approver.Allows(authz.KindCredentialInstall) {
		t.Error("a key listing only node.change_approval signs more or less than that")
	}
	none := authz.AdminKey{KeyID: "b6-07", Principal: vm2Person, Kinds: []authz.RequestKind{}}
	for _, k := range append(newKinds, authz.DefaultAdminKinds...) {
		if none.Allows(k) {
			t.Errorf("a key with an empty list may sign %s", k)
		}
	}
	if err := authz.ValidateAdminKinds(newKinds); err != nil {
		t.Errorf("the two new kinds: %v", err)
	}
	for name, kinds := range map[string][]authz.RequestKind{
		"a kind twice":          {authz.KindNodeChangeApproval, authz.KindNodeChangeApproval},
		"a kind no admin signs": {authz.RequestKind("ied.run")},
	} {
		if authz.ValidateAdminKinds(kinds) == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
