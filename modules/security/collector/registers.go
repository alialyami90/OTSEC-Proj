package collector

import (
	"fmt"
	"sync"

	"otsec.local/otsec/contracts/authz"
	"otsec.local/otsec/contracts/register"
)

// Registers holds the register packages the collector has verified itself
// (C7 register signature rules, SC-18). The node can deliver a package, but
// only a package whose envelope verifies against the collector's trust
// anchors, and that passes the per-family anti-rollback floor, is ever
// active. A run for a family with no active package is refused with
// register_unverified.
//
// The trust anchors are fixed when the collector starts. They are installed
// at enrollment or by a signed release of the node software, never by
// central policy (AP-7). A change to them restarts the collector, which then
// verifies every package again, so a package signed by a key revoked since
// is not activated.
type Registers struct {
	state   *State
	anchors []authz.TrustAnchor

	mu     sync.RWMutex
	active map[string]activeRegister
}

type activeRegister struct {
	pkg     *register.Package
	matcher *register.Matcher
}

// NewRegisters returns an empty set over the given trust anchors. The floors
// live in state.
func NewRegisters(state *State, anchors []authz.TrustAnchor) *Registers {
	return &Registers{state: state, anchors: append([]authz.TrustAnchor(nil), anchors...), active: map[string]activeRegister{}}
}

// Activate verifies a signed register envelope and, only if it verifies,
// persists its family's floor and makes it the family's active package.
// Every rejection wraps authz.ErrRegisterRejected; a failure to persist the
// floor wraps ErrStateUnavailable. On any error the family's previous
// package stays active.
func (r *Registers) Activate(envelope []byte) (*register.Package, error) {
	env, err := authz.DecodeRegisterEnvelope(envelope)
	if err != nil {
		return nil, err
	}
	pkg, floor, err := authz.VerifyRegisterPackage(env, r.anchors, r.state.FamilyFloors())
	if err != nil {
		return nil, err
	}
	m, err := register.NewMatcher(pkg)
	if err != nil {
		return nil, fmt.Errorf("%w: matcher: %v", authz.ErrRegisterRejected, err)
	}
	if err := r.state.SetFamilyFloor(pkg.Family, floor); err != nil {
		return nil, err
	}
	r.mu.Lock()
	r.active[pkg.Family] = activeRegister{pkg: pkg, matcher: m}
	r.mu.Unlock()
	return pkg, nil
}

// Active returns the family's active package and its matcher.
func (r *Registers) Active(family string) (*register.Package, *register.Matcher, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	a, ok := r.active[family]
	return a.pkg, a.matcher, ok
}
