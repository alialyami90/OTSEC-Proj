package authz

import (
	"errors"
	"fmt"
	"regexp"

	"otsec.local/otsec/contracts/version"
)

// ContractID is the identifier every C7 message this package writes
// carries. 0.2 added the asset.clear_suspension request and the
// suspension_mismatch refusal (D2-15, A1). 0.3 added the asset_suspended
// refusal and the suspension it names (A6 on #120). 0.4 added
// admin-signed requests and the admin_unverified refusal (D2-11). 0.5
// added the admin-signed node kinds node.quarantine_clear and
// node.seq_reset_ack, and on an accepted admin-signed request the repeat
// answer (repeat_of) and what the collector verified (admin) (P3-A3, #181).
const ContractID = "otsec.authz/0.5"

// AcceptsContract reports whether a reader of this package can read a
// message stamped id: any minor of its major (contracts/README.md). What a
// request may ask for under an older minor is checked by Validate.
func AcceptsContract(id string) bool {
	got, err := version.Parse(id)
	return err == nil && contractVersion.Accepts(got)
}

var contractVersion, _ = version.Parse(ContractID)

// PrincipalType says what kind of actor a principal is.
type PrincipalType string

const (
	PrincipalHuman    PrincipalType = "human"    // a person signed in to the platform
	PrincipalSchedule PrincipalType = "schedule" // a site-local collection schedule; acts with the collector role
	PrincipalNode     PrincipalType = "node"     // a platform node acting for itself (enrollment, posture)
	PrincipalSystem   PrincipalType = "system"   // a platform service acting for itself (startup, pruning)
)

// Principal identifies who asked for something.
type Principal struct {
	Type PrincipalType `json:"type"`
	ID   string        `json:"id"`
}

var principalIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._@:-]{0,127}$`)

// Validate checks the principal's type and ID syntax.
func (p Principal) Validate() error {
	switch p.Type {
	case PrincipalHuman, PrincipalSchedule, PrincipalNode, PrincipalSystem:
	default:
		return fmt.Errorf("authz: unknown principal type %q", p.Type)
	}
	if !principalIDPattern.MatchString(p.ID) {
		return fmt.Errorf("authz: principal id %q is not valid", p.ID)
	}
	return nil
}

// Role is a platform role. The set is closed in 0.1.
type Role string

const (
	RoleMonitor         Role = "monitor"
	RoleEngineer        Role = "engineer" // reserved for Phase 4 engineering access; observe only in 0.1
	RoleAdmin           Role = "admin"
	RoleSecurityAuditor Role = "security-auditor"
	RoleCollector       Role = "collector" // non-human; exercised only through a schedule principal
)

// Roles lists every role.
var Roles = []Role{RoleMonitor, RoleEngineer, RoleAdmin, RoleSecurityAuditor, RoleCollector}

// Human reports whether the role may be held by a person.
func (r Role) Human() bool { return r != RoleCollector }

// OperationClass groups platform operations for authorization. The set is
// closed in 0.1, and it deliberately has no class for device writes.
type OperationClass string

const (
	ClassObserve         OperationClass = "observe"          // read assets, events, alarms
	ClassDeviceRead      OperationClass = "device-read"      // run a read-only register operation on a device
	ClassPolicyAdmin     OperationClass = "policy-admin"     // schedules and register versions within the site ceiling
	ClassCredentialWrite OperationClass = "credential-write" // install, revoke or clear a device credential; never read
	ClassRoleAdmin       OperationClass = "role-admin"       // grant and remove roles
	ClassAuditRead       OperationClass = "audit-read"       // read and export audit records
)

// Classes lists every operation class.
var Classes = []OperationClass{ClassObserve, ClassDeviceRead, ClassPolicyAdmin, ClassCredentialWrite, ClassRoleAdmin, ClassAuditRead}

// matrix is the role and operation matrix (A3 findings 4.1). A missing entry
// is a denial.
var matrix = map[Role]map[OperationClass]bool{
	RoleMonitor:         {ClassObserve: true},
	RoleEngineer:        {ClassObserve: true},
	RoleAdmin:           {ClassObserve: true, ClassPolicyAdmin: true, ClassCredentialWrite: true, ClassRoleAdmin: true},
	RoleSecurityAuditor: {ClassObserve: true, ClassAuditRead: true},
	RoleCollector:       {ClassDeviceRead: true},
}

// Permits reports whether role may perform operations of class. Unknown roles
// and classes are denied.
func Permits(role Role, class OperationClass) bool {
	return matrix[role][class]
}

// ErrSeparationOfDuties is returned when a role set breaks a separation rule.
var ErrSeparationOfDuties = errors.New("authz: role set breaks separation of duties")

// conflicts lists role pairs that one principal may never hold together.
var conflicts = [][2]Role{
	{RoleAdmin, RoleEngineer},
	{RoleAdmin, RoleSecurityAuditor},
	{RoleEngineer, RoleSecurityAuditor},
}

// ValidateRoleSet checks that one principal's roles are known, do not repeat,
// and respect separation of duties (AP-14). The collector role is valid only
// alone and only for a schedule principal; a schedule holds nothing else.
func ValidateRoleSet(t PrincipalType, roles []Role) error {
	if len(roles) == 0 {
		return errors.New("authz: empty role set")
	}
	held := map[Role]bool{}
	for _, r := range roles {
		if _, ok := matrix[r]; !ok {
			return fmt.Errorf("authz: unknown role %q", r)
		}
		if held[r] {
			return fmt.Errorf("authz: role %q repeated", r)
		}
		held[r] = true
	}
	if held[RoleCollector] != (t == PrincipalSchedule) || (held[RoleCollector] && len(roles) != 1) {
		return fmt.Errorf("%w: the collector role is held alone, and only by a schedule", ErrSeparationOfDuties)
	}
	if t != PrincipalHuman && t != PrincipalSchedule {
		return fmt.Errorf("authz: principal type %q holds no roles", t)
	}
	for _, c := range conflicts {
		if held[c[0]] && held[c[1]] {
			return fmt.Errorf("%w: %s and %s", ErrSeparationOfDuties, c[0], c[1])
		}
	}
	return nil
}

// RequiresSecondApprover reports whether an operation needs a second admin's
// approval before it takes effect: granting engineer, admin or
// security-auditor, and any policy change that widens what the site collects
// or where it forwards (A3 findings 4.1, C-A5-3).
func RequiresSecondApprover(class OperationClass, grantedRole Role, widening bool) bool {
	switch class {
	case ClassRoleAdmin:
		return grantedRole == RoleEngineer || grantedRole == RoleAdmin || grantedRole == RoleSecurityAuditor
	case ClassPolicyAdmin:
		return widening
	}
	return false
}
