// Package winsvc runs the node under the Windows service control manager
// and installs both services (P2-A5; A3 design W-1 to W-4, ADR-0007).
//
// The installer, run elevated:
//
//   - creates %ProgramData%\OTSEC and its subdirectories itself, each with a
//     protected DACL and owner Administrators, and stops if any of them
//     already exists with another owner or an ACE it did not write (W-4): a
//     user who pre-created a folder would own it and could rewrite its DACL;
//   - copies the node configuration into OTSEC\config and loads it, so a
//     configuration the node would refuse is refused at install;
//   - installs otsec-node (and otsec-collector when its binary is given) as
//     virtual service accounts NT SERVICE\<name>, with an unrestricted
//     service SID, so the store and pipe DACLs and the peer checks can name
//     each service (W-1);
//   - gives each service a required-privileges list holding only
//     SeChangeNotifyPrivilege, so the SCM removes SeImpersonatePrivilege and
//     every other privilege from its token (W-2);
//   - adds a Windows Firewall rule, matched by service, that blocks
//     otsec-node from opening Telnet connections, so a compromised node
//     service cannot reach a relay itself (W-3, slice ports only);
//   - refuses binaries outside %ProgramFiles% (W-4).
//
// Everything here except this file is Windows-only. Evidence class of all
// of it: compiled in the Linux container only; the Windows run is owed
// (D2-8), with A3's test T-13.
package winsvc

import (
	"path/filepath"

	"otsec.local/otsec/modules/security/collectorwire"
)

// Service names (collectorwire, ADR-0002).
const (
	NodeService      = collectorwire.NodeService
	CollectorService = collectorwire.CollectorService
)

// Access masks used in the directory DACLs.
const (
	// accessFull is FILE_ALL_ACCESS.
	accessFull = "FA"
	// accessTraverse is read and execute on the directory itself:
	// FILE_GENERIC_READ | FILE_GENERIC_EXECUTE.
	accessTraverse = "0x1200a9"
)

// Dir is one directory the installer creates, with its exact security
// descriptor in SDDL: owner Administrators, a protected DACL.
type Dir struct {
	Path string
	SDDL string
}

// grant is one allow ACE: inherit says whether files and subdirectories
// inherit it (OICI) or it applies to the directory itself only.
type grant struct {
	sid     string
	access  string
	inherit bool
}

func sddl(grants ...grant) string {
	s := "O:BAD:P"
	for _, g := range append([]grant{{"SY", accessFull, true}, {"BA", accessFull, true}}, grants...) {
		flags := ""
		if g.inherit {
			flags = "OICI"
		}
		s += "(A;" + flags + ";" + g.access + ";;;" + g.sid + ")"
	}
	return s
}

// Dirs is the directory tree under programData, in creation order:
//
//	OTSEC                      node and collector may traverse
//	OTSEC\config               node reads (its configuration)
//	OTSEC\store                node full control: the C5 store and status
//	OTSEC\collector            collector may traverse
//	OTSEC\collector\credentials collector full control (A3 credential design)
//
// SYSTEM and Administrators have full control everywhere; nobody else,
// Users and Everyone included, has any access.
func Dirs(programData string) []Dir {
	node := collectorwire.ServiceSID(NodeService)
	coll := collectorwire.ServiceSID(CollectorService)
	root := filepath.Join(programData, "OTSEC")
	return []Dir{
		{root, sddl(grant{node, accessTraverse, false}, grant{coll, accessTraverse, false})},
		{filepath.Join(root, "config"), sddl(grant{node, accessTraverse, true})},
		{StoreDir(programData), sddl(grant{node, accessFull, true})},
		{filepath.Join(root, "collector"), sddl(grant{coll, accessTraverse, false})},
		{filepath.Join(root, "collector", "credentials"), sddl(grant{coll, accessFull, true})},
	}
}

// StoreDir is the store directory the node configuration must name.
func StoreDir(programData string) string { return filepath.Join(programData, "OTSEC", "store") }

// ConfigPath is where the installer puts the node configuration.
func ConfigPath(programData string) string {
	return filepath.Join(programData, "OTSEC", "config", "node.json")
}

// RequiredPrivileges is the only privilege either service keeps (W-2).
var RequiredPrivileges = []string{"SeChangeNotifyPrivilege"}

// FirewallRule is the name of the W-3 rule the installer adds.
const FirewallRule = "otsec-node: no outbound Telnet (W-3)"
