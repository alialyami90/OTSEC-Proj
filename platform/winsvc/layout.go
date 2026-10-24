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
//   - when the collector binary is given, writes the collector's first-start
//     marker if neither collector store exists, and installs otsec-collector
//     with "run -data %ProgramData%\OTSEC" (A3);
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
//	OTSEC\collector             collector reads (collector.json, A3)
//	OTSEC\collector\credentials collector full control (A3 credential design)
//	OTSEC\collector\state       collector full control (A3: failed-auth floor, collector_seq)
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
		{filepath.Join(root, "collector"), sddl(grant{coll, accessTraverse, true})},
		{filepath.Join(root, "collector", "credentials"), sddl(grant{coll, accessFull, true})},
		{filepath.Join(root, "collector", "state"), sddl(grant{coll, accessFull, true})},
	}
}

// DataDir is the -data argument of the collector service (A3).
func DataDir(programData string) string { return filepath.Join(programData, "OTSEC") }

// ProvisionMarker is the empty file the installer writes so that the
// collector, at its first start and under its own account, creates its
// credential and state stores: only when both are absent and the marker is
// present (A3). A missing store at any other time is lost state, never a
// first start.
func ProvisionMarker(programData string) string {
	return filepath.Join(programData, "OTSEC", "collector", "state", "provision")
}

// CollectorStores are the collector's two stores; the marker is written
// only when neither exists.
func CollectorStores(programData string) []string {
	return []string{
		filepath.Join(programData, "OTSEC", "collector", "state", "state.json"),
		filepath.Join(programData, "OTSEC", "collector", "credentials", "credentials.json"),
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
