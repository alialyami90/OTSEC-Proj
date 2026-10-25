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
//   - when the collector binary is given, copies the collector's
//     configuration into OTSEC\collector, owned by Administrators and
//     readable by the collector service only, writes the collector's
//     first-start marker if neither collector store exists, excludes the
//     collector from Windows Error Reporting dumps (A3 T-5), and installs
//     otsec-collector with "run -data %ProgramData%\OTSEC" (A3);
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
//	OTSEC\config\tls           node reads (TLS reference files, D2-12)
//	OTSEC\config\admin         node and collector read (administrator files, D2-15)
//	OTSEC\store                node full control: the C5 store and status
//	OTSEC\collector             collector reads (collector.json, A3)
//	OTSEC\collector\credentials collector full control (A3 credential design)
//	OTSEC\collector\state       collector full control (A3: failed-auth floor, collector_seq)
//	OTSEC\collector\public      collector full control, node reads (install-key.json, A3)
//
// SYSTEM and Administrators have full control everywhere; nobody else,
// Users and Everyone included, has any access. The node has no entry on
// OTSEC\collector, so it cannot list it or read collector.json; it reaches
// collector\public by its full path, which needs only the traverse right
// SeChangeNotifyPrivilege gives, the one privilege it keeps (W-2). The
// collector reaches config\admin the same way: it has no entry on
// OTSEC\config, so it cannot read node.json.
func Dirs(programData string) []Dir {
	node := collectorwire.ServiceSID(NodeService)
	coll := collectorwire.ServiceSID(CollectorService)
	root := filepath.Join(programData, "OTSEC")
	return []Dir{
		{root, sddl(grant{node, accessTraverse, false}, grant{coll, accessTraverse, false})},
		{filepath.Join(root, "config"), sddl(grant{node, accessTraverse, true})},
		{TLSDir(programData), sddl(grant{node, accessTraverse, true})},
		{AdminDir(programData), sddl(grant{node, accessTraverse, true}, grant{coll, accessTraverse, true})},
		{StoreDir(programData), sddl(grant{node, accessFull, true})},
		{filepath.Join(root, "collector"), sddl(grant{coll, accessTraverse, true})},
		{filepath.Join(root, "collector", "credentials"), sddl(grant{coll, accessFull, true})},
		{filepath.Join(root, "collector", "state"), sddl(grant{coll, accessFull, true})},
		{PublicDir(programData), sddl(grant{coll, accessFull, true}, grant{node, accessTraverse, true})},
	}
}

// PublicDir is where the collector writes what the node may read: its
// install-key.json, the public half of its sealing key (A3). Nothing in it
// is secret.
func PublicDir(programData string) string {
	return filepath.Join(programData, "OTSEC", "collector", "public")
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

// CollectorConfigPath is where the installer puts the collector's
// configuration (A3). It inherits the collector directory's DACL: SYSTEM
// and Administrators full control, the collector service read, and nothing
// for the node service.
func CollectorConfigPath(programData string) string {
	return filepath.Join(programData, "OTSEC", "collector", "collector.json")
}

// MaxCollectorConfigBytes bounds the collector configuration the installer
// copies.
const MaxCollectorConfigBytes = 4 << 20

// TLSDir is the tls_dir the node configuration must name when it has one
// (D2-12). Its DACL gives the node read and no write, owner
// Administrators, as node.Config.TargetTLS requires. An administrator
// copies the reference files in, so they inherit that DACL; a moved file
// keeps its own and the node refuses it if that grants anything else.
func TLSDir(programData string) string { return filepath.Join(programData, "OTSEC", "config", "tls") }

// AdminDir is the admin_dir the node configuration must name when it has
// one: OTSEC\config\admin, where an administrator leaves the Phase 2
// interim files such as clear-suspension.json and seq-reset-ack.json. The
// node and the collector both read it and neither can write it (A3 #117),
// and files an administrator creates there are owned by Administrators,
// as both require (protect.ReadFileFor with node.AdminReaders).
func AdminDir(programData string) string {
	return filepath.Join(programData, "OTSEC", "config", "admin")
}

// StoreDir is the store directory the node configuration must name.
func StoreDir(programData string) string { return filepath.Join(programData, "OTSEC", "store") }

// ConfigPath is where the installer puts the node configuration.
func ConfigPath(programData string) string {
	return filepath.Join(programData, "OTSEC", "config", "node.json")
}

// RequiredPrivileges is the only privilege either service keeps (W-2).
var RequiredPrivileges = []string{"SeChangeNotifyPrivilege"}

// CollectorImage is the collector binary's file name. The Windows Error
// Reporting exclusion is keyed by it, so the installer refuses a collector
// binary with another name.
const CollectorImage = "otsec-collector.exe"

// WERExclusionKey is the HKLM key under which the installer sets
// CollectorImage = 1 (REG_DWORD), so Windows Error Reporting writes no dump
// of the collector's memory, which holds credentials. The collector refuses
// to start without it (A3 T-5).
const WERExclusionKey = `SOFTWARE\Microsoft\Windows\Windows Error Reporting\ExcludedApplications`

// FirewallRule is the name of the W-3 rule the installer adds.
const FirewallRule = "otsec-node: no outbound Telnet (W-3)"
