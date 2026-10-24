//go:build windows

package winsvc

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"

	"otsec.local/otsec/platform/node"
)

// InstallOptions are the installer's inputs.
type InstallOptions struct {
	// NodeExe is otsec.exe, under %ProgramFiles%.
	NodeExe string
	// CollectorExe is A3's collector binary, under %ProgramFiles%. Empty
	// installs the node service only.
	CollectorExe string
	// Config is the node configuration to install. It is copied to
	// ConfigPath and must name StoreDir as store.dir.
	Config string
}

// Install creates the directory tree, installs the configuration and the
// services, and adds the firewall rule. It changes nothing it did not
// create: an existing directory with another owner or ACE, or an existing
// service, stops it.
func Install(opt InstallOptions) error {
	pd, pf := os.Getenv("ProgramData"), os.Getenv("ProgramFiles")
	if pd == "" || pf == "" {
		return errors.New("winsvc: ProgramData or ProgramFiles is not set")
	}
	for _, exe := range []string{opt.NodeExe, opt.CollectorExe} {
		if exe != "" && !under(exe, pf) {
			return fmt.Errorf("winsvc: %s is not under %s (W-4)", exe, pf)
		}
	}
	for _, d := range Dirs(pd) {
		if err := makeDir(d); err != nil {
			return err
		}
	}
	if err := installConfig(opt.Config, pd); err != nil {
		return err
	}
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	if err := createService(m, NodeService, opt.NodeExe, "OTSEC node", "node", "-config", ConfigPath(pd)); err != nil {
		return err
	}
	if opt.CollectorExe != "" {
		if err := createService(m, CollectorService, opt.CollectorExe, "OTSEC collector"); err != nil {
			return err
		}
	}
	if err := eventlog.InstallAsEventCreate(NodeService, eventlog.Error|eventlog.Warning|eventlog.Info); err != nil {
		return fmt.Errorf("winsvc: event log source: %w", err)
	}
	return firewall("add", "rule", "name="+FirewallRule, "dir=out", "action=block", "service="+NodeService,
		"protocol=TCP", "remoteport=23", "enable=yes")
}

// Uninstall stops and removes the services, the event log source and the
// firewall rule. It leaves the directory tree and the store: evidence is
// never deleted by an uninstall.
func Uninstall() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	var errs []error
	for _, name := range []string{NodeService, CollectorService} {
		s, err := m.OpenService(name)
		if err != nil {
			continue
		}
		s.Control(0x1) // SERVICE_CONTROL_STOP; an error means it was not running
		errs = append(errs, s.Delete())
		s.Close()
	}
	eventlog.Remove(NodeService)
	errs = append(errs, firewall("delete", "rule", "name="+FirewallRule))
	return errors.Join(errs...)
}

func under(path, root string) bool {
	p, err := filepath.Abs(path)
	if err != nil {
		return false
	}
	rel, err := filepath.Rel(root, p)
	return err == nil && rel != "." && !strings.HasPrefix(strings.ToLower(rel), "..") && filepath.VolumeName(p) != "" &&
		strings.EqualFold(filepath.VolumeName(p), filepath.VolumeName(root))
}

// makeDir creates d with its descriptor, or checks an existing one has
// exactly that descriptor's owner and ACEs.
func makeDir(d Dir) error {
	sd, err := windows.SecurityDescriptorFromString(d.SDDL)
	if err != nil {
		return fmt.Errorf("winsvc: %s: %w", d.Path, err)
	}
	if _, err := os.Lstat(d.Path); err == nil {
		return checkDir(d, sd)
	}
	p, err := windows.UTF16PtrFromString(d.Path)
	if err != nil {
		return err
	}
	sa := &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	if err := windows.CreateDirectory(p, sa); err != nil {
		return fmt.Errorf("winsvc: create %s: %w", d.Path, err)
	}
	// Read it back: the descriptor Windows stored is what is checked.
	return checkDir(d, sd)
}

// checkDir refuses a directory whose owner, protection or ACEs differ from
// want's (W-4).
func checkDir(d Dir, want *windows.SECURITY_DESCRIPTOR) error {
	got, err := windows.GetNamedSecurityInfo(d.Path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("winsvc: read the DACL of %s: %w", d.Path, err)
	}
	fail := func(why string) error {
		return fmt.Errorf("winsvc: %s exists with %s; the installer stops (W-4). Found %s", d.Path, why, got.String())
	}
	owner, _, err := got.Owner()
	wantOwner, _, _ := want.Owner()
	if err != nil || owner == nil || !owner.Equals(wantOwner) {
		return fail("another owner")
	}
	ctl, _, err := got.Control()
	if err != nil || ctl&windows.SE_DACL_PROTECTED == 0 {
		return fail("an inherited DACL")
	}
	ga, err := aces(got)
	if err != nil {
		return fail(err.Error())
	}
	wa, err := aces(want)
	if err != nil {
		return err
	}
	if len(ga) != len(wa) {
		return fail(fmt.Sprintf("%d ACEs, want %d", len(ga), len(wa)))
	}
	for i := range wa {
		if ga[i] != wa[i] {
			return fail(fmt.Sprintf("ACE %d %+v, want %+v", i, ga[i], wa[i]))
		}
	}
	return nil
}

type ace struct {
	typ, flags byte
	mask       windows.ACCESS_MASK
	sid        string
}

func aces(sd *windows.SECURITY_DESCRIPTOR) ([]ace, error) {
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		return nil, errors.New("no DACL")
	}
	var out []ace
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var a *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &a); err != nil {
			return nil, err
		}
		if a.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return nil, fmt.Errorf("ACE %d has type %d", i, a.Header.AceType)
		}
		sid := (*windows.SID)(unsafe.Pointer(&a.SidStart))
		out = append(out, ace{a.Header.AceType, a.Header.AceFlags, a.Mask, sid.String()})
	}
	return out, nil
}

// installConfig copies the configuration into the config directory, which
// it inherits its DACL from, and loads it there.
func installConfig(src, pd string) error {
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	cfg, err := node.ParseConfig(b)
	if err != nil {
		return err
	}
	if !strings.EqualFold(filepath.Clean(cfg.Store.Dir), StoreDir(pd)) {
		return fmt.Errorf("winsvc: store.dir is %s; the installed node keeps its store in %s", cfg.Store.Dir, StoreDir(pd))
	}
	dst := ConfigPath(pd)
	if _, err := os.Lstat(dst); err == nil {
		return fmt.Errorf("winsvc: %s exists; uninstall and remove it first", dst)
	}
	if err := os.WriteFile(dst, b, 0o600); err != nil {
		return err
	}
	_, err = node.LoadConfig(dst)
	return err
}

// serviceRequiredPrivilegesInfo is SERVICE_REQUIRED_PRIVILEGES_INFO.
type serviceRequiredPrivilegesInfo struct {
	RequiredPrivileges *uint16 // a double-NUL-terminated list
}

func createService(m *mgr.Mgr, name, exe, display string, args ...string) error {
	if s, err := m.OpenService(name); err == nil {
		s.Close()
		return fmt.Errorf("winsvc: service %s exists; uninstall first", name)
	}
	s, err := m.CreateService(name, exe, mgr.Config{
		ServiceType:      windows.SERVICE_WIN32_OWN_PROCESS,
		StartType:        mgr.StartAutomatic,
		ErrorControl:     mgr.ErrorNormal,
		ServiceStartName: `NT SERVICE\` + name,
		DisplayName:      display,
		Description:      display + " (read-only OT monitoring; see docs/phase2)",
		SidType:          windows.SERVICE_SID_TYPE_UNRESTRICTED,
	}, args...)
	if err != nil {
		return fmt.Errorf("winsvc: create %s: %w", name, err)
	}
	defer s.Close()
	var list []uint16
	for _, p := range RequiredPrivileges {
		u, _ := windows.UTF16FromString(p)
		list = append(list, u...)
	}
	list = append(list, 0)
	info := serviceRequiredPrivilegesInfo{RequiredPrivileges: &list[0]}
	if err := windows.ChangeServiceConfig2(s.Handle, windows.SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO, (*byte)(unsafe.Pointer(&info))); err != nil {
		s.Delete()
		return fmt.Errorf("winsvc: %s required privileges (W-2): %w", name, err)
	}
	if err := s.SetRecoveryActions([]mgr.RecoveryAction{{Type: mgr.ServiceRestart, Delay: 60e9}}, 86400); err != nil {
		s.Delete()
		return fmt.Errorf("winsvc: %s recovery actions: %w", name, err)
	}
	return nil
}

func firewall(args ...string) error {
	out, err := exec.Command("netsh", append([]string{"advfirewall", "firewall"}, args...)...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("winsvc: netsh %s: %v: %s", strings.Join(args, " "), err, out)
	}
	return nil
}
