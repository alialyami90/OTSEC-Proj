//go:build windows

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

var procWerAddExcludedApplication = windows.NewLazySystemDLL("wer.dll").NewProc("WerAddExcludedApplication")

// werExclusions is where Windows Error Reporting lists the applications it
// must not report on or dump. The installer adds the collector machine-wide
// (A5, platform/winsvc).
const werExclusions = `SOFTWARE\Microsoft\Windows\Windows Error Reporting\ExcludedApplications`

// harden keeps secrets out of crash dumps (T-5, design section 10):
//
//   - no fault dialog that would hold the process open for a debugger;
//   - the collector excluded from Windows Error Reporting for its own
//     account (WerAddExcludedApplication), best effort: under the SCM the
//     virtual account's registry hive may not be loaded, and the
//     machine-wide exclusion below is the control;
//   - and it refuses to start unless the installer's machine-wide
//     exclusion is in place, so a dump cannot come from WER's
//     machine-wide LocalDumps either.
//
// That the exclusion also suppresses LocalDumps is [inferred] from the WER
// documentation, and is test T-5 on the Windows site image.
func harden() error {
	if err := checkTraceback(); err != nil {
		return err
	}
	windows.SetErrorMode(windows.SEM_FAILCRITICALERRORS | windows.SEM_NOGPFAULTERRORBOX)
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	name := filepath.Base(exe)
	p, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return err
	}
	if procWerAddExcludedApplication.Find() == nil {
		procWerAddExcludedApplication.Call(uintptr(unsafe.Pointer(p)), 0)
	}
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, werExclusions, registry.QUERY_VALUE)
	if err != nil {
		return fmt.Errorf("WER machine-wide exclusion missing (%s): %w", werExclusions, err)
	}
	defer k.Close()
	v, _, err := k.GetIntegerValue(name)
	if err != nil || v != 1 {
		return errors.New("WER machine-wide exclusion for " + name + " is not set to 1; the installer sets it")
	}
	return nil
}
