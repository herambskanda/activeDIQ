//go:build windows

package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The virtual account of ADR-0006 decision 1. Compiled in; never taken from input.
const serviceAccount = `NT SERVICE\activeDIQAgent`

// ChannelReadAccess is 0x1 (https://learn.microsoft.com/en-us/windows/win32/wes/eventlog-channel-access).
const channelReadAccess = 0x1

func run(args []string) int {
	if len(args) == 0 {
		return usage()
	}
	var err error
	switch args[0] {
	case "grant-channel":
		err = changeChannel(true)
	case "revoke-channel":
		err = changeChannel(false)
	case "write-config":
		err = writeConfig()
	case "prepare-datadir":
		fs := flag.NewFlagSet("prepare-datadir", flag.ContinueOnError)
		dir := fs.String("data-dir", "", "absolute data directory")
		if fs.Parse(args[1:]) != nil || !filepath.IsAbs(*dir) {
			return usage()
		}
		err = prepareDataDir(*dir)
	default:
		return usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "agentsetup:", err)
		return 1
	}
	return 0
}

func serviceSID() (*windows.SID, error) {
	sid, _, _, err := windows.LookupSID("", serviceAccount)
	return sid, err
}

// ---- Security channel ACE through wevtapi ----
// EvtOpenChannelConfig / EvtGetChannelConfigProperty / EvtSetChannelConfigProperty /
// EvtSaveChannelConfig: https://learn.microsoft.com/en-us/windows/win32/api/winevt/
// The property id of EvtChannelConfigAccess is 5 [UNVERIFIED — lab].

var (
	wevtapi   = windows.NewLazySystemDLL("wevtapi.dll")
	pOpenCfg  = wevtapi.NewProc("EvtOpenChannelConfig")
	pGetCfg   = wevtapi.NewProc("EvtGetChannelConfigProperty")
	pSetCfg   = wevtapi.NewProc("EvtSetChannelConfigProperty")
	pSaveCfg  = wevtapi.NewProc("EvtSaveChannelConfig")
	pCloseEvt = wevtapi.NewProc("EvtClose")
)

const (
	evtChannelConfigAccess = 5
	evtVarTypeString       = 1
)

// evtVariant mirrors EVT_VARIANT: an 8-byte value, a count and a type.
type evtVariant struct {
	Value uint64
	Count uint32
	Type  uint32
}

func changeChannel(grant bool) error {
	sid, err := serviceSID()
	if err != nil {
		return fmt.Errorf("service account is not resolvable (install the service first): %w", err)
	}
	name, _ := windows.UTF16PtrFromString("Security")
	h, _, e := pOpenCfg.Call(0, uintptr(unsafe.Pointer(name)), 0)
	if h == 0 {
		return e
	}
	defer pCloseEvt.Call(h)

	buf := make([]byte, 16<<10)
	var used uint32
	if r, _, e := pGetCfg.Call(h, evtChannelConfigAccess, 0, uintptr(len(buf)), uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&used))); r == 0 {
		return e
	}
	v := (*evtVariant)(unsafe.Pointer(&buf[0]))
	if v.Type != evtVarTypeString || v.Value == 0 {
		return errors.New("channel access descriptor has an unexpected type")
	}
	current := windows.UTF16PtrToString(*(**uint16)(unsafe.Pointer(&v.Value)))

	next, err := editSDDL(current, sid, grant)
	if err != nil {
		return err
	}
	np, err := windows.UTF16PtrFromString(next)
	if err != nil {
		return err
	}
	nv := evtVariant{Type: evtVarTypeString}
	*(**uint16)(unsafe.Pointer(&nv.Value)) = np
	if r, _, e := pSetCfg.Call(h, evtChannelConfigAccess, 0, uintptr(unsafe.Pointer(&nv))); r == 0 {
		return e
	}
	if r, _, e := pSaveCfg.Call(h, 0); r == 0 {
		return e
	}
	return nil
}

// editSDDL parses the channel's descriptor, adds or removes exactly one ACE for sid through the typed
// ACL APIs and renders the result. No SDDL fragment is concatenated by hand.
func editSDDL(current string, sid *windows.SID, grant bool) (string, error) {
	sd, err := windows.SecurityDescriptorFromString(current)
	if err != nil {
		return "", err
	}
	old, _, err := sd.DACL()
	if err != nil {
		return "", err
	}
	mode := windows.ACCESS_MODE(windows.REVOKE_ACCESS)
	if grant {
		mode = windows.GRANT_ACCESS
	}
	ea := []windows.EXPLICIT_ACCESS{{
		AccessPermissions: channelReadAccess,
		AccessMode:        mode,
		Trustee: windows.TRUSTEE{TrusteeForm: windows.TRUSTEE_IS_SID, TrusteeType: windows.TRUSTEE_IS_UNKNOWN,
			TrusteeValue: windows.TrusteeValueFromSID(sid)},
	}}
	acl, err := windows.ACLFromEntries(ea, old)
	if err != nil {
		return "", err
	}
	out, err := windows.NewSecurityDescriptor()
	if err != nil {
		return "", err
	}
	if owner, _, e := sd.Owner(); e == nil && owner != nil {
		_ = out.SetOwner(owner, false)
	}
	if group, _, e := sd.Group(); e == nil && group != nil {
		_ = out.SetGroup(group, false)
	}
	if err := out.SetDACL(acl, true, false); err != nil {
		return "", err
	}
	return out.String(), nil
}

// ---- Data directory ----

func prepareDataDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	sid, err := serviceSID()
	if err != nil {
		return err
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return err
	}
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return err
	}
	var ea []windows.EXPLICIT_ACCESS
	for _, s := range []*windows.SID{sid, system, admins} {
		ea = append(ea, windows.EXPLICIT_ACCESS{
			AccessPermissions: windows.GENERIC_ALL, AccessMode: windows.SET_ACCESS,
			Inheritance: windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT,
			Trustee:     windows.TRUSTEE{TrusteeForm: windows.TRUSTEE_IS_SID, TrusteeValue: windows.TrusteeValueFromSID(s)},
		})
	}
	acl, err := windows.ACLFromEntries(ea, nil)
	if err != nil {
		return err
	}
	// PROTECTED: no inherited entries from the parent. Owner is Administrators.
	return windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION|windows.OWNER_SECURITY_INFORMATION,
		admins, nil, acl, nil)
}

// writeConfig writes agent.json next to the executable. The install directory is writable by
// Administrators and SYSTEM only, so the service cannot widen the ceilings it contains. Values are
// marshalled, never formatted into text.
func writeConfig() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	pd, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, 0)
	if err != nil {
		return err
	}
	root := filepath.Join(pd, "skenzeriq", "agent")
	b, err := json.MarshalIndent(map[string]any{
		"data_dir":              filepath.Join(root, "data"),
		"enrollment_dir":        filepath.Join(root, "enrol"),
		"outbox_max_bytes":      256 << 20,
		"batch_max_bytes":       256 << 10,
		"max_events_per_second": 2000,
	}, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(filepath.Dir(exe), "agent.json"), b, 0o644)
}
