//go:build windows

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/eventlog"
)

// The virtual account of ADR-0006 decision 1. Compiled in; never taken from input.
const serviceAccount = `NT SERVICE\activeDIQAgent`

// ChannelReadAccess is 0x1 (https://learn.microsoft.com/en-us/windows/win32/wes/eventlog-channel-access).
const channelReadAccess = 0x1

func run(args []string) int {
	if pin, ok := parseRepin(args); ok {
		root, err := dataRoot()
		if err != nil {
			fmt.Fprintln(os.Stderr, "agentsetup:", err)
			return 1
		}
		return runRepin(filepath.Join(root, "enrol"), pin, invokingActor(), openRepinAudit)
	}
	verb, ok := parseVerb(args)
	if !ok {
		return usage()
	}
	var err error
	switch verb {
	case "grant-channel":
		err = changeChannel(true)
	case "revoke-channel":
		err = changeChannel(false)
	case "write-config":
		err = writeConfig()
	case "prepare-datadir":
		var dir string
		if dir, err = dataRoot(); err == nil {
			err = prepareDataDir(dir)
		}
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "agentsetup:", err)
		if verb == "revoke-channel" {
			warnRevokeFailed(err)
		}
		return 1
	}
	return 0
}

// dataRoot is %ProgramData%\skenzeriq\agent from the known folder: not an argument and not an
// environment variable, so nothing a caller supplies can redirect a SYSTEM action (T-0688 ruling 4a).
func dataRoot() (string, error) {
	pd, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, 0)
	if err != nil {
		return "", err
	}
	return filepath.Join(pd, "skenzeriq", "agent"), nil
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

// prepareDataDir builds the agent's data tree below %ProgramData% as SYSTEM. Any local principal can
// create folders under ProgramData and owns what it creates, so nothing here trusts a path that
// already exists: each component is created with the protected DACL and Administrators as owner in
// one call; an existing component is opened without following a reparse point, must be owned by
// SYSTEM or Administrators, and (the leaf only) has its DACL set through the open handle, never by
// name. A planted junction or a user-owned parent is refused.
func prepareDataDir(dir string) error {
	pd, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, 0)
	if err != nil {
		return err
	}
	rel, err := filepath.Rel(filepath.Clean(pd), filepath.Clean(dir))
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return fmt.Errorf("data directory must be below %s", pd)
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
	sd, err := windows.NewSecurityDescriptor()
	if err != nil {
		return err
	}
	if err := sd.SetOwner(admins, false); err != nil {
		return err
	}
	if err := sd.SetDACL(acl, true, false); err != nil {
		return err
	}
	if err := sd.SetControl(windows.SE_DACL_PROTECTED, windows.SE_DACL_PROTECTED); err != nil {
		return err
	}
	sa := &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	trusted := []*windows.SID{system, admins}

	parts := strings.Split(rel, string(filepath.Separator))
	cur := filepath.Clean(pd)
	for i, part := range parts {
		cur = filepath.Join(cur, part)
		leaf := i == len(parts)-1
		if err := ensureDir(cur, sa, trusted, leaf, acl, admins); err != nil {
			return fmt.Errorf("%s: %w", cur, err)
		}
	}
	return nil
}

// ensureDir creates path with sa, or validates and (for the leaf) re-secures an existing one.
func ensureDir(path string, sa *windows.SecurityAttributes, trusted []*windows.SID, leaf bool, acl *windows.ACL, admins *windows.SID) error {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	err = windows.CreateDirectory(p, sa)
	if err != nil && !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		return err
	}
	// Open what is there (including what we just made) without following a reparse point.
	// https://learn.microsoft.com/en-us/windows/win32/fileio/reparse-points-and-file-operations
	h, err := windows.CreateFile(p, windows.READ_CONTROL|windows.WRITE_DAC|windows.WRITE_OWNER, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h)
	var fi windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &fi); err != nil {
		return err
	}
	if fi.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 || fi.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return errors.New("is a reparse point or not a directory; refusing")
	}
	osd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	owner, _, err := osd.Owner()
	if err != nil || owner == nil {
		return errors.New("cannot read owner; refusing")
	}
	ok := false
	for _, t := range trusted {
		ok = ok || windows.EqualSid(owner, t)
	}
	if !ok {
		return fmt.Errorf("owned by %s, not SYSTEM or Administrators; refusing", owner.String())
	}
	if !leaf {
		return nil
	}
	return windows.SetSecurityInfo(h, windows.SE_FILE_OBJECT,
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
	root, err := dataRoot()
	if err != nil {
		return err
	}
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

// warnRevokeFailed records in the Application log that the Security-log read ACE for the service
// SID was not removed at uninstall (the custom action is Return=ignore so uninstall still
// completes). Best effort: a failure to log is itself ignored.
func warnRevokeFailed(cause error) {
	l, err := eventlog.Open("activeDIQAgent")
	if err != nil {
		return
	}
	defer l.Close()
	_ = l.Warning(4101, "uninstall could not remove the Security event log read permission for NT SERVICE\\activeDIQAgent; remove it with wevtutil sl Security or by repeating the uninstall. Cause: "+cause.Error())
}

// invokingActor names the account (SID and, when resolvable, DOMAIN\name) running this process and
// the host. The event log itself records no user for a source-written event, so it goes in the text.
func invokingActor() string {
	host, _ := os.Hostname()
	tu, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return "unknown account on " + host
	}
	who := tu.User.Sid.String()
	if name, domain, _, err := tu.User.Sid.LookupAccount(""); err == nil {
		who = domain + `\` + name + " (" + who + ")"
	}
	return who + " on " + host
}

// openRepinAudit opens the registered agent event source. Events: 4102 success, 4103 failure. The
// message is also echoed on stderr. Pins are public values; no key material is involved.
func openRepinAudit() (auditSink, func(), error) {
	l, err := eventlog.Open(agentEventSource)
	if err != nil {
		return nil, nil, err
	}
	return func(msg string, failed bool) {
		fmt.Fprintln(os.Stderr, "agentsetup:", msg)
		if failed {
			_ = l.Error(4103, msg)
			return
		}
		_ = l.Info(4102, msg)
	}, func() { l.Close() }, nil
}
