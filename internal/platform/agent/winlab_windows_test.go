//go:build windows && windowslab

package agent

import (
	"context"
	"errors"
	"encoding/binary"
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/skenzeriq/activediq/internal/agenthost/hostapi"
)

// Lab tests for the Windows adapters (T-0648). They need an elevated token on a Windows lab host and
// create their trees under ProgramData, so they run only with -tags windowslab, never in unit CI:
//
//	GOOS=windows go test -c -tags windowslab -o agent.test.exe ./internal/platform/agent
//
// then run agent.test.exe -test.run TestLab on the lab DC (lab/windows/guest/agent-verify.ps1 does).

func labSID(t *testing.T, k windows.WELL_KNOWN_SID_TYPE) *windows.SID {
	t.Helper()
	s, err := windows.CreateWellKnownSid(k)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// aclOf builds an ACL from plain allow entries (typed API).
func allowACL(t *testing.T, sids ...*windows.SID) *windows.ACL {
	t.Helper()
	var ea []windows.EXPLICIT_ACCESS
	for _, s := range sids {
		ea = append(ea, windows.EXPLICIT_ACCESS{AccessPermissions: windows.GENERIC_ALL, AccessMode: windows.SET_ACCESS,
			Inheritance: windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT,
			Trustee:     windows.TRUSTEE{TrusteeForm: windows.TRUSTEE_IS_SID, TrusteeType: windows.TRUSTEE_IS_UNKNOWN, TrusteeValue: windows.TrusteeValueFromSID(s)}})
	}
	acl, err := windows.ACLFromEntries(ea, nil)
	if err != nil {
		t.Fatal(err)
	}
	return acl
}

// callbackACL is an ACL whose only entry is an ACCESS_ALLOWED_CALLBACK_ACE (type 9) for sid, which
// x/sys cannot build, so the bytes are laid out by hand (ACL and ACE headers per winnt.h).
func callbackACL(sid *windows.SID) *windows.ACL {
	sidLen := int(windows.GetLengthSid(sid))
	aceSize := 8 + sidLen
	aceSize = (aceSize + 3) &^ 3
	buf := make([]byte, 8+aceSize)
	buf[0] = 2 // ACL_REVISION
	binary.LittleEndian.PutUint16(buf[2:], uint16(len(buf)))
	binary.LittleEndian.PutUint16(buf[4:], 1)
	buf[8] = 9 // ACCESS_ALLOWED_CALLBACK_ACE_TYPE
	binary.LittleEndian.PutUint16(buf[10:], uint16(aceSize))
	binary.LittleEndian.PutUint32(buf[12:], 0x1f01ff)
	copy(buf[16:], unsafe.Slice((*byte)(unsafe.Pointer(sid)), sidLen))
	return (*windows.ACL)(unsafe.Pointer(&buf[0]))
}

func setDACL(t *testing.T, dir string, owner *windows.SID, acl *windows.ACL) {
	t.Helper()
	info := windows.SECURITY_INFORMATION(windows.DACL_SECURITY_INFORMATION | windows.PROTECTED_DACL_SECURITY_INFORMATION)
	if owner != nil {
		info |= windows.OWNER_SECURITY_INFORMATION
	}
	if err := windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, info, owner, nil, acl, nil); err != nil {
		t.Fatalf("SetNamedSecurityInfo %s: %v", dir, err)
	}
}

func enablePrivilege(t *testing.T, name string) {
	t.Helper()
	var luid windows.LUID
	if err := windows.LookupPrivilegeValue(nil, windows.StringToUTF16Ptr(name), &luid); err != nil {
		t.Fatal(err)
	}
	var tok windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &tok); err != nil {
		t.Fatal(err)
	}
	defer tok.Close()
	tp := windows.Tokenprivileges{PrivilegeCount: 1}
	tp.Privileges[0] = windows.LUIDAndAttributes{Luid: luid, Attributes: windows.SE_PRIVILEGE_ENABLED}
	if err := windows.AdjustTokenPrivileges(tok, false, &tp, 0, nil, nil); err != nil {
		t.Fatal(err)
	}
}

// TestLabCheckDataDir covers the T-0555 review cases: a plain tree passes; an allow for Everyone, a
// callback ACE, a foreign owner and a writable parent are each refused, on the leaf and on the parent.
func TestLabCheckDataDir(t *testing.T) {
	enablePrivilege(t, "SeRestorePrivilege")
	pd, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, 0)
	if err != nil {
		t.Fatal(err)
	}
	root, err := os.MkdirTemp(pd, "agentlab-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	system, admins := labSID(t, windows.WinLocalSystemSid), labSID(t, windows.WinBuiltinAdministratorsSid)
	everyone, users := labSID(t, windows.WinWorldSid), labSID(t, windows.WinBuiltinUsersSid)
	parent := filepath.Join(root, "agent")
	leaf := filepath.Join(parent, "data")
	for _, d := range []string{parent, leaf} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	good := func() {
		setDACL(t, parent, admins, allowACL(t, system, admins))
		setDACL(t, leaf, admins, allowACL(t, system, admins))
	}
	good()
	if err := CheckDataDir(leaf); err != nil {
		t.Fatalf("a SYSTEM/Administrators tree must pass: %v", err)
	}
	cases := []struct {
		name string
		do   func()
	}{
		{"allow Everyone on leaf", func() { setDACL(t, leaf, admins, allowACL(t, system, admins, everyone)) }},
		{"allow Users on parent", func() { setDACL(t, parent, admins, allowACL(t, system, admins, users)) }},
		{"callback ACE for Everyone on leaf", func() { setDACL(t, leaf, admins, callbackACL(everyone)) }},
		{"foreign owner on leaf", func() { setDACL(t, leaf, users, allowACL(t, system, admins)) }},
		{"foreign owner on parent", func() { setDACL(t, parent, users, allowACL(t, system, admins)) }},
	}
	for _, c := range cases {
		good()
		c.do()
		if err := CheckDataDir(leaf); err == nil {
			t.Errorf("%s: CheckDataDir accepted it", c.name)
		} else {
			t.Logf("%s: refused: %v", c.name, err)
		}
	}
	good()
	link := filepath.Join(root, "junction")
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", link, leaf).CombinedOutput(); err != nil {
		t.Fatalf("mklink: %v %s", err, out)
	}
	if err := CheckDataDir(link); err == nil {
		t.Error("a junction was accepted as a data directory")
	}
}

var recRe = regexp.MustCompile(`(?i)oldestRecordNumber:\s*(\d+)`)

// TestLabOldestRecord checks EVT_LOG_PROPERTY_ID 6 and the EVT_VARIANT layout against the number the
// OS reports for the Security log, and that wiping the log with 1102 moves it forward.
func TestLabOldestRecord(t *testing.T) {
	want := func() uint64 {
		out, err := exec.Command("wevtutil", "gli", "Security").CombinedOutput()
		if err != nil {
			t.Fatalf("wevtutil gli: %v %s", err, out)
		}
		m := recRe.FindSubmatch(out)
		if m == nil {
			t.Fatalf("no oldestRecordNumber in %s", out)
		}
		n, _ := strconv.ParseUint(string(m[1]), 10, 64)
		return n
	}
	got, err := winSource{}.OldestRecord(hostapi.ChannelSecurity)
	if err != nil {
		t.Fatal(err)
	}
	if w := want(); got != w {
		t.Fatalf("OldestRecord = %d, wevtutil says %d", got, w)
	}
	before := got
	if out, err := exec.Command("wevtutil", "cl", "Security").CombinedOutput(); err != nil {
		t.Fatalf("wevtutil cl: %v %s", err, out)
	}
	after, err := winSource{}.OldestRecord(hostapi.ChannelSecurity)
	if err != nil {
		t.Fatal(err)
	}
	if after <= before-1 && after == before {
		t.Fatalf("oldest record did not move after clearing the log: %d -> %d", before, after)
	}
	if w := want(); after != w {
		t.Fatalf("after clear: OldestRecord = %d, wevtutil says %d", after, w)
	}
	t.Logf("oldest record %d -> %d after clearing Security (a 1102 is written)", before, after)
}

var labOut = flag.String("labout", "", "TestLabReadAsService: file that receives the result line")

// TestLabReadAsService is run by agent-verify with the agent service's own image pointed at this binary,
// so SCM starts it with the real restricted service token. It reads the Security channel through the
// same Subscribe the agent uses and writes "readable events=N" or "unreadable" to -labout.
func TestLabReadAsService(t *testing.T) {
	if *labOut == "" {
		t.Skip("run by agent-verify as the service identity")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	n := 0
	err := winSource{}.Subscribe(ctx, hostapi.ChannelSecurity, 1, nil, func([]byte) { n++ })
	res := "readable events=" + strconv.Itoa(n)
	switch {
	case errors.Is(err, hostapi.ErrUnreadable):
		res = "unreadable"
	case err != nil && !errors.Is(err, context.DeadlineExceeded):
		res = "error " + err.Error()
	}
	if werr := os.WriteFile(*labOut, []byte(res), 0o644); werr != nil {
		t.Fatal(werr)
	}
}
