//go:build windows

package dial

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"

	"github.com/skenzeriq/activediq/internal/platform/ownerfile"
)

// T-1341 Windows-lab tests: an elevated administrator enrols and repins the state directory of a
// service identity (a virtual account), the service's own Load then succeeds, and a non-administrator
// is refused with nothing written. They need a real service account, so they run only when the lab
// harness (lab/windows/bin/identity-verify) passes -diq.account and -diq.parent; the
// service-side check runs as a Windows service under that account.
var (
	labOut = flag.String("diq.out", "", "service-side check: file to write results to")
	labDir = flag.String("diq.dir", "", "service-side check: state directory to load")

	labAccount = flag.String("diq.account", "", "service account whose state is operated on, e.g. NT SERVICE\\diqT1341")
	labParent  = flag.String("diq.parent", "", "trusted parent directory that holds the state directory")
)

func labEnv(t *testing.T) (account, parent string) {
	t.Helper()
	account, parent = *labAccount, *labParent
	if account == "" || parent == "" {
		t.Skip("T-1341 lab test: -diq.account / -diq.parent not set")
	}
	return account, parent
}

func TestWindowsLabEnrolAsServiceIdentity(t *testing.T) {
	acct, parent := labEnv(t)
	iss, m, _ := setup(t)
	dir := filepath.Join(parent, "enrol")
	st, err := Enroll(context.Background(), m, dir, iss.exchange, ForAccount(acct))
	if err != nil {
		t.Fatalf("elevated enrol for the service identity: %v", err)
	}
	if st.Pin != iss.srv.pin() {
		t.Fatalf("pin = %s", st.Pin)
	}
}

func TestWindowsLabRepinAsServiceIdentity(t *testing.T) {
	acct, parent := labEnv(t)
	dir := filepath.Join(parent, "enrol")
	// The administrator reads the state the way agentsetup does: as the account, not as itself.
	before, err := pinFor(dir, acct)
	if err != nil {
		t.Fatal(err)
	}
	// The server CA was replaced: the new server presents it, and the state's endpoint points at it.
	newSrv := newCA(t, "new installation server CA")
	addr := serveChain(t, newSrv, newSrv.der)
	d, err := ownerfile.OpenDir(dir, ownerfile.ForAccount(acct))
	if err != nil {
		t.Fatal(err)
	}
	if err := d.WriteFile(EndpointsFile, []byte(addr+"\n")); err != nil {
		t.Fatal(err)
	}
	d.Close()

	var events []RepinEvent
	if err := Repin(context.Background(), dir, newSrv.pin().String(), func(e RepinEvent) { events = append(events, e) }, ForAccount(acct)); err != nil {
		t.Fatalf("elevated repin for the service identity: %v", err)
	}
	if len(events) != 1 || events[0].Err != nil || events[0].OldPin != before || events[0].NewPin != newSrv.pin() {
		t.Fatalf("audit = %+v", events)
	}
	// The service's own Load of the new state is checked by the harness (service-side run).
	if after, err := pinFor(dir, acct); err != nil || after != newSrv.pin() {
		t.Fatalf("pin after repin = %v, %v", after, err)
	}
	if err := os.WriteFile(filepath.Join(parent, "newpin.txt"), []byte(newSrv.pin().String()), 0o600); err != nil {
		t.Fatal(err)
	}
}

// A caller that is not an elevated administrator is refused before anything is opened, by Repin and by
// Enroll, and the directory is untouched (the harness compares listings and descriptors around it).
// The parent test runs the child as a restricted copy of its own token: Administrators is a deny-only
// group and every privilege is removed, which is what an administrator's filtered (non-elevated)
// token looks like, and what any non-administrator has. A domain controller has no local users, so a
// real second account is not available on the lab DC.
func TestWindowsLabNonAdminRefused(t *testing.T) {
	acct, parent := labEnv(t)
	if os.Getenv("DIQ_T1341_CHILD") == "" {
		tok, err := restrictedToken()
		if err != nil {
			t.Fatal(err)
		}
		defer tok.Close()
		// The restricted token cannot resolve a service name through the LSA (the lookup fails with
		// "handle is invalid"), so hand it the SID in its string form.
		sid, _, _, err := windows.LookupSID("", acct)
		if err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(os.Args[0], "-test.run=^TestWindowsLabNonAdminRefused$", "-test.v", "-diq.account="+sid.String(), "-diq.parent="+parent)
		cmd.Env = append(os.Environ(), "DIQ_T1341_CHILD=1")
		cmd.SysProcAttr = &syscall.SysProcAttr{Token: syscall.Token(tok)}
		out, err := cmd.CombinedOutput()
		t.Logf("restricted child:\n%s", out)
		if err != nil || !strings.Contains(string(out), "--- PASS: TestWindowsLabNonAdminRefused") {
			t.Fatalf("restricted child failed: %v", err)
		}
		return
	}
	if admins, _ := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid); admins != nil {
		if member, _ := windows.Token(0).IsMember(admins); member {
			t.Fatal("the child still is a member of Administrators; the restriction did not apply")
		}
	}
	// No code gate: the refusal comes from the DACL and the owner check (T-2215 ruling, AC2). First the
	// raw file operations Repin and Enroll are built on, which only the DACL can refuse here.
	dir := filepath.Join(parent, "enrol")
	if _, err := os.ReadDir(dir); err == nil {
		t.Fatal("the non-admin listed the state directory")
	}
	if _, err := os.ReadFile(filepath.Join(dir, KeyFile)); err == nil {
		t.Fatal("the non-admin read key.pem")
	}
	if err := os.WriteFile(filepath.Join(dir, PinFile), []byte("x"), 0o600); err == nil {
		t.Fatal("the non-admin overwrote the pin")
	}
	if err := os.Mkdir(filepath.Join(parent, "other"), 0o700); err == nil {
		t.Fatal("the non-admin created a directory under the trusted parent")
	}
	// Then the verbs themselves (in a restricted token the account name does not even resolve, so these
	// refusals are weaker evidence; the raw operations above are the DACL proof).
	err := Repin(context.Background(), dir, "sha256:"+strings.Repeat("ab", 32), func(RepinEvent) {}, ForAccount(acct))
	if err == nil {
		t.Fatal("Repin as non-admin succeeded")
	}
	t.Logf("repin refused: %v", err)
	iss, m, _ := setup(t)
	if _, err := Enroll(context.Background(), m, filepath.Join(parent, "other"), iss.exchange, ForAccount(acct)); err == nil {
		t.Fatal("Enroll as non-admin succeeded")
	} else {
		t.Logf("enrol refused: %v", err)
	}
	if _, err := os.Stat(filepath.Join(parent, "other")); err == nil {
		t.Fatal("a refused enrol created a directory")
	}
}

// restrictedToken returns a primary token that is the caller's with every privilege removed and
// BUILTIN\\Administrators turned into a deny-only group.
// https://learn.microsoft.com/windows/win32/api/securitybaseapi/nf-securitybaseapi-createrestrictedtoken
func restrictedToken() (windows.Token, error) {
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return 0, err
	}
	var self windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_DUPLICATE|windows.TOKEN_QUERY|windows.TOKEN_ASSIGN_PRIMARY, &self); err != nil {
		return 0, err
	}
	defer self.Close()
	const disableMaxPrivilege = 0x1
	sids := []windows.SIDAndAttributes{{Sid: admins}}
	var out windows.Token
	r, _, e := windows.NewLazySystemDLL("advapi32.dll").NewProc("CreateRestrictedToken").Call(
		uintptr(self), disableMaxPrivilege, uintptr(len(sids)), uintptr(unsafe.Pointer(&sids[0])), 0, 0, 0, 0, uintptr(unsafe.Pointer(&out)))
	if r == 0 {
		return 0, e
	}
	return out, nil
}

// TestWindowsLabServiceSide is not a test of this process: the harness registers the test binary as a
// service running as the service identity, and this function is its service body. It Loads the state
// exactly as the agent does (token user = the directory owner) and records the outcome, the owner and
// DACL of the directory and every file in it (icacls), for the evidence.
func TestWindowsLabServiceSide(t *testing.T) {
	if *labOut == "" {
		t.Skip("service-side check only")
	}
	if is, _ := svc.IsWindowsService(); !is {
		t.Skip("not running as a service")
	}
	if err := svc.Run("diqT1341", labService{}); err != nil {
		t.Fatal(err)
	}
}

type labService struct{}

func (labService) Execute(_ []string, _ <-chan svc.ChangeRequest, s chan<- svc.Status) (bool, uint32) {
	s <- svc.Status{State: svc.StartPending}
	s <- svc.Status{State: svc.Running}
	var out strings.Builder
	tu, _ := windows.GetCurrentProcessToken().GetTokenUser()
	fmt.Fprintf(&out, "service token user: %s\n", tu.User.Sid)
	if st, err := Load(*labDir); err != nil {
		fmt.Fprintf(&out, "load: FAILED: %v\n", err)
	} else {
		fmt.Fprintf(&out, "load: ok pin=%s\n", st.Pin)
	}
	ic, _ := exec.Command(`C:\Windows\System32\icacls.exe`, *labDir, "/T").CombinedOutput()
	fmt.Fprintf(&out, "icacls:\n%s\n", ic)
	ents, _ := os.ReadDir(*labDir)
	for _, e := range ents {
		fmt.Fprintf(&out, "entry: %s\n", e.Name())
	}
	_ = os.WriteFile(*labOut, []byte(out.String()), 0o600)
	return false, 0
}

// pinFor reads the pin of the state directory as an administrator acting for the account.
func pinFor(dir, acct string) (Pin, error) {
	d, err := ownerfile.OpenDir(dir, ownerfile.ForAccount(acct))
	if err != nil {
		return Pin{}, err
	}
	defer d.Close()
	b, err := d.ReadFile(PinFile)
	if err != nil {
		return Pin{}, err
	}
	return ParsePin(strings.TrimSpace(string(b)))
}
