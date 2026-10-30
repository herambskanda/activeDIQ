package hostcheck

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func ip(i int) *int { return &i }

// clean is a compliant booted install on the given profile; every fixture below breaks one thing in it.
func clean(profile string) Observation {
	o := Observation{
		Profile:   profile,
		Installer: &Installer{OnDomainController: true, Refused: true},
		Service:   &Service{Account: "10001:10001", UID: ip(10001)},
		Files: []File{
			{Path: "/var/lib/activediq/tls", Kind: "tls-dir", Mode: "0700"},
			{Path: "/var/lib/activediq/tls/server.key", Kind: "tls-key", Mode: "0600"},
		},
		First: &FirstRun{Listeners: []Listener{{Addr: "127.0.0.1:8080", TLS: true}}},
		Setup: &Setup{UsedOnce: true},
		Dumps: &Dumps{CoreLimitZero: true, NotDumpable: true},
		DSN: []DSNProbe{
			{Mode: "require", Remote: true},
			{Mode: "loopback", MustAccept: true, Accepted: true},
		},
	}
	if profile == "windows" {
		o.Service = &Service{Account: `CORP\activediq$`}
	}
	return o
}

func failures(t *testing.T, o Observation, c string) []string {
	t.Helper()
	for _, r := range Evaluate(o) {
		if r.Case == c {
			if r.Inactive != "" {
				t.Fatalf("%s inactive: %s", c, r.Inactive)
			}
			return r.Failures
		}
	}
	t.Fatalf("no case %s", c)
	return nil
}

func TestCleanInstallPassesEveryCase(t *testing.T) {
	for _, p := range []string{"linux-oci", "windows"} {
		for _, r := range Evaluate(clean(p)) {
			if r.Inactive != "" || len(r.Failures) > 0 {
				t.Errorf("%s %s: %+v", p, r.Case, r)
			}
		}
	}
}

// Each row is a failing fixture: the named case must fire, and only that case.
func TestEachCaseFailsOnItsViolation(t *testing.T) {
	rows := []struct {
		name, c, want string
		mut           func(*Observation)
	}{
		{"installer accepts a DC", CaseDC, "did not refuse", func(o *Observation) { o.Installer.Refused = false }},
		{"installer leaves files on a DC", CaseDC, "exist on a domain controller", func(o *Observation) { o.Installer.Installed = true }},
		{"LocalSystem", CaseIdent, "LocalSystem", func(o *Observation) { o.Service = &Service{Account: `NT AUTHORITY\SYSTEM`} }},
		{"uid 0", CaseIdent, "uid 0", func(o *Observation) { o.Service = &Service{Account: "0:0", UID: ip(0)} }},
		{"root by name", CaseIdent, "root", func(o *Observation) { o.Service = &Service{Account: "root"} }},
		{"empty identity", CaseIdent, "empty", func(o *Observation) { o.Service = &Service{} }},
		{"key readable by group", CasePerms, "readable by a principal", func(o *Observation) { o.Files[1].ReadableByOthers = true }},
		{"keystore readable", CasePerms, "keystore", func(o *Observation) {
			o.Files = append(o.Files, File{Path: "ks", Kind: "keystore", ReadableByOthers: true})
		}},
		{"binary replaceable", CasePerms, "writable", func(o *Observation) {
			o.Files = append(o.Files, File{Path: "bin", Kind: "binary", WritableByOthers: true})
		}},
		{"default admin/admin", CaseCred, "admin", func(o *Observation) { o.First.DefaultCredentials = []string{"admin on /api/v1/session"} }},
		{"plaintext answers", CasePlaintext, "plaintext request", func(o *Observation) { o.First.Listeners[0].PlaintextResponds = true }},
		{"no TLS handshake", CasePlaintext, "TLS handshake", func(o *Observation) { o.First.Listeners[0].TLS = false }},
		{"nothing listening", CasePlaintext, "no listener", func(o *Observation) { o.First.Listeners = nil }},
		{"setup secret reusable", CaseSetup, "second time", func(o *Observation) { o.Setup.AcceptedAgain = true }},
		{"expired secret accepted", CaseSetup, "expired", func(o *Observation) { o.Setup.ExpiredAccepted = true }},
		{"setup secret world readable", CaseSetup, "readable", func(o *Observation) { o.Setup.ReadableByOthers = true }},
		{"setup probe proves nothing", CaseSetup, "first time", func(o *Observation) { o.Setup.UsedOnce = false }},
		{"core dumps allowed", CaseDumps, "RLIMIT_CORE", func(o *Observation) { o.Dumps.CoreLimitZero = false }},
		{"dumpable", CaseDumps, "dumpable", func(o *Observation) { o.Dumps.NotDumpable = false }},
		{"crash-level traceback", CaseDumps, "crash dump", func(o *Observation) { o.Dumps.TracebackCrash = true }},
		{"pprof", CaseDumps, "pprof", func(o *Observation) { o.Dumps.PprofListens = true }},
		{"remote DSN accepted weak", CaseDSN, "was accepted", func(o *Observation) { o.DSN[0].Accepted = true }},
		{"remote DSN dialled first", CaseDSN, "connected to a remote host", func(o *Observation) { o.DSN[0].Contacted = true }},
		{"compliant DSN refused", CaseDSN, "compliant DSN", func(o *Observation) { o.DSN[1].Accepted = false }},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			o := clean("linux-oci")
			r.mut(&o)
			f := failures(t, o, r.c)
			if len(f) == 0 || !strings.Contains(strings.Join(f, "\n"), r.want) {
				t.Fatalf("case %s did not fail with %q: %v", r.c, r.want, f)
			}
			for _, res := range Evaluate(o) {
				if res.Case != r.c && len(res.Failures) > 0 {
					t.Errorf("fixture for %s also tripped %s: %v", r.c, res.Case, res.Failures)
				}
			}
		})
	}
}

func TestWindowsDumpsUseWER(t *testing.T) {
	o := clean("windows")
	o.Dumps = &Dumps{} // Linux fields are meaningless on Windows
	if f := failures(t, o, CaseDumps); len(f) != 0 {
		t.Fatalf("%v", f)
	}
	o.Dumps.WERLocalDumps = true
	if f := failures(t, o, CaseDumps); len(f) != 1 || !strings.Contains(f[0], "LocalDumps") {
		t.Fatalf("%v", f)
	}
}

func TestUnobservedIsInactiveNotGreen(t *testing.T) {
	for _, r := range Evaluate(Observation{Profile: "linux-oci"}) {
		if r.Inactive == "" || len(r.Failures) > 0 {
			t.Errorf("%s: %+v", r.Case, r)
		}
	}
}

func TestGapRatchet(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "g.json")
	write := func(s string) {
		if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(`{"gaps":[{"case":"HOST-NO-DUMPS","profile":"linux-oci","ticket":"T-1","reason":"x"}]}`)
	gaps, err := LoadGaps(p, "linux-oci")
	if err != nil {
		t.Fatal(err)
	}
	broken := clean("linux-oci")
	broken.Dumps.CoreLimitZero = false
	for _, v := range Judge(Evaluate(broken), gaps) {
		if v.Fails() {
			t.Errorf("a tolerated gap failed the build: %s", v.Line())
		}
	}
	var stale bool
	for _, v := range Judge(Evaluate(clean("linux-oci")), gaps) {
		stale = stale || (v.Case == CaseDumps && v.Fails())
	}
	if !stale {
		t.Error("a known gap that now passes must fail the build")
	}
	// an untolerated failure still fails
	broken.Service = &Service{Account: "root"}
	failed := false
	for _, v := range Judge(Evaluate(broken), gaps) {
		failed = failed || (v.Case == CaseIdent && v.Fails())
	}
	if !failed {
		t.Error("a case without a gap entry must fail")
	}
	write(`{"gaps":[{"case":"NOPE","profile":"linux-oci","ticket":"T-1","reason":"x"}]}`)
	if _, err := LoadGaps(p, "linux-oci"); err == nil {
		t.Error("unknown case accepted")
	}
	write(`{"gaps":[{"case":"HOST-NO-DUMPS","profile":"linux-oci","reason":"x"}]}`)
	if _, err := LoadGaps(p, "linux-oci"); err == nil {
		t.Error("gap without a ticket accepted")
	}
}

// TestFindingsAreOneLinePerFailure: the pre-merge gate compares findings line by line (T-0973), so
// every untolerated failure is one `FAIL <case>: <failure>` line and a tolerated gap adds none.
func TestFindingsAreOneLinePerFailure(t *testing.T) {
	broken := clean("linux-oci")
	broken.Service = &Service{Account: "root"}
	var got []string
	for _, v := range Judge(Evaluate(broken), nil) {
		got = append(got, v.Findings()...)
	}
	if len(got) == 0 {
		t.Fatal("a root service produced no finding line")
	}
	for _, l := range got {
		if !strings.HasPrefix(l, "FAIL "+CaseIdent+": ") || strings.Contains(l, "\n") {
			t.Errorf("not a self-contained finding line: %q", l)
		}
	}
	gaps := map[string]Gap{CaseIdent: {Case: CaseIdent, Ticket: "T-1", Reason: "x"}}
	for _, v := range Judge(Evaluate(broken), gaps) {
		if v.Case == CaseIdent && len(v.Findings()) != 0 {
			t.Errorf("a tolerated gap produced findings: %v", v.Findings())
		}
	}
}

func TestPlaintextServes(t *testing.T) {
	for in, want := range map[string]bool{
		"":                             false, // connection closed or reset
		"\x15\x03\x01\x00\x02\x02\x0a": false, // TLS alert
		"HTTP/1.0 400 Bad Request\r\n\r\nClient sent an HTTP request to an HTTPS server.\n": false,
		"HTTP/1.1 200 OK\r\n":                            true,
		"HTTP/1.1 401 Unauthorized\r\n":                  true,
		"HTTP/1.1 400 Bad Request\r\n\r\nbad host":       true, // a plaintext server that merely disliked the request
		"HTTP/1.1 301 Moved\r\nLocation: https://x/\r\n": true, // a redirect listener is still a plaintext listener
	} {
		if got := PlaintextServes(in); got != want {
			t.Errorf("%q: got %v want %v", in, got, want)
		}
	}
}
