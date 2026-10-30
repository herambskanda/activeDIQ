package main

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestParseVerbRefusesAnyExtraArgument(t *testing.T) {
	for _, a := range [][]string{nil, {}, {"grant-channel", "x"}, {"prepare-datadir", "--data-dir", `C:\x`}, {"unknown"}, {""}, {"grant-channel", ""}} {
		if v, ok := parseVerb(a); ok {
			t.Errorf("parseVerb(%q) = %q, true; want refusal", a, v)
		}
	}
	for v := range verbs {
		if got, ok := parseVerb([]string{v}); !ok || got != v {
			t.Errorf("parseVerb(%q) refused", v)
		}
	}
}

func TestParseRepin(t *testing.T) {
	pin := "sha256:" + strings.Repeat("ab", 32)
	if got, ok := parseRepin([]string{"repin", pin}); !ok || got != pin {
		t.Fatalf("valid repin refused: %q %v", got, ok)
	}
	for _, a := range [][]string{nil, {"repin"}, {"repin", ""}, {"repin", "x"}, {"repin", pin, "extra"}, {"repin", strings.ToUpper(pin)}, {"repin", pin + "0"}, {"grant-channel", pin}, {"repin", `C:\x`}} {
		if _, ok := parseRepin(a); ok {
			t.Errorf("parseRepin(%q) accepted", a)
		}
	}
	if _, ok := parseVerb([]string{"repin"}); ok {
		t.Error("repin must not be a bare verb")
	}
}

func TestRepinReportsFailureOnce(t *testing.T) {
	var msgs []string
	code := repin(t.TempDir(), "sha256:"+strings.Repeat("ab", 32), func(m string, failed bool) {
		if !failed {
			t.Error("success reported")
		}
		msgs = append(msgs, m)
	})
	if code != 1 || len(msgs) != 1 {
		t.Fatalf("code = %d, audit = %q", code, msgs)
	}
}

func TestRepinRefusedWithoutAuditSink(t *testing.T) {
	dir := t.TempDir()
	code := runRepin(dir, "sha256:"+strings.Repeat("ab", 32), "alice on h", func() (auditSink, func(), error) {
		return nil, nil, errors.New("no log")
	})
	if code != 1 {
		t.Fatalf("code = %d", code)
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 0 {
		t.Fatalf("state touched: %v", ents)
	}
}

func TestRepinAuditNamesActor(t *testing.T) {
	var got string
	runRepin(t.TempDir(), "sha256:"+strings.Repeat("ab", 32), "CORP\\alice on h1", func() (auditSink, func(), error) {
		return func(m string, _ bool) { got = m }, func() {}, nil
	})
	if !strings.Contains(got, "CORP\\alice on h1") {
		t.Fatalf("actor missing: %q", got)
	}
}

// The audit source must be the one the MSI registers and the agent logs under.
func TestEventSourceMatchesMSI(t *testing.T) {
	wxs, err := os.ReadFile("../../packaging/windows/agent/Agent.wxs")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(wxs), `EventSource Log="Application" Name="`+agentEventSource+`"`) {
		t.Fatalf("Agent.wxs does not register source %q", agentEventSource)
	}
	ag, err := os.ReadFile("../agent/run_windows.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(ag), `OpenEventLog("`+agentEventSource+`")`) {
		t.Fatalf("agent logs under a different source than %q", agentEventSource)
	}
}

// Every Application-log write in agentsetup must use the shared agentEventSource constant, never a
// string literal (T-0751: warnRevokeFailed used "activeDIQAgent", an unregistered source).
func TestAgentsetupEventSourceIsSharedConstant(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	re := regexp.MustCompile(`eventlog\.(Open|InstallAsEventCreate|Install)\(\s*([^,)]*)`)
	n := 0
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range re.FindAllStringSubmatch(string(b), -1) {
			n++
			if m[1] != "Open" || strings.TrimSpace(m[2]) != "agentEventSource" {
				t.Errorf("%s: %s uses source %q; must be eventlog.Open(agentEventSource)", f, m[1], m[2])
			}
		}
	}
	if n == 0 {
		t.Fatal("no eventlog.Open call found; test is stale")
	}
}
