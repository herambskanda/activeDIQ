package agent_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/compose/agent"
	"github.com/skenzeriq/activediq/internal/compose/config"
	"github.com/skenzeriq/activediq/internal/platform/fleet/dial"
)

func TestRunWithoutConfigRefuses(t *testing.T) {
	t.Setenv(agent.ConfigEnv, "")
	if err := agent.Run(context.Background(), config.Config{}); !errors.Is(err, agent.ErrNoConfig) {
		t.Fatalf("Run = %v", err)
	}
}

func TestRunNotEnrolledIsDistinct(t *testing.T) {
	d := privateTemp(t)
	cfg := filepath.Join(d, "agent.json")
	enr := filepath.Join(d, "enrol")
	body := `{"data_dir":"` + filepath.ToSlash(filepath.Join(d, "data")) + `","enrollment_dir":"` + filepath.ToSlash(enr) + `"}`
	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(agent.ConfigEnv, cfg)
	if err := agent.Run(context.Background(), config.Config{}); !errors.Is(err, agent.ErrNotEnrolled) {
		t.Fatalf("Run = %v", err)
	}
}

func TestPrivilegeCheckRunsBeforeAnythingElse(t *testing.T) {
	d := privateTemp(t)
	cfg := filepath.Join(d, "agent.json")
	_ = os.WriteFile(cfg, []byte(`{"data_dir":"`+filepath.ToSlash(d)+`","enrollment_dir":"`+filepath.ToSlash(d)+`"}`), 0o600)
	t.Setenv(agent.ConfigEnv, cfg)
	err := agent.RunWith(context.Background(), config.Config{}, agent.Hooks{
		HeldPrivileges: func() ([]string, error) { return []string{"SeChangeNotifyPrivilege", "SeDebugPrivilege"}, nil }})
	if !errors.Is(err, agent.ErrPrivileges) || !strings.Contains(err.Error(), "SeDebugPrivilege") {
		t.Fatalf("got %v", err)
	}
}

func TestParseLocalStrict(t *testing.T) {
	good := `{"data_dir":"/d","enrollment_dir":"/e"}`
	if _, err := agent.ParseLocal([]byte(good)); err != nil && !strings.Contains(err.Error(), "absolute") {
		t.Fatal(err)
	}
	for name, doc := range map[string]string{
		"unknown key": `{"data_dir":"/d","enrollment_dir":"/e","extra":1}`,
		"trailing":    good + ` {}`,
		"relative":    `{"data_dir":"d","enrollment_dir":"e"}`,
		"tiny outbox": `{"data_dir":"/d","enrollment_dir":"/e","outbox_max_bytes":10}`,
		"empty":       ``,
	} {
		if _, err := agent.ParseLocal([]byte(doc)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestRunServingIdlesWhenNotEnrolled(t *testing.T) {
	d := privateTemp(t)
	cfg := filepath.Join(d, "agent.json")
	body := `{"data_dir":"` + filepath.ToSlash(filepath.Join(d, "data")) + `","enrollment_dir":"` + filepath.ToSlash(filepath.Join(d, "enrol")) + `"}`
	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(agent.ConfigEnv, cfg)
	ctx, cancel := context.WithCancel(context.Background())
	waits := 0
	checks := make(chan struct{}, 8)
	hk := agent.Hooks{NotEnrolledCheck: func() { checks <- struct{}{} }}
	done := make(chan error, 1)
	go func() {
		done <- agent.RunServing(ctx, config.Config{}, hk, time.Millisecond, func() { waits++ })
	}()
	// Wait for the first check and at least one re-check: the service must still be running.
	<-checks
	<-checks
	select {
	case err := <-done:
		t.Fatalf("exited while unenrolled: %v", err)
	default:
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("stop = %v", err)
	}
	if waits != 1 {
		t.Fatalf("waiting announced %d times, want once", waits)
	}
}

func TestRunServingStillFailsOnOtherErrors(t *testing.T) {
	t.Setenv(agent.ConfigEnv, "")
	if err := agent.RunServing(context.Background(), config.Config{}, agent.Hooks{}, time.Millisecond, nil); !errors.Is(err, agent.ErrNoConfig) {
		t.Fatalf("got %v", err)
	}
}

// T-1249: enrolment state that exists but cannot be used is not "not enrolled".
func unusableCfg(t *testing.T) (enrolDir string) {
	t.Helper()
	d := privateTemp(t)
	enrolDir = filepath.Join(d, "enrol")
	if err := os.MkdirAll(enrolDir, 0o777); err != nil { // wider than the component accepts
		t.Fatal(err)
	}
	if err := os.Chmod(enrolDir, 0o777); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(d, "agent.json")
	body := `{"data_dir":"` + filepath.ToSlash(filepath.Join(d, "data")) + `","enrollment_dir":"` + filepath.ToSlash(enrolDir) + `"}`
	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(agent.ConfigEnv, cfg)
	return enrolDir
}

func TestRunWithUnusableStateIsNotNotEnrolled(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix permission bits; Windows is covered by the dial tests and the lab run")
	}
	unusableCfg(t)
	err := agent.RunWith(context.Background(), config.Config{}, agent.Hooks{})
	var se *agent.StateError
	if errors.Is(err, agent.ErrNotEnrolled) || !errors.Is(err, agent.ErrStateUnusable) || !errors.As(err, &se) || se.Class != agent.StateUnsafe {
		t.Fatalf("RunWith = %v, want a StateError of class %s that is not ErrNotEnrolled", err, agent.StateUnsafe)
	}
}

func TestRunServingReportsUnusableStateOncePerClassAndKeepsRunning(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix permission bits")
	}
	dir := unusableCfg(t)
	ctx, cancel := context.WithCancel(context.Background())
	checks := make(chan struct{}, 16)
	var got []*agent.StateError
	waits := 0
	hk := agent.Hooks{
		StateUnusable:      func(e *agent.StateError) { got = append(got, e) },
		StateUnusableCheck: func() { checks <- struct{}{} },
		NotEnrolledCheck:   func() { t.Error("reported as not enrolled") },
	}
	done := make(chan error, 1)
	go func() {
		done <- agent.RunServing(ctx, config.Config{}, hk, time.Millisecond, func() { waits++ })
	}()
	<-checks
	<-checks
	<-checks
	select {
	case err := <-done:
		t.Fatalf("the service exited on unusable state: %v", err)
	default:
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("stop = %v", err)
	}
	if len(got) != 1 || got[0].Class != agent.StateUnsafe {
		t.Fatalf("StateUnusable calls = %v, want exactly one of class %s", got, agent.StateUnsafe)
	}
	if waits != 0 {
		t.Fatalf("the 'waiting for enrolment' announcement fired %d times for unusable state", waits)
	}
	_ = dir
}

// T-1249: while `enroll` is still writing (some files there, the leaf not yet), the service looks
// again after EnrollingInterval, not after the whole interval, so a pickup is not a poll late.
func TestRunServingRechecksSoonWhileEnrolmentIsBeingWritten(t *testing.T) {
	d := privateTemp(t)
	enrol := filepath.Join(d, "enrol")
	if err := os.MkdirAll(enrol, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(enrol, dial.CAFile), []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(d, "agent.json")
	body := `{"data_dir":"` + filepath.ToSlash(filepath.Join(d, "data")) + `","enrollment_dir":"` + filepath.ToSlash(enrol) + `"}`
	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(agent.ConfigEnv, cfg)
	ctx, cancel := context.WithCancel(context.Background())
	checks := make(chan struct{}, 8)
	hk := agent.Hooks{NotEnrolledCheck: func() { checks <- struct{}{} }}
	done := make(chan error, 1)
	go func() { done <- agent.RunServing(ctx, config.Config{}, hk, time.Hour, nil) }()
	for i := 0; i < 2; i++ {
		select {
		case <-checks:
		case <-time.After(agent.EnrollingInterval + 5*time.Second):
			cancel()
			t.Fatal("no re-check within the enrolling interval: a one-hour interval was used")
		}
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

// privateTemp is t.TempDir() made 0700: the enrolment directory's parent must not be writable by
// group or others (T-1315), and a 002 umask would make it so.
func privateTemp(t *testing.T) string {
	t.Helper()
	d := t.TempDir()
	if err := os.Chmod(d, 0o700); err != nil {
		t.Fatal(err)
	}
	return d
}
