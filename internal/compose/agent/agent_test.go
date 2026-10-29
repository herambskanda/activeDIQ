package agent_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/compose/agent"
	"github.com/skenzeriq/activediq/internal/compose/config"
)

func TestRunWithoutConfigRefuses(t *testing.T) {
	t.Setenv(agent.ConfigEnv, "")
	if err := agent.Run(context.Background(), config.Config{}); !errors.Is(err, agent.ErrNoConfig) {
		t.Fatalf("Run = %v", err)
	}
}

func TestRunNotEnrolledIsDistinct(t *testing.T) {
	d := t.TempDir()
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
	d := t.TempDir()
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
	d := t.TempDir()
	cfg := filepath.Join(d, "agent.json")
	body := `{"data_dir":"` + filepath.ToSlash(filepath.Join(d, "data")) + `","enrollment_dir":"` + filepath.ToSlash(filepath.Join(d, "enrol")) + `"}`
	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(agent.ConfigEnv, cfg)
	ctx, cancel := context.WithCancel(context.Background())
	waits := 0
	done := make(chan error, 1)
	go func() {
		done <- agent.RunServing(ctx, config.Config{}, agent.Hooks{}, 5*time.Millisecond, func() { waits++ })
	}()
	time.Sleep(60 * time.Millisecond)
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
