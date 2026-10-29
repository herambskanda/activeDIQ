package setup

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func fresh(t *testing.T, ttl time.Duration) (*Store, *clock) {
	t.Helper()
	c := &clock{t: time.Date(2026, 10, 29, 9, 0, 0, 0, time.UTC)}
	s, err := New(filepath.Join(t.TempDir(), DirName), ttl, WithClock(c.now))
	if err != nil {
		t.Fatal(err)
	}
	return s, c
}

func secretOf(t *testing.T, s *Store) string {
	t.Helper()
	b, err := os.ReadFile(s.SecretPath())
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(b))
}

func TestClaimOnceThenRefused(t *testing.T) {
	s, _ := fresh(t, time.Hour)
	if issued, _, err := s.Issue(); err != nil || !issued {
		t.Fatalf("issue: %v %v", issued, err)
	}
	sec := secretOf(t, s)
	if err := s.Claim(sec); err != nil {
		t.Fatalf("first use: %v", err)
	}
	if err := s.Claim(sec); !errors.Is(err, ErrRefused) {
		t.Fatalf("second use = %v, want ErrRefused", err)
	}
	if _, err := os.Stat(s.SecretPath()); !os.IsNotExist(err) {
		t.Fatalf("secret file survived the claim: %v", err)
	}
}

func TestTypedFormIsForgiving(t *testing.T) {
	s, _ := fresh(t, time.Hour)
	_, _, _ = s.Issue()
	typed := " " + strings.ToLower(secretOf(t, s)) + " "
	if err := s.Claim(typed); err != nil {
		t.Fatalf("lower case with spaces: %v", err)
	}
}

func TestWrongGuessDoesNotConsume(t *testing.T) {
	s, _ := fresh(t, time.Hour)
	_, _, _ = s.Issue()
	for _, bad := range []string{"", "AAAA-AAAA", strings.Repeat("A", 52)} {
		if err := s.Claim(bad); !errors.Is(err, ErrRefused) {
			t.Fatalf("Claim(%q) = %v", bad, err)
		}
	}
	if err := s.Claim(secretOf(t, s)); err != nil {
		t.Fatalf("the real secret after wrong guesses: %v", err)
	}
}

func TestExpiredIsRefusedAndReissuedOnRestart(t *testing.T) {
	s, c := fresh(t, time.Minute)
	_, _, _ = s.Issue()
	old := secretOf(t, s)
	c.t = c.t.Add(2 * time.Minute)
	if err := s.Claim(old); !errors.Is(err, ErrRefused) {
		t.Fatalf("expired secret = %v, want ErrRefused", err)
	}
	if issued, _, err := s.Issue(); err != nil || !issued {
		t.Fatalf("restart after expiry should issue: %v %v", issued, err)
	}
	if secretOf(t, s) == old {
		t.Fatal("the expired secret was reused")
	}
	if err := s.Claim(old); !errors.Is(err, ErrRefused) {
		t.Fatalf("the old secret works after reissue: %v", err)
	}
}

func TestRestartKeepsLiveSecret(t *testing.T) {
	s, _ := fresh(t, time.Hour)
	_, _, _ = s.Issue()
	sec := secretOf(t, s)
	if issued, _, err := s.Issue(); err != nil || issued {
		t.Fatalf("second Issue: %v %v", issued, err)
	}
	if secretOf(t, s) != sec {
		t.Fatal("a restart rotated a live secret")
	}
}

func TestClaimedInstallNeverReissues(t *testing.T) {
	s, _ := fresh(t, time.Hour)
	_, _, _ = s.Issue()
	if err := s.Claim(secretOf(t, s)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Issue(); !errors.Is(err, ErrAlreadyClaimed) {
		t.Fatalf("Issue after claim = %v", err)
	}
	if _, err := os.Stat(s.SecretPath()); !os.IsNotExist(err) {
		t.Fatal("a secret file exists on a claimed install")
	}
}

func TestNoIssueNoClaim(t *testing.T) {
	s, _ := fresh(t, time.Hour)
	if err := s.Claim("anything"); !errors.Is(err, ErrRefused) {
		t.Fatalf("claim on an install that never issued = %v", err)
	}
}

func TestConcurrentClaimsOneWinner(t *testing.T) {
	s, _ := fresh(t, time.Hour)
	_, _, _ = s.Issue()
	sec := secretOf(t, s)
	var wins atomic.Int32
	var wg sync.WaitGroup
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if s.Claim(sec) == nil {
				wins.Add(1)
			}
		}()
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("%d claims won, want exactly 1", wins.Load())
	}
}

func TestSecretFileIsPrivateAndHashOnlyInState(t *testing.T) {
	s, _ := fresh(t, time.Hour)
	_, _, _ = s.Issue()
	if runtimeUnix() {
		if fi, _ := os.Stat(s.SecretPath()); fi.Mode().Perm() != 0o600 {
			t.Fatalf("secret file mode %04o", fi.Mode().Perm())
		}
		if fi, _ := os.Stat(s.Dir()); fi.Mode().Perm() != 0o700 {
			t.Fatalf("setup dir mode %04o", fi.Mode().Perm())
		}
	}
	st, _ := os.ReadFile(filepath.Join(s.Dir(), StateFile))
	if strings.Contains(strings.ReplaceAll(string(st), "-", ""), normalise(secretOf(t, s))) {
		t.Fatal("the state file holds the secret, not its hash")
	}
}

func TestOpenDirRefused(t *testing.T) {
	if !runtimeUnix() {
		t.Skip("POSIX modes")
	}
	dir := filepath.Join(t.TempDir(), DirName)
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	s, _ := New(dir, time.Hour)
	if _, _, err := s.Issue(); err == nil {
		t.Fatal("a world-readable setup directory was accepted")
	}
}

func TestTTLMustBePositive(t *testing.T) {
	if _, err := New(t.TempDir(), 0); err == nil {
		t.Fatal("zero ttl accepted")
	}
}
