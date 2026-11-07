package authn

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

type fixedThreshold struct {
	n     int
	known bool
	err   error
}

func (f fixedThreshold) LockoutThreshold(context.Context, tenant.ID, string) (int, bool, error) {
	return f.n, f.known, f.err
}

var key1 = bytes.Repeat([]byte{7}, 32)

func (e *env) node(t *testing.T, th LockoutThresholds, window time.Duration) *ADAttempts {
	t.Helper()
	db, err := store.Open(context.Background(), store.Config{DSN: e.d.AppDSN()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	return &ADAttempts{DB: db, Thresholds: th, Window: window}
}

// Acceptance 1: threshold 5, four attempts reach the directory, the fifth is refused.
func TestCounterStopsBelowThreshold(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		c := e.node(t, fixedThreshold{n: 5, known: true}, 0)
		for i := 1; i <= 4; i++ {
			if err := c.Take(context.Background(), e.a, "corp", key1); err != nil {
				t.Fatalf("attempt %d refused: %v", i, err)
			}
		}
		for i := 5; i <= 7; i++ {
			if err := c.Take(context.Background(), e.a, "corp", key1); !errors.Is(err, ErrADAttemptsRefused) {
				t.Fatalf("attempt %d = %v; want refused", i, err)
			}
		}
		// Another account and another tenant have their own budget.
		if err := c.Take(context.Background(), e.a, "corp", bytes.Repeat([]byte{8}, 32)); err != nil {
			t.Errorf("a different account was refused: %v", err)
		}
		if err := c.Take(context.Background(), e.b, "corp", key1); err != nil {
			t.Errorf("the same key in another tenant was refused: %v", err)
		}
		// A success clears the count.
		if err := c.Succeeded(context.Background(), e.a, key1); err != nil {
			t.Fatal(err)
		}
		if err := c.Take(context.Background(), e.a, "corp", key1); err != nil {
			t.Errorf("attempt after success refused: %v", err)
		}
	})
}

// Acceptance 2: attempts split across two nodes (and run concurrently) are one budget.
func TestCounterSharedAcrossNodes(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		th := fixedThreshold{n: 5, known: true}
		nodes := []*ADAttempts{e.node(t, th, 0), e.node(t, th, 0)}
		var wg sync.WaitGroup
		var mu sync.Mutex
		admitted := 0
		for i := 0; i < 20; i++ {
			wg.Add(1)
			go func(c *ADAttempts) {
				defer wg.Done()
				if c.Take(context.Background(), e.a, "corp", key1) == nil {
					mu.Lock()
					admitted++
					mu.Unlock()
				}
			}(nodes[i%2])
		}
		wg.Wait()
		if admitted != 4 {
			t.Fatalf("%d attempts reached the directory across two nodes; want exactly 4", admitted)
		}
	})
}

// Acceptance 3: threshold unknown, 0 (or 1), or unreadable refuses; so does a bad key.
func TestCounterFailClosed(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		for name, th := range map[string]LockoutThresholds{
			"unknown":    fixedThreshold{n: 5, known: false},
			"zero":       fixedThreshold{n: 0, known: true},
			"one":        fixedThreshold{n: 1, known: true},
			"negative":   fixedThreshold{n: -1, known: true},
			"port error": fixedThreshold{n: 5, known: true, err: errors.New("dc down")},
			"nil port":   nil,
		} {
			c := e.node(t, th, 0)
			if err := c.Take(context.Background(), e.a, "corp", key1); !errors.Is(err, ErrADAttemptsRefused) {
				t.Errorf("%s: %v; want refused", name, err)
			}
		}
		c := e.node(t, fixedThreshold{n: 5, known: true}, 0)
		if err := c.Take(context.Background(), e.a, "corp", []byte("short")); !errors.Is(err, ErrADAttemptsRefused) {
			t.Errorf("short key: %v; want refused", err)
		}
		var nilc *ADAttempts
		if err := nilc.Take(context.Background(), e.a, "corp", key1); !errors.Is(err, ErrADAttemptsRefused) {
			t.Errorf("nil counter: %v; want refused", err)
		}
	})
}

// Acceptance 4: after the window the count restarts.
func TestCounterWindowReset(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		c := e.node(t, fixedThreshold{n: 3, known: true}, time.Second)
		for i := 1; i <= 2; i++ {
			if err := c.Take(context.Background(), e.a, "corp", key1); err != nil {
				t.Fatalf("attempt %d: %v", i, err)
			}
		}
		if err := c.Take(context.Background(), e.a, "corp", key1); !errors.Is(err, ErrADAttemptsRefused) {
			t.Fatalf("third attempt = %v; want refused", err)
		}
		time.Sleep(1200 * time.Millisecond)
		for i := 1; i <= 2; i++ {
			if err := c.Take(context.Background(), e.a, "corp", key1); err != nil {
				t.Fatalf("attempt %d after the window: %v", i, err)
			}
		}
		if err := c.Take(context.Background(), e.a, "corp", key1); !errors.Is(err, ErrADAttemptsRefused) {
			t.Fatalf("budget did not hold after reset: %v", err)
		}
	})
}
