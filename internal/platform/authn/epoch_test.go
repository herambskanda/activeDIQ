package authn

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

type resetFn func(s *Store, ctx context.Context, tx store.Tx, t tenant.ID, account string, by authority.Chain) (int, error)

var resets = map[string]resetFn{
	"password_reset": (*Store).OnPasswordReset,
	"mfa_reset":      (*Store).OnMFAReset,
	"role_change":    (*Store).OnRoleChanged,
}

func liveCount(t *testing.T, e *acctEnv, acct string) int {
	t.Helper()
	var n int
	err := e.db.WithTenant(context.Background(), e.ten, func(ctx context.Context, tx store.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM public.authn_sessions WHERE tenant_id = $1 AND account_id = $2::uuid AND state = 'active'`, e.ten.String(), acct).Scan(&n)
	})
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func runReset(e *acctEnv, f resetFn, acct string) error {
	return e.db.WithTenant(context.Background(), e.ten, func(ctx context.Context, tx store.Tx) error {
		_, err := f(e.ss, ctx, tx, e.ten, acct, human)
		return err
	})
}

func activeAcct(t *testing.T, e *acctEnv, name string) Account {
	t.Helper()
	a := newSSO(t, e, name)
	if _, err := e.a.SetState(context.Background(), e.ten, a.ID, AccountActive, human); err != nil {
		t.Fatal(err)
	}
	return a
}

// T-0429: a sign-in that captured the epoch (verified the old credential/MFA/roles) before the change
// committed cannot mint a session afterwards.
func TestCreateRefusedAfterResetCommitted(t *testing.T) {
	eachAcct(t, func(t *testing.T, e *acctEnv) {
		for name, f := range resets {
			a := activeAcct(t, e, "after-"+name)
			captured := epochOf(t, e.ss, e.ten, a.ID) // the sign-in verified the old credential here
			if err := runReset(e, f, a.ID); err != nil {
				t.Fatal(err)
			}
			_, err := e.ss.Create(context.Background(), CreateInput{Tenant: e.ten, Account: a.ID, Methods: []string{"password"}, Epoch: captured})
			if !errors.Is(err, ErrCredentialsChanged) {
				t.Errorf("%s: Create = %v, want ErrCredentialsChanged", name, err)
			}
			if n := liveCount(t, e, a.ID); n != 0 {
				t.Errorf("%s: %d live sessions", name, n)
			}
			// A sign-in that captures the new epoch works.
			if _, err := e.ss.Create(context.Background(), CreateInput{Tenant: e.ten, Account: a.ID, Methods: []string{"password"}, Epoch: epochOf(t, e.ss, e.ten, a.ID)}); err != nil {
				t.Errorf("%s: fresh sign-in: %v", name, err)
			}
		}
	})
}

func TestCreateRequiresEpoch(t *testing.T) {
	eachAcct(t, func(t *testing.T, e *acctEnv) {
		a := activeAcct(t, e, "noepoch")
		if _, err := e.ss.Create(context.Background(), CreateInput{Tenant: e.ten, Account: a.ID, Methods: []string{"password"}}); !errors.Is(err, ErrInvalid) {
			t.Errorf("Create without epoch = %v, want ErrInvalid", err)
		}
	})
}

// T-0429 race, barrier form: the sign-in holds its transaction open after INSERT; the reset has to wait
// for it on the account row and then revokes the new session. Both commit: no active session remains.
func TestCreateSerialisedAgainstResets(t *testing.T) {
	eachAcct(t, func(t *testing.T, e *acctEnv) {
		ctx := context.Background()
		for name, f := range resets {
			for round := 0; round < 3; round++ {
				a := activeAcct(t, e, fmt.Sprintf("race-%s-%d", name, round))
				captured := epochOf(t, e.ss, e.ten, a.ID)
				inserted, release := make(chan struct{}), make(chan struct{})
				var wg sync.WaitGroup
				var signErr, resetErr error
				wg.Add(1)
				go func() {
					defer wg.Done()
					signErr = e.db.WithTenant(ctx, e.ten, func(ctx context.Context, tx store.Tx) error {
						if _, err := e.ss.CreateTx(ctx, tx, CreateInput{Tenant: e.ten, Account: a.ID, Methods: []string{"password"}, Epoch: captured}); err != nil {
							return err
						}
						close(inserted)
						<-release
						return nil
					})
				}()
				select {
				case <-inserted:
				case <-time.After(10 * time.Second):
					t.Fatal("sign-in never reached the barrier")
				}
				wg.Add(1)
				go func() {
					defer wg.Done()
					resetErr = runReset(e, f, a.ID)
				}()
				time.Sleep(300 * time.Millisecond) // the reset is blocked on the sign-in's row lock
				close(release)
				wg.Wait()
				if signErr != nil || resetErr != nil {
					t.Fatalf("%s: sign-in: %v, reset: %v", name, signErr, resetErr)
				}
				if n := liveCount(t, e, a.ID); n != 0 {
					t.Fatalf("%s round %d: %d live sessions after sign-in and reset", name, round, n)
				}
			}
		}
	})
}

// The reverse interleaving, with real concurrency and no barrier: whichever order they commit in, no
// session minted from the old epoch survives.
func TestCreateVersusResetUnordered(t *testing.T) {
	eachAcct(t, func(t *testing.T, e *acctEnv) {
		for name, f := range resets {
			for round := 0; round < 10; round++ {
				a := activeAcct(t, e, fmt.Sprintf("free-%s-%d", name, round))
				captured := epochOf(t, e.ss, e.ten, a.ID)
				var wg sync.WaitGroup
				var signErr, resetErr error
				wg.Add(2)
				go func() {
					defer wg.Done()
					_, signErr = e.ss.Create(context.Background(), CreateInput{Tenant: e.ten, Account: a.ID, Methods: []string{"password"}, Epoch: captured})
				}()
				go func() { defer wg.Done(); resetErr = runReset(e, f, a.ID) }()
				wg.Wait()
				if resetErr != nil || (signErr != nil && !errors.Is(signErr, ErrCredentialsChanged)) {
					t.Fatalf("%s: sign-in: %v, reset: %v", name, signErr, resetErr)
				}
				if n := liveCount(t, e, a.ID); n != 0 {
					t.Fatalf("%s round %d: %d live sessions", name, round, n)
				}
			}
		}
	})
}

// A pending sign-in (AN-10) whose first factor predates a reset cannot become a session.
func TestPendingSignInDiesWithReset(t *testing.T) {
	eachPending(t, func(t *testing.T, e *pendEnv) {
		ctx := context.Background()
		h := e.begin(t) // first factor verified, epoch captured
		if err := e.db.WithTenant(ctx, e.ten, func(ctx context.Context, tx store.Tx) error {
			_, err := e.sess.OnPasswordReset(ctx, tx, e.ten, e.account, human)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		_, err := e.sf.VerifyTOTP(ctx, h, e.good())
		if !errors.Is(err, ErrPendingInvalid) {
			t.Fatalf("VerifyTOTP after reset = %v, want ErrPendingInvalid", err)
		}
	})
}

// Rotate while a reset commits: the account ends with no live session.
func TestRotateVersusReset(t *testing.T) {
	eachAcct(t, func(t *testing.T, e *acctEnv) {
		for name, f := range resets {
			a := activeAcct(t, e, "rot-"+name)
			r, err := e.ss.Create(context.Background(), CreateInput{Tenant: e.ten, Account: a.ID, Methods: []string{"password"}, Epoch: epochOf(t, e.ss, e.ten, a.ID)})
			if err != nil {
				t.Fatal(err)
			}
			if err := runReset(e, f, a.ID); err != nil {
				t.Fatal(err)
			}
			if _, err := e.ss.Rotate(context.Background(), r.Token, ReasonOnDemand); err == nil {
				t.Errorf("%s: Rotate of a session ended by a reset succeeded", name)
			}
			if n := liveCount(t, e, a.ID); n != 0 {
				t.Errorf("%s: %d live sessions", name, n)
			}
		}
	})
}
