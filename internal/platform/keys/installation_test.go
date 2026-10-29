package keys_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/keys"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
)

type recAuditor struct {
	mu  sync.Mutex
	evs []keys.InstallationEvent
	err error
	// onCreate, when set, runs (once) before a create event is recorded: the creating tx is open, uncommitted.
	onCreate func()
}

func (a *recAuditor) RecordInstallationKey(_ context.Context, ev keys.InstallationEvent) error {
	if ev.Action == keys.ActionCreate && a.onCreate != nil {
		f := a.onCreate
		a.onCreate = nil
		f()
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.evs = append(a.evs, ev)
	return a.err
}

func (a *recAuditor) count(action, outcome string) (n int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, e := range a.evs {
		if e.Action == action && e.Outcome == outcome {
			n++
		}
	}
	return
}

func (r *rig) instDEK(ik *keys.InstallationKeys, v uint32) (keys.DEK, error) {
	var d keys.DEK
	err := r.db.WithPlatform(context.Background(), "test: installation dek", func(ctx context.Context, tx store.Tx) (err error) {
		d, err = ik.DEK(ctx, tx, v, "test.consumer")
		return
	})
	return d, err
}

func (r *rig) activeCount() (n int) {
	r.t.Helper()
	out, err := r.d.OwnerStrings(context.Background(), `SELECT count(*)::text FROM public.installation_keys WHERE state = 'active'`)
	if err != nil || len(out) != 1 {
		r.t.Fatal(err, out)
	}
	_, _ = fmt.Sscan(out[0], &n)
	return n
}

func TestInstallationDEKCreatedOnFirstUseAndAudited(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		r := setup(t, s)
		aud := &recAuditor{}
		ik, err := keys.NewInstallationKeys(r.kms, aud)
		if err != nil {
			t.Fatal(err)
		}
		if r.activeCount() != 0 {
			t.Fatal("key exists before first use")
		}
		d, err := r.instDEK(ik, 0)
		if err != nil || d.Version != 1 {
			t.Fatalf("first use: v=%d err=%v", d.Version, err)
		}
		defer d.Destroy()
		if r.activeCount() != 1 {
			t.Fatal("want exactly one active key")
		}
		// Seal round trip, and the stored blob is not the DEK.
		c := keys.InstallationContext{Table: "public.fleet_server_ca", Row: "r1", Column: "sealed_key", Version: 1}
		blob, err := keys.SealInstallation(d, c, []byte("ca key"))
		if err != nil {
			t.Fatal(err)
		}
		d2, err := r.instDEK(ik, 1)
		if err != nil {
			t.Fatal(err)
		}
		defer d2.Destroy()
		if pt, err := keys.OpenInstallation(d2, c, blob); err != nil || !bytes.Equal(pt, []byte("ca key")) {
			t.Fatalf("round trip: %q %v", pt, err)
		}
		if aud.count(keys.ActionCreate, keys.UnsealOK) != 1 || aud.count(keys.ActionUnseal, keys.UnsealOK) != 2 {
			t.Fatalf("audit events: %+v", aud.evs)
		}
	})
}

func TestInstallationDEKConcurrentCreationYieldsOneActiveKey(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		r := setup(t, s)
		ik, _ := keys.NewInstallationKeys(r.kms, &recAuditor{})
		const n = 8
		var wg sync.WaitGroup
		versions := make([]uint32, n)
		errs := make([]error, n)
		wg.Add(n)
		for i := 0; i < n; i++ {
			go func() {
				defer wg.Done()
				d, err := r.instDEK(ik, 0)
				versions[i], errs[i] = d.Version, err
				d.Destroy()
			}()
		}
		wg.Wait()
		for i := range errs {
			if errs[i] != nil || versions[i] != 1 {
				t.Fatalf("caller %d: v=%d err=%v", i, versions[i], errs[i])
			}
		}
		if got := r.activeCount(); got != 1 {
			t.Fatalf("active keys = %d, want 1", got)
		}
	})
}

func TestInstallationDEKKEKDownFailsClosedNothingCached(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		r := setup(t, s)
		aud := &recAuditor{}
		ik, _ := keys.NewInstallationKeys(r.kms, aud)
		d, err := r.instDEK(ik, 0)
		if err != nil {
			t.Fatal(err)
		}
		d.Destroy()
		before := r.kms.Unwraps
		r.kms.SetDown(true)
		got, err := r.instDEK(ik, 0)
		if keys.Code(err) != keys.ProviderUnavailable || got.Version != 0 {
			t.Fatalf("KEK down: v=%d err=%v; want typed ProviderUnavailable and no key", got.Version, err)
		}
		if aud.count(keys.ActionUnseal, keys.UnsealFailed) != 1 {
			t.Fatalf("failed unseal not audited: %+v", aud.evs)
		}
		r.kms.SetDown(false)
		d, err = r.instDEK(ik, 0)
		if err != nil {
			t.Fatal(err)
		}
		d.Destroy()
		// Every access went to the provider: the second success was a fresh unwrap, not a cache hit.
		if r.kms.Unwraps != before+1 {
			t.Fatalf("unwraps %d -> %d; want exactly one more (no cache)", before, r.kms.Unwraps)
		}
	})
}

func TestInstallationDEKUnauditableUnsealIsWithheld(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		r := setup(t, s)
		ik, _ := keys.NewInstallationKeys(r.kms, &recAuditor{err: errors.New("audit sink down")})
		d, err := r.instDEK(ik, 0)
		if keys.Code(err) != keys.AuditFailed || d.Version != 0 {
			t.Fatalf("v=%d err=%v; want AuditFailed and no key", d.Version, err)
		}
	})
}

func TestInstallationDEKRefusesTenantWrapAndUnknownVersion(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		r := setup(t, s)
		ik, _ := keys.NewInstallationKeys(r.kms, &recAuditor{})
		if _, err := r.instDEK(ik, 7); keys.Code(err) != keys.KeyNotFound {
			t.Fatalf("unknown version: %v", err)
		}
		if _, err := keys.NewInstallationKeys(nil, &recAuditor{}); keys.Code(err) != keys.InvalidContext {
			t.Fatalf("nil provider: %v", err)
		}
		if _, err := keys.NewInstallationKeys(r.kms, nil); keys.Code(err) != keys.InvalidContext {
			t.Fatalf("nil auditor: %v", err)
		}
		// A tenant's wrapped DEK planted as the installation row does not unwrap.
		if err := r.provision(r.a); err != nil {
			t.Fatal(err)
		}
		d, _ := keys.NewDEK(1)
		w, ref, _ := keys.WrapDEK(r.kms, r.a, d)
		if err := r.d.ExecOwner(context.Background(), `INSERT INTO public.installation_keys (version, state, wrapped_dek, kek_provider, kek_key_id) VALUES (1,'active',$1,$2,$3)`, w, ref.Provider, ref.KeyID); err != nil {
			t.Fatal(err)
		}
		if got, err := r.instDEK(ik, 0); keys.Code(err) != keys.UnwrapFailed || got.Version != 0 {
			t.Fatalf("tenant wrap as installation key: v=%d err=%v", got.Version, err)
		}
	})
}

// pgAuditor writes each event to a real table through the owner connection: its own commit, as the
// production adapter must do.
type pgAuditor struct{ r *rig }

func (a pgAuditor) RecordInstallationKey(ctx context.Context, ev keys.InstallationEvent) error {
	return a.r.d.ExecOwner(ctx, `INSERT INTO test_installation_audit (action, outcome, code) VALUES ($1,$2,$3)`,
		ev.Action, ev.Outcome, ev.Code)
}

func (r *rig) auditRows(action, outcome string) (n int) {
	r.t.Helper()
	out, err := r.d.OwnerStrings(context.Background(), fmt.Sprintf(
		`SELECT count(*)::text FROM test_installation_audit WHERE action = '%s' AND outcome = '%s'`, action, outcome))
	if err != nil || len(out) != 1 {
		r.t.Fatal(err, out)
	}
	_, _ = fmt.Sscan(out[0], &n)
	return n
}

var errRollback = errors.New("caller rolls back")

// rolledBack runs a DEK call and then fails the transaction, as every caller does on an error path.
func (r *rig) rolledBack(ik *keys.InstallationKeys, v uint32) error {
	return r.db.WithPlatform(context.Background(), "test: installation dek", func(ctx context.Context, tx store.Tx) error {
		d, _ := ik.DEK(ctx, tx, v, "test.consumer")
		d.Destroy()
		return errRollback
	})
}

func TestInstallationAuditSurvivesCallerRollback(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		r := setup(t, s)
		if err := r.d.ExecOwner(context.Background(), `CREATE TABLE test_installation_audit (action text, outcome text, code text)`); err != nil {
			t.Fatal(err)
		}
		ik, _ := keys.NewInstallationKeys(r.kms, pgAuditor{r})
		// Seed an active key (committed), then exercise three rolled-back calls.
		d, err := r.instDEK(ik, 0)
		if err != nil {
			t.Fatal(err)
		}
		d.Destroy()
		base := r.auditRows(keys.ActionUnseal, keys.UnsealOK)

		// (c) a successful unseal whose caller rolls back.
		if err := r.rolledBack(ik, 0); !errors.Is(err, errRollback) {
			t.Fatal(err)
		}
		if got := r.auditRows(keys.ActionUnseal, keys.UnsealOK); got != base+1 {
			t.Fatalf("success record lost on rollback: %d -> %d", base, got)
		}
		// (a) KEK down.
		r.kms.SetDown(true)
		_ = r.rolledBack(ik, 0)
		r.kms.SetDown(false)
		if got := r.auditRows(keys.ActionUnseal, keys.UnsealFailed); got != 1 {
			t.Fatalf("KEK-down failure record lost on rollback: %d", got)
		}
		// (b) a planted tenant-wrapped row => UnwrapFailed.
		if err := r.provision(r.a); err != nil {
			t.Fatal(err)
		}
		td, _ := keys.NewDEK(1)
		w, ref, _ := keys.WrapDEK(r.kms, r.a, td)
		if err := r.d.ExecOwner(context.Background(), `UPDATE public.installation_keys SET wrapped_dek=$1, kek_provider=$2, kek_key_id=$3 WHERE state='active'`, w, ref.Provider, ref.KeyID); err != nil {
			t.Skipf("runtime fixture cannot tamper installation_keys: %v", err)
		}
		_ = r.rolledBack(ik, 0)
		if got := r.auditRows(keys.ActionUnseal, keys.UnsealFailed); got != 2 {
			t.Fatalf("UnwrapFailed record lost on rollback: %d", got)
		}
	})
}

func TestInstallationAuditFailureKeepsPrimaryError(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		r := setup(t, s)
		aud := &recAuditor{}
		ik, _ := keys.NewInstallationKeys(r.kms, aud)
		d, err := r.instDEK(ik, 0)
		if err != nil {
			t.Fatal(err)
		}
		d.Destroy()
		sink := errors.New("audit sink down")
		aud.err = sink
		r.kms.SetDown(true)
		_, err = r.instDEK(ik, 0)
		if keys.Code(err) != keys.ProviderUnavailable || !errors.Is(err, sink) {
			t.Fatalf("want ProviderUnavailable with the audit error visible, got %v", err)
		}
	})
}

func TestInstallationRacingCreatorsRecordExactlyOneCreate(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		r := setup(t, s)
		aud := &recAuditor{}
		ik, _ := keys.NewInstallationKeys(r.kms, aud)
		reached, release := make(chan struct{}), make(chan struct{})
		// A has INSERTed but not committed when its create is about to be recorded.
		defer func() {
			select {
			case <-release:
			default:
				close(release)
			}
		}()
		aud.onCreate = func() { close(reached); <-release }
		aDone := make(chan error, 1)
		go func() { d, err := r.instDEK(ik, 0); d.Destroy(); aDone <- err }()
		<-reached
		bDone := make(chan error, 1)
		go func() { d, err := r.instDEK(ik, 0); d.Destroy(); bDone <- err }()
		// B must queue behind A's uncommitted INSERT (unique index). pg_stat_activity is not visible to the
		// owner role in every lab, so give B time to reach the INSERT, and fail if it finishes before A commits.
		select {
		case err := <-bDone:
			t.Fatalf("B finished while A's creating transaction was open: %v", err)
		case <-time.After(750 * time.Millisecond):
		}
		close(release)
		if err := <-aDone; err != nil {
			t.Fatal(err)
		}
		if err := <-bDone; err != nil {
			t.Fatal(err)
		}
		if got := aud.count(keys.ActionCreate, keys.UnsealOK); got != 1 {
			t.Fatalf("create events = %d, want 1 (events %+v)", got, aud.evs)
		}
		if r.activeCount() != 1 {
			t.Fatal("want one active key")
		}
	})
}
