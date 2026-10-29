package client

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/directory/connection"
	"github.com/skenzeriq/activediq/internal/directory/inventory"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

type liveReads struct {
	got   ObjectRead
	err   error
	calls int
	tid   string
}

func (f *liveReads) Object(ctx context.Context, _ authority.Pins, _ authority.TargetRef, _ string, need bool) (ObjectRead, error) {
	f.calls++
	f.tid, _ = authority.TenantFrom(ctx)
	if !need {
		return ObjectRead{}, errors.New("tier0 verdict not requested")
	}
	return f.got, f.err
}

type liveStore struct {
	err   error
	calls int
	tid   tenant.ID
	tier0 bool
	at    time.Time
}

func (s *liveStore) RecordLiveFacts(_ context.Context, tid tenant.ID, _ inventory.Ref, tier0 bool, at time.Time) error {
	s.calls++
	if s.err != nil {
		return s.err
	}
	s.tid, s.tier0, s.at = tid, tier0, at
	return nil
}

func liveSetup(t *testing.T, r *liveReads, s *liveStore) *InventoryRefresher {
	t.Helper()
	conns := fakeConns{adConn: {ID: adConn}}
	ref, err := NewInventoryRefresher(conns, r, s, func() time.Time { return t0Now })
	if err != nil {
		t.Fatal(err)
	}
	return ref
}

var liveRef = inventory.Ref{Connection: adConn, Object: groupObj}

func mustTenant(t *testing.T) tenant.ID {
	t.Helper()
	id, err := tenant.Parse(tenantID)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// Acceptance 1: facts are re-read live, stored, and the returned time is the read time.
func TestRefreshReadsStoresAndReturnsReadTime(t *testing.T) {
	r, s := &liveReads{got: ObjectRead{Exists: true, Tier0: true}}, &liveStore{}
	tid := mustTenant(t)
	at, err := liveSetup(t, r, s).RefreshCorrelations(context.Background(), tid, liveRef)
	if err != nil || !at.Equal(t0Now) {
		t.Fatalf("at=%v err=%v", at, err)
	}
	if s.calls != 1 || !s.at.Equal(t0Now) || !s.tier0 || s.tid != tid || r.tid != tenantID {
		t.Fatalf("store: %+v reads: %+v", s, r)
	}
}

// Acceptance 2: a failed read, a gone object or a failed store advance nothing.
func TestRefreshFailureStoresNothing(t *testing.T) {
	boom := errors.New("dc unreachable")
	for name, c := range map[string]struct {
		r    *liveReads
		s    *liveStore
		want error
	}{
		"read fails":   {&liveReads{err: boom}, &liveStore{}, boom},
		"object gone":  {&liveReads{got: ObjectRead{Exists: false}}, &liveStore{}, ErrRefreshGone},
		"store fails":  {&liveReads{got: ObjectRead{Exists: true}}, &liveStore{err: boom}, boom},
		"unknown base": {&liveReads{got: ObjectRead{Exists: true, Tier0: true}}, &liveStore{err: inventory.ErrBasisUnknown}, inventory.ErrBasisUnknown},
	} {
		t.Run(name, func(t *testing.T) {
			at, err := liveSetup(t, c.r, c.s).RefreshCorrelations(context.Background(), mustTenant(t), liveRef)
			if !errors.Is(err, c.want) || !at.IsZero() || !c.s.at.IsZero() {
				t.Fatalf("at=%v err=%v stored=%v", at, err, c.s.at)
			}
		})
	}
}

// Acceptance 3: a ref of another tenant's connection is refused before any directory is contacted.
func TestRefreshRefusesOtherTenantsRef(t *testing.T) {
	r, s := &liveReads{got: ObjectRead{Exists: true}}, &liveStore{}
	other := inventory.Ref{Connection: "6f1c2a40-0000-4000-8000-0000000000b9", Object: groupObj}
	_, err := liveSetup(t, r, s).RefreshCorrelations(context.Background(), mustTenant(t), other)
	if !errors.Is(err, ErrRefreshConnection) || r.calls != 0 || s.calls != 0 {
		t.Fatalf("err=%v reads=%d store=%d", err, r.calls, s.calls)
	}
	// A retired connection is not live either.
	now := t0Now
	conns := fakeConns{adConn: {ID: connection.ID(adConn), RetiredAt: &now}}
	ref, _ := NewInventoryRefresher(conns, r, s, nil)
	if _, err := ref.RefreshCorrelations(context.Background(), mustTenant(t), liveRef); !errors.Is(err, ErrRefreshConnection) || r.calls != 0 {
		t.Fatalf("retired: %v", err)
	}
	// Malformed input and a zero tenant are refused.
	if _, err := liveSetup(t, r, s).RefreshCorrelations(context.Background(), tenant.ID{}, liveRef); !errors.Is(err, ErrInvalidOp) {
		t.Fatalf("zero tenant: %v", err)
	}
}

// The refresher is the builder's optional port: a stale statement is fixed by it.
func TestRefresherSatisfiesPort(t *testing.T) {
	var _ LiveRefresher = (*InventoryRefresher)(nil)
}
