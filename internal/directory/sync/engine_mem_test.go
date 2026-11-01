package sync_test

import (
	"context"
	"fmt"
	"runtime"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/directory/connection"
	"github.com/skenzeriq/activediq/internal/directory/inventory"
	dsync "github.com/skenzeriq/activediq/internal/directory/sync"
	"github.com/skenzeriq/activediq/internal/platform/jobs"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// Ports for the memory test: the engine over a generated domain, no database. Memory is a property of the
// read loop, not of Postgres, so the database stays out and the numbers are the engine's own.

type memTenants struct{}

func (memTenants) WithTenant(ctx context.Context, _ tenant.ID, fn func(context.Context, store.Tx) error) error {
	return fn(ctx, nil)
}

type memConns struct{ c connection.Connection }

func (m memConns) Get(context.Context, tenant.ID, connection.ID) (connection.Connection, error) {
	return m.c, nil
}

type memCursors struct{}

func (memCursors) Claim(_ context.Context, _ store.Tx, k dsync.Key, _ jobs.Lease) (dsync.Cursor, error) {
	return dsync.Cursor{Key: k, State: dsync.StateInitialSync}, nil
}

func (memCursors) CompleteScan(_ context.Context, _ store.Tx, k dsync.Key, _ jobs.Lease, at time.Time) (dsync.Cursor, error) {
	return dsync.Cursor{Key: k, State: dsync.StateIncremental, LastFullSync: at}, nil
}

type countingIngest struct {
	batches, objects, biggest, lastMore int
	passes                              int
}

func (c *countingIngest) Ingest(_ context.Context, _ store.Tx, cy inventory.Cycle) (inventory.Ingested, error) {
	c.batches++
	c.objects += len(cy.Observations)
	c.biggest = max(c.biggest, len(cy.Observations))
	if !cy.MoreBatches {
		c.passes += len(cy.PassNCs)
	}
	return inventory.Ingested{}, nil
}

// flatDomain generates n objects in stream order, children before parents: n-2 users under one OU, then the
// OU, then the domain head. Nothing is held: at(i) builds the node when asked.
func flatDomain(nc uint64, n int) *fdom {
	ou := nc + 1
	head := fmt.Sprintf("DC=d%d,DC=test", nc)
	return &fdom{nc: nc, count: n, sid: 1, at: func(i int) fnode {
		switch {
		case i == n-1:
			return fnode{n: nc, class: []string{"top", "domain", "domainDNS"}, dn: head}
		case i == n-2:
			return fnode{n: ou, parent: nc, class: []string{"top", "organizationalUnit"}, dn: "OU=Users," + head}
		}
		return fnode{n: nc + 100 + uint64(i), parent: ou, class: []string{"top", "person", "organizationalPerson", "user"},
			sam: fmt.Sprintf("u%d", i), rid: uint32(1000 + i), pgid: domUsers, dn: fmt.Sprintf("CN=u%d,OU=Users,%s", i, head)}
	}}
}

// heapGrowth reads a domain of n objects and returns the peak heap growth over the baseline, sampled after a
// collection every few batches, and what the ingester saw.
func heapGrowth(t *testing.T, n int) (peak uint64, ing *countingIngest) {
	t.Helper()
	f := newFake(flatDomain(ncA, n))
	ing = &countingIngest{}
	var base uint64
	sample := func() {
		var m runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&m)
		if m.HeapAlloc > base {
			peak = max(peak, m.HeapAlloc-base)
		}
	}
	batches := 0
	f.onBatch = func() {
		if batches++; batches%10 == 0 {
			sample()
		}
	}
	eng := &dsync.Engine{Tenants: memTenants{}, Domains: &managedDomains{list: domainsOf(ncA)}, Source: &connSource{cc: f},
		Ingester: ing, Cursors: memCursors{},
		Conns: memConns{connection.Connection{ID: "00000000-0000-4000-8000-0000000000c1", Kind: connection.KindADForest,
			State: connection.StateActive, DirectoryIdentity: connection.DirectoryIdentity(forestRoot)}}}
	lease := func(_ context.Context, name string) (jobs.Lease, error) { return jobs.Lease{Name: name, Holder: "mem", Token: 1}, nil }
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	base = m.HeapAlloc
	rep, err := eng.FullCycle(context.Background(), tenant.New(), "00000000-0000-4000-8000-0000000000c1", lease)
	if err != nil {
		t.Fatalf("FullCycle(%d objects): %v", n, err)
	}
	if len(rep.Domains) != 1 || rep.Domains[0].Mapped != n || !rep.Domains[0].Completed {
		t.Fatalf("report = %+v, want %d objects", rep.Domains, n)
	}
	return peak, ing
}

// TestFullCycleMemoryIsBounded is the second half of acceptance 6: a 100,000-object domain is read without
// holding it. The only per-object state is the pre-scan's parent link (two GUIDs); a whole-domain slice of
// observations would cost well over 100 MB.
func TestFullCycleMemoryIsBounded(t *testing.T) {
	const budget = 16 << 20
	var peaks []uint64
	for _, n := range []int{10_000, 100_000} {
		peak, ing := heapGrowth(t, n)
		peaks = append(peaks, peak)
		t.Logf("%7d objects: peak heap growth %.1f MiB, %d batches, largest %d, %d pass", n, float64(peak)/(1<<20), ing.batches, ing.biggest, ing.passes)
		if ing.objects != n {
			t.Fatalf("ingested %d objects, want %d", ing.objects, n)
		}
		if ing.biggest > inventory.IngestBatchSize {
			t.Fatalf("a batch of %d objects, the bound is %d", ing.biggest, inventory.IngestBatchSize)
		}
		if ing.passes != 1 {
			t.Fatalf("%d passes recorded, want exactly one on the last batch", ing.passes)
		}
	}
	if peaks[1] > budget {
		t.Fatalf("peak heap growth at 100k objects = %.1f MiB, over the %d MiB budget", float64(peaks[1])/(1<<20), budget>>20)
	}
}
