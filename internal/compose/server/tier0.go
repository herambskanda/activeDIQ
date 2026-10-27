package server

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/skenzeriq/activediq/internal/directory/client"
	"github.com/skenzeriq/activediq/internal/directory/connection"
	"github.com/skenzeriq/activediq/internal/directory/inventory"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// ErrNoTier0Tenant: a write reached the Tier0Context builder with no tenant on its context. The write
// is refused; a builder never guesses a tenant.
var ErrNoTier0Tenant = errors.New("server: tier0 context: no tenant on the request")

// tier0Sources are the tenant-independent sources of the per-tenant Tier0Builders. Every one except
// Refresh is required.
type tier0Sources struct {
	Connections  client.ConnectionSource
	Correlations client.CorrelationSource
	Designations client.Designations
	HybridLinks  client.HybridLinks
	Overrides    client.OverrideSource
	Revision     client.RevisionSource
	Refresh      client.LiveRefresher // optional
}

// tenantTier0 is the client.Tier0Builder of the server: it resolves the tenant from the request
// context and delegates to client.NewTier0Builder's builder for that tenant, built once and cached.
type tenantTier0 struct {
	src tier0Sources
	mu  sync.Mutex
	per map[tenant.ID]client.Tier0Builder
}

var _ client.Tier0Builder = (*tenantTier0)(nil)

// newTenantTier0 validates the sources and returns the builder. A missing required source fails here,
// at startup, rather than on the first write.
func newTenantTier0(s tier0Sources) (*tenantTier0, error) {
	// A probe with a throwaway tenant applies the client's own source check, so the two cannot drift.
	if _, err := client.NewTier0Builder(s.sources(tenant.New())); err != nil {
		return nil, fmt.Errorf("server: tier0 builder: %w", err)
	}
	return &tenantTier0{src: s, per: map[tenant.ID]client.Tier0Builder{}}, nil
}

func (s tier0Sources) sources(t tenant.ID) client.Tier0Sources {
	return client.Tier0Sources{
		Tenant: t, Connections: s.Connections, Correlations: s.Correlations, Designations: s.Designations,
		HybridLinks: s.HybridLinks, Overrides: s.Overrides, Revision: s.Revision, Refresh: s.Refresh,
	}
}

// Build implements client.Tier0Builder.
func (b *tenantTier0) Build(ctx context.Context, st client.Stage, op client.WriteOp) (client.Tier0, error) {
	txt, ok := authority.TenantFrom(ctx)
	if !ok {
		return client.Tier0{}, ErrNoTier0Tenant
	}
	tid, err := tenant.Parse(txt)
	if err != nil || tid.IsZero() {
		return client.Tier0{}, ErrNoTier0Tenant
	}
	inner, err := b.forTenant(tid)
	if err != nil {
		return client.Tier0{}, err
	}
	return inner.Build(ctx, st, op)
}

func (b *tenantTier0) forTenant(tid tenant.ID) (client.Tier0Builder, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if in, ok := b.per[tid]; ok {
		return in, nil
	}
	in, err := client.NewTier0Builder(b.src.sources(tid))
	if err != nil {
		return nil, err
	}
	b.per[tid] = in
	return in, nil
}

// buildTier0 wires the Tier0Builder from the stores: the inventory reader (correlations, designations,
// revision), the connection registry (connections, hybrid links, overrides) and, when reads are
// available, the live refresher. With nil reads there is no refresher, so a stale statement is not sent.
func buildTier0(db *store.DB, reads client.Reads) (*tenantTier0, error) {
	if db == nil {
		return nil, errors.New("server: tier0 builder needs the store")
	}
	conns := connection.NewRegistry(db)
	inv := inventory.NewReader(db, inventory.NewGroups(db))
	s := tier0Sources{
		Connections: conns, Correlations: inv, Designations: inv,
		HybridLinks: conns, Overrides: conns, Revision: inv,
	}
	if reads != nil {
		r, err := client.NewInventoryRefresher(conns, reads, inventory.NewFacts(db), nil)
		if err != nil {
			return nil, fmt.Errorf("server: live refresher: %w", err)
		}
		s.Refresh = r
	}
	return newTenantTier0(s)
}
