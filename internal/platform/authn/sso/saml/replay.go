package saml

import (
	"context"
	"sync"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// ReplayCache is the SAML-16 replay store (DM-39.I5). Remember records (tenant, IdP, assertion ID) until
// the given time and reports whether it was new. A duplicate is not an error: it is the replay. The
// PostgreSQL implementation, which every node shares and which is written in the transaction that
// consumes the sign-in Transaction (SSO-1), belongs to the callback handler (T-0203).
type ReplayCache interface {
	Remember(ctx context.Context, t tenant.ID, idpID, assertionID string, until time.Time) (fresh bool, err error)
}

// MemoryReplayCache is a process-local ReplayCache. It is correct for one node and is what tests use; two
// nodes need the shared implementation.
type MemoryReplayCache struct {
	mu   sync.Mutex
	seen map[string]time.Time
	now  func() time.Time
}

// NewMemoryReplayCache returns an empty cache that expires entries by now.
func NewMemoryReplayCache(now func() time.Time) *MemoryReplayCache {
	if now == nil {
		now = time.Now
	}
	return &MemoryReplayCache{seen: map[string]time.Time{}, now: now}
}

// Remember implements ReplayCache.
func (m *MemoryReplayCache) Remember(_ context.Context, t tenant.ID, idpID, assertionID string, until time.Time) (bool, error) {
	key := t.String() + "\x00" + idpID + "\x00" + assertionID
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	for k, exp := range m.seen {
		if !exp.After(now) {
			delete(m.seen, k)
		}
	}
	if _, dup := m.seen[key]; dup {
		return false, nil
	}
	m.seen[key] = until
	return true, nil
}
