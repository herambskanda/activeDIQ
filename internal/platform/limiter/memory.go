package limiter

import (
	"context"
	"sync"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/apihost"
)

// MemoryStore is a PrincipalStore in one process's memory. It is exact for a single node; a
// multi-node install needs a store every node shares.
type MemoryStore struct {
	mu  sync.Mutex
	b   map[string]*bucket
	now func() time.Time
}

// NewMemoryStore returns an empty MemoryStore. now may be nil.
func NewMemoryStore(now func() time.Time) *MemoryStore {
	if now == nil {
		now = time.Now
	}
	return &MemoryStore{b: map[string]*bucket{}, now: now}
}

// Take implements PrincipalStore.
func (m *MemoryStore) Take(_ context.Context, key string, l Limit) (apihost.Decision, error) {
	now := m.now()
	m.mu.Lock()
	defer m.mu.Unlock()
	b, ok := m.b[key]
	if !ok {
		b = &bucket{tokens: float64(l.Burst), at: now}
		m.b[key] = b
	}
	refill(b, l, now)
	if b.tokens < 1 {
		return apihost.Decision{RetryAfter: retryAfter(b.tokens, l)}, nil
	}
	b.tokens--
	return apihost.Decision{Allowed: true}, nil
}
