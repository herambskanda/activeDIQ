package server

import (
	"fmt"

	"github.com/skenzeriq/activediq/internal/compose/config"
	"github.com/skenzeriq/activediq/internal/platform/limiter"
	"github.com/skenzeriq/activediq/internal/platform/store"
)

// principalStore builds the store of per-principal rate budgets the configuration selects, and refuses a
// store that cannot hold one budget across the configured nodes (TM-TB2-T7). db may be nil only for the
// memory store.
func principalStore(cfg config.Config, db *store.DB) (limiter.PrincipalStore, error) {
	if err := cfg.ValidatePrincipalStore(); err != nil {
		return nil, fmt.Errorf("server: %w", err)
	}
	var ps limiter.PrincipalStore
	switch cfg.PrincipalStore {
	case config.PrincipalStoreMemory:
		ps = limiter.NewMemoryStore(nil)
	default:
		pg, err := limiter.NewPGStore(db)
		if err != nil {
			return nil, fmt.Errorf("server: %w", err)
		}
		ps = pg
	}
	if err := limiter.RequireShared(ps, cfg.Nodes); err != nil {
		return nil, fmt.Errorf("server: %w", err)
	}
	return ps, nil
}
