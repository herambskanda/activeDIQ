package limiter

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/skenzeriq/activediq/internal/platform/apihost"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tablekind"
)

// bucketsTable declares public.platform_rate_buckets (DM-07) for fitness-domain-keys. It is a
// registered-global table (ADR-0002 rule 6), so its kind is Platform.
var bucketsTable = tablekind.Declare(tablekind.Table{
	Name:   "public.platform_rate_buckets",
	Entity: "DM-07",
	Kind:   tablekind.Platform,
})

// PGStore is the PrincipalStore every server node shares: the buckets live in PostgreSQL, so a
// principal's budget is one budget however many nodes serve it (ADR-0002 rule 6, TM-TB2-T7).
type PGStore struct {
	db *store.DB
}

// NewPGStore returns a PGStore over db.
func NewPGStore(db *store.DB) (*PGStore, error) {
	if db == nil {
		return nil, errors.New("limiter: PGStore needs a database")
	}
	return &PGStore{db: db}, nil
}

var _ PrincipalStore = (*PGStore)(nil)

// Shared reports that every node sees this store's buckets (see RequireShared).
func (*PGStore) Shared() bool { return true }

// take refills and takes in one statement, on the database clock. The clock is clock_timestamp(), read
// after the row lock is won, never now(): now() is the transaction start, so a waiter queued on the row
// would carry an earlier time than the holder it waited for and write it back, crediting the same
// interval twice. greatest(b.refilled_at, ...) keeps the stored time from ever going backwards. Each
// read can differ by microseconds; that only under-credits refill, never over-credits. The upsert locks the conflicting row,
// so concurrent takes on one key run one after the other and each sees the previous one's tokens; no
// read-then-write window exists. A refused take still stores the refilled level, which is what makes the
// next refill start from now. admitted is read back from the row this statement wrote.
const take = `INSERT INTO public.platform_rate_buckets AS b (key, tokens, admitted, refilled_at)
VALUES ($1, $3::float8 - 1, true, clock_timestamp())
ON CONFLICT (key) DO UPDATE SET
  tokens = least($3::float8, b.tokens + greatest(0, extract(epoch FROM greatest(b.refilled_at, clock_timestamp()) - b.refilled_at)) * $2::float8 / 60.0)
    - CASE WHEN least($3::float8, b.tokens + greatest(0, extract(epoch FROM greatest(b.refilled_at, clock_timestamp()) - b.refilled_at)) * $2::float8 / 60.0) >= 1 THEN 1 ELSE 0 END,
  admitted = least($3::float8, b.tokens + greatest(0, extract(epoch FROM greatest(b.refilled_at, clock_timestamp()) - b.refilled_at)) * $2::float8 / 60.0) >= 1,
  refilled_at = greatest(b.refilled_at, clock_timestamp())
RETURNING b.tokens, b.admitted`

// Take implements PrincipalStore. Any database error is returned, never turned into an admission.
func (s *PGStore) Take(ctx context.Context, key string, l Limit) (apihost.Decision, error) {
	if l.Rate <= 0 || l.Burst <= 0 {
		return apihost.Decision{}, fmt.Errorf("limiter: invalid limit rate=%d burst=%d", l.Rate, l.Burst)
	}
	sum := sha256.Sum256([]byte(key))
	var tokens float64
	var admitted bool
	err := s.db.WithPlatform(ctx, "limiter: take a principal rate token", func(ctx context.Context, tx store.Tx) error {
		return tx.QueryRow(ctx, take, hex.EncodeToString(sum[:]), l.Rate, l.Burst).Scan(&tokens, &admitted)
	})
	if err != nil {
		return apihost.Decision{}, fmt.Errorf("limiter: take: %w", err)
	}
	if admitted {
		return apihost.Decision{Allowed: true}, nil
	}
	return apihost.Decision{RetryAfter: retryAfter(tokens, l)}, nil
}
