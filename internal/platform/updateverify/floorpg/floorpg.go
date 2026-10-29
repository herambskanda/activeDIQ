// Package floorpg is the database half of the update verifier's rollback floor: a updateverify.FloorStore
// over one install-level PostgreSQL row. It lives beside, not inside, updateverify so that package stays
// standard-library only. Compose it with the host half: updateverify.Dual{Database: store, Host: file}.
package floorpg

import (
	"context"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tablekind"
	"github.com/skenzeriq/activediq/internal/platform/updateverify"
)

// floorTable declares public.update_verifier_floor for fitness-domain-keys. It is a registered global
// table (ADR-0002 rule 4): the verifier is install-level and runs outside any tenant, so its kind is
// Platform. It stores the DM-05 Release family's trust state.
var floorTable = tablekind.Declare(tablekind.Table{
	Name:   "public.update_verifier_floor",
	Entity: "DM-05",
	Kind:   tablekind.Platform,
})

// Store is the database FloorStore.
type Store struct{ db *store.DB }

// NewStore returns a Store over db.
func NewStore(db *store.DB) (*Store, error) {
	if db == nil {
		return nil, errors.New("floorpg: a database is required")
	}
	return &Store{db: db}, nil
}

var _ updateverify.FloorStore = (*Store)(nil)

const load = `SELECT root_version, timestamp_version, snapshot_version, targets_version, newest_signing, committed
FROM public.update_verifier_floor WHERE singleton`

// raise raises every numeric field with GREATEST (GREATEST ignores NULL, so a first newest_signing is
// stored and an absent one changes nothing). The upsert takes the row lock that the committed-version
// step below relies on. A zero Floor field is a no-op, never a lowering.
const raise = `INSERT INTO public.update_verifier_floor AS f
  (singleton, root_version, timestamp_version, snapshot_version, targets_version, newest_signing)
VALUES (true, $1, $2, $3, $4, $5)
ON CONFLICT (singleton) DO UPDATE SET
  root_version = GREATEST(f.root_version, EXCLUDED.root_version),
  timestamp_version = GREATEST(f.timestamp_version, EXCLUDED.timestamp_version),
  snapshot_version = GREATEST(f.snapshot_version, EXCLUDED.snapshot_version),
  targets_version = GREATEST(f.targets_version, EXCLUDED.targets_version),
  newest_signing = GREATEST(f.newest_signing, EXCLUDED.newest_signing)
RETURNING f.committed`

const setCommitted = `UPDATE public.update_verifier_floor SET committed = $1 WHERE singleton`

// Load returns the stored floor; an install that has verified nothing has the zero Floor.
func (s *Store) Load(ctx context.Context) (updateverify.Floor, error) {
	var out updateverify.Floor
	err := s.db.WithPlatform(ctx, "floorpg: load the update verifier floor", func(ctx context.Context, tx store.Tx) error {
		var r, ts, sn, tg int64
		var signed *time.Time
		err := tx.QueryRow(ctx, load).Scan(&r, &ts, &sn, &tg, &signed, &out.Committed)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		out.Root, out.Timestamp, out.Snapshot, out.Targets = uint64(r), uint64(ts), uint64(sn), uint64(tg)
		if signed != nil {
			out.NewestSigning = signed.UTC()
		}
		return nil
	})
	if err != nil {
		return updateverify.Floor{}, fmt.Errorf("floorpg: load: %w", err)
	}
	return out, nil
}

// Raise stores the field-wise maximum of the stored floor and f in one transaction. It never lowers a
// field. A version above the database's range, or a committed version that is not a product version, is
// refused before any SQL runs. The newest signing time is kept to microseconds, the column's precision.
func (s *Store) Raise(ctx context.Context, f updateverify.Floor) error {
	for _, v := range []uint64{f.Root, f.Timestamp, f.Snapshot, f.Targets} {
		if v > math.MaxInt64 {
			return fmt.Errorf("floorpg: metadata version %d is out of range", v)
		}
	}
	if f.Committed != "" { // Max skips validation against an empty side, so compare against version "0"
		if _, err := updateverify.Max(updateverify.Floor{Committed: "0"}, updateverify.Floor{Committed: f.Committed}); err != nil {
			return fmt.Errorf("floorpg: %w", err)
		}
	}
	var signed *time.Time
	if !f.NewestSigning.IsZero() {
		t := f.NewestSigning.UTC().Truncate(time.Microsecond)
		signed = &t
	}
	err := s.db.WithPlatform(ctx, "floorpg: raise the update verifier floor", func(ctx context.Context, tx store.Tx) error {
		var cur string
		if err := tx.QueryRow(ctx, raise, int64(f.Root), int64(f.Timestamp), int64(f.Snapshot), int64(f.Targets), signed).Scan(&cur); err != nil {
			return err
		}
		if f.Committed == "" {
			return nil
		}
		next, err := updateverify.Max(updateverify.Floor{Committed: cur}, updateverify.Floor{Committed: f.Committed})
		if err != nil {
			return err // the stored value is not a version: fail closed, do not overwrite
		}
		if next.Committed == cur {
			return nil
		}
		_, err = tx.Exec(ctx, setCommitted, next.Committed)
		return err
	})
	if err != nil {
		return fmt.Errorf("floorpg: raise: %w", err)
	}
	return nil
}
