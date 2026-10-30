package updateverify

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// Floor is the rollback and freeze memory of one install (spec section 3, rules 2 and 3): the highest
// metadata versions seen, the newest signing time verified and the highest committed product version.
// Every field only ever rises.
type Floor struct {
	Root, Timestamp, Snapshot, Targets uint64
	// NewestSigning is the newest "issued" time of any metadata verified; a clock earlier than it is refused.
	NewestSigning time.Time
	// Committed is the highest product version committed by the apply mechanism ("" = none yet).
	Committed string
}

// FloorStore is the persistence port. Raise stores the field-wise maximum of the stored floor and f
// (it never lowers anything). Load and Raise errors fail verification closed.
type FloorStore interface {
	Load(ctx context.Context) (Floor, error)
	Raise(ctx context.Context, f Floor) error
}

// Max is the field-wise maximum of a and b.
func Max(a, b Floor) (Floor, error) {
	out := a
	out.Root = max(a.Root, b.Root)
	out.Timestamp = max(a.Timestamp, b.Timestamp)
	out.Snapshot = max(a.Snapshot, b.Snapshot)
	out.Targets = max(a.Targets, b.Targets)
	if b.NewestSigning.After(a.NewestSigning) {
		out.NewestSigning = b.NewestSigning
	}
	switch {
	case a.Committed == "":
		out.Committed = b.Committed
	case b.Committed == "":
	default:
		c, err := compareVersions(a.Committed, b.Committed)
		if err != nil {
			return Floor{}, err
		}
		if c < 0 {
			out.Committed = b.Committed
		}
	}
	return out, nil
}

// Dual keeps the floor in two independent halves, the database and the host (spec rule 2: "so a
// database restore cannot rewind it"). Load returns the maximum of both and heals the lower half; Raise
// writes both. If either half cannot be read or written, the call fails and verification stops.
type Dual struct{ Database, Host FloorStore }

func (d Dual) Load(ctx context.Context) (Floor, error) {
	if d.Database == nil || d.Host == nil {
		return Floor{}, errors.New("updateverify: both floor halves are required")
	}
	db, err := d.Database.Load(ctx)
	if err != nil {
		return Floor{}, fmt.Errorf("updateverify: database floor: %w", err)
	}
	host, err := d.Host.Load(ctx)
	if err != nil {
		return Floor{}, fmt.Errorf("updateverify: host floor: %w", err)
	}
	m, err := Max(db, host)
	if err != nil {
		return Floor{}, err
	}
	if err := d.Raise(ctx, m); err != nil { // heal a restored database half
		return Floor{}, err
	}
	return m, nil
}

func (d Dual) Raise(ctx context.Context, f Floor) error {
	if d.Database == nil || d.Host == nil {
		return errors.New("updateverify: both floor halves are required")
	}
	if err := d.Host.Raise(ctx, f); err != nil {
		return fmt.Errorf("updateverify: host floor: %w", err)
	}
	if err := d.Database.Raise(ctx, f); err != nil {
		return fmt.Errorf("updateverify: database floor: %w", err)
	}
	return nil
}

// MemoryFloor is an in-process FloorStore for tests and for composing under Dual in tests.
type MemoryFloor struct{ F Floor }

func (m *MemoryFloor) Load(context.Context) (Floor, error) { return m.F, nil }

func (m *MemoryFloor) Raise(_ context.Context, f Floor) error {
	n, err := Max(m.F, f)
	if err != nil {
		return err
	}
	m.F = n
	return nil
}
