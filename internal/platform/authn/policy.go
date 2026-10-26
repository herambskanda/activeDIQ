package authn

import (
	"errors"
	"fmt"
	"time"
)

// EvictionPolicy chooses which session goes when a new one would exceed the concurrent limit.
type EvictionPolicy string

const (
	// EvictOldestCreated revokes the session created first. It is the default.
	EvictOldestCreated EvictionPolicy = "oldest_created"
	// EvictLeastRecentlyUsed revokes the session idle the longest.
	EvictLeastRecentlyUsed EvictionPolicy = "least_recently_used"
)

// Policy is a tenant's session policy (ADM-145). Idle and Absolute are tenant-configurable only
// within Bounds.
type Policy struct {
	Idle          time.Duration
	Absolute      time.Duration
	MaxConcurrent int // sessions an account may hold at once
	Eviction      EvictionPolicy
}

// Bounds are the platform limits a tenant's Policy must stay within. A zero MaxConcurrentCeiling is
// not allowed: an unlimited session count is not offered.
type Bounds struct {
	IdleMin, IdleMax         time.Duration
	AbsoluteMin, AbsoluteMax time.Duration
	MaxConcurrentCeiling     int
}

// DefaultBounds are the platform bounds: idle 5 minutes to 8 hours, absolute 15 minutes to 24 hours,
// at most 20 concurrent sessions per account.
var DefaultBounds = Bounds{
	IdleMin: 5 * time.Minute, IdleMax: 8 * time.Hour,
	AbsoluteMin: 15 * time.Minute, AbsoluteMax: 24 * time.Hour,
	MaxConcurrentCeiling: 20,
}

// DefaultPolicy is used for a tenant that has configured nothing: idle 30 minutes, absolute 8 hours,
// 3 concurrent sessions, oldest created evicted.
var DefaultPolicy = Policy{Idle: 30 * time.Minute, Absolute: 8 * time.Hour, MaxConcurrent: 3, Eviction: EvictOldestCreated}

// ErrPolicy is returned when a Policy is outside the Bounds or malformed. Nothing is clamped: a
// session is never created under a policy the operator did not set.
var ErrPolicy = errors.New("authn: session policy outside the platform bounds")

// Validate reports why p is not acceptable within b, wrapping ErrPolicy.
func (p Policy) Validate(b Bounds) error {
	switch {
	case p.Idle < b.IdleMin || p.Idle > b.IdleMax:
		return fmt.Errorf("%w: idle timeout must be between %s and %s", ErrPolicy, b.IdleMin, b.IdleMax)
	case p.Absolute < b.AbsoluteMin || p.Absolute > b.AbsoluteMax:
		return fmt.Errorf("%w: absolute timeout must be between %s and %s", ErrPolicy, b.AbsoluteMin, b.AbsoluteMax)
	case p.Idle > p.Absolute:
		return fmt.Errorf("%w: idle timeout exceeds the absolute timeout", ErrPolicy)
	case p.MaxConcurrent < 1 || p.MaxConcurrent > b.MaxConcurrentCeiling:
		return fmt.Errorf("%w: concurrent sessions must be between 1 and %d", ErrPolicy, b.MaxConcurrentCeiling)
	case p.Eviction != EvictOldestCreated && p.Eviction != EvictLeastRecentlyUsed:
		return fmt.Errorf("%w: unknown eviction policy", ErrPolicy)
	}
	return nil
}
