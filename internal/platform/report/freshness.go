package report

import (
	"slices"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/authz"
)

// NCState is the state of a naming context's sync, as inventory reports it.
type NCState uint8

const (
	ncInvalid NCState = iota
	NCOK
	NCResyncRequired
	NCPaused
	NCNeverSynced
)

// NCWatermark is one naming context's last successful sync pass (not its last change, so a quiet
// domain is not "Stale").
type NCWatermark struct {
	Connection authz.ObjectID
	NC         authz.ObjectID
	LastPassAt time.Time
	State      NCState
}

// FreshnessState is the label of a result's currency. "Live" is never a state.
type FreshnessState uint8

const (
	freshnessInvalid FreshnessState = iota
	FreshnessSynced
	FreshnessStale
	FreshnessNotSyncedYet
)

func (s FreshnessState) String() string {
	switch s {
	case FreshnessSynced:
		return "synced"
	case FreshnessStale:
		return "stale"
	case FreshnessNotSyncedYet:
		return "not_synced_yet"
	}
	return "invalid"
}

// StaleNC names a naming context that makes a result stale, and why.
type StaleNC struct {
	Connection authz.ObjectID
	NC         authz.ObjectID
	Age        time.Duration // since its last pass
	State      NCState
}

// Freshness is the computed label.
type Freshness struct {
	State FreshnessState
	// AsOf is the oldest last pass among the covered NCs that have one; zero when none has.
	AsOf  time.Time
	Stale []StaleNC // oldest first
	// NotSynced lists the connections skipped because they have never completed a pass.
	NotSynced []authz.ObjectID
}

// Label computes the freshness label from the watermarks of the covered NCs (contract §6.4). It is
// pure: now is passed in.
//   - synced: every covered NC with a pass is ok and no older than threshold;
//   - stale: any covered NC is older than threshold, resync_required or paused;
//   - not_synced_yet: no covered NC has ever completed a pass.
//
// An NC that has never synced is listed in NotSynced and does not by itself make the rest stale.
func Label(ws []NCWatermark, threshold time.Duration, now time.Time) Freshness {
	var f Freshness
	synced := 0
	for _, w := range ws {
		if w.State == NCNeverSynced || w.LastPassAt.IsZero() {
			if !slices.Contains(f.NotSynced, w.Connection) {
				f.NotSynced = append(f.NotSynced, w.Connection)
			}
			continue
		}
		synced++
		if f.AsOf.IsZero() || w.LastPassAt.Before(f.AsOf) {
			f.AsOf = w.LastPassAt
		}
		age := now.Sub(w.LastPassAt)
		if w.State != NCOK || age > threshold {
			f.Stale = append(f.Stale, StaleNC{w.Connection, w.NC, age, w.State})
		}
	}
	slices.SortStableFunc(f.Stale, func(a, b StaleNC) int { return int(b.Age - a.Age) })
	switch {
	case synced == 0:
		f.State = FreshnessNotSyncedYet
	case len(f.Stale) > 0:
		f.State = FreshnessStale
	default:
		f.State = FreshnessSynced
	}
	return f
}
