package sync

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/skenzeriq/activediq/internal/directory/inventory"
	"github.com/skenzeriq/activediq/internal/platform/store"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// PatchWriter is the inventory's patch write side (inventory.Ingester).
type PatchWriter interface {
	ApplyPatches(ctx context.Context, tx store.Tx, c inventory.PatchCycle) (inventory.Patched, error)
}

// Applier applies change-feed batches to inventory (contract §6.4). It is the apply step only: it does no I/O of
// its own and takes the caller's tenant transaction, so the batch's rows and the cursor commit together (DM-19.I1).
type Applier struct {
	Mapper *ChangeMapper
	Writer PatchWriter
}

// ApplyOptions describe the batch being applied.
type ApplyOptions struct {
	Connection inventory.ConnectionID
	// Observed is the cycle's as-of; Now the time the gate is judged at.
	Observed, Now time.Time
	ObservedDSA   string
	// MoreBatches and PassNCs are as in inventory.Cycle.
	MoreBatches bool
	PassNCs     []inventory.GUID
}

// ApplyReport is what applying one batch did. It carries counts and GUIDs, never a value from the directory.
type ApplyReport struct {
	Changes int
	// Refused counts changes that could not be mapped (a malformed value) or applied; the rest of the batch is
	// applied. A refused change that named an object is not lost: the object is in NeedsRead.
	Refused                 int
	Updated, Created, Stale int
	// NeedsRead lists the objects the engine must read by GUID (a ScopedSearch) and ingest in full: those the
	// inventory has never seen whose change did not carry enough to build a row (nothing was stored for them), and
	// those whose change was refused or whose membership change named a member without a GUID. A stored group
	// among the latter has its member edges ended until that read lands, so it grants nothing in the meantime.
	NeedsRead []inventory.GUID
	// MembersUnresolved counts member values named without a GUID.
	MembersUnresolved int
	// EdgesRemoved counts edges ended because an end of them is deleted, recycled or purged.
	EdgesRemoved int
	// Rounds is how many writes the batch took (more than one only when it named an object twice).
	Rounds int
	inventory.Ingested
}

// Apply maps every change of the batch and writes them in the caller's transaction. The order of the changes
// carries no meaning (a child before its parent, a delete before a create) and the result does not depend on
// it; applying the same batch again changes nothing. A change that cannot be mapped is counted and skipped. An
// object named twice is applied in the order given, one round per occurrence, because the second change is a
// patch of the first's result.
func (a *Applier) Apply(ctx context.Context, tx store.Tx, b *connectorv1.ChangeBatch, o ApplyOptions) (ApplyReport, error) {
	var rep ApplyReport
	if a == nil || a.Mapper == nil || a.Writer == nil || b == nil {
		return rep, fmt.Errorf("%w: applier", ErrNotConfigured)
	}
	var rounds [][]inventory.Patch
	occurrence := map[inventory.GUID]int{}
	for _, ch := range b.GetChanges() {
		rep.Changes++
		p, err := a.Mapper.Plan(ch)
		if err != nil {
			if !errors.Is(err, ErrMalformed) {
				return rep, err
			}
			if p.Patch.Object == "" {
				rep.Refused++ // no GUID to read by: a bare count
				continue
			}
			// The change is consumed with the cookie. The object it named is read, and a stored group stops
			// granting until then, so a removal it carried cannot be lost.
			p.Patch = inventory.Patch{Object: p.Patch.Object, NC: p.Patch.NC, Refused: true}
		} else {
			rep.MembersUnresolved += p.MembersUnresolved
		}
		n := occurrence[p.Patch.Object]
		occurrence[p.Patch.Object] = n + 1
		if n == len(rounds) {
			rounds = append(rounds, nil)
		}
		rounds[n] = append(rounds[n], p.Patch)
	}
	if len(rounds) == 0 {
		rounds = [][]inventory.Patch{nil} // the pass records and the gate still run on the last batch
	}
	for i, patches := range rounds {
		last := i == len(rounds)-1
		for len(patches) > 0 || last {
			chunk := patches
			if len(chunk) > inventory.IngestBatchSize {
				chunk = chunk[:inventory.IngestBatchSize]
			}
			patches = patches[len(chunk):]
			final := last && len(patches) == 0
			res, err := a.Writer.ApplyPatches(ctx, tx, inventory.PatchCycle{
				Connection: o.Connection, Observed: o.Observed, ObservedDSA: o.ObservedDSA, Patches: chunk, Now: o.Now,
				MoreBatches: o.MoreBatches || !final, PassNCs: o.PassNCs,
			})
			rep.Rounds++
			rep.Updated += res.Updated
			rep.Created += res.Created
			rep.Stale += res.Stale
			rep.Refused += res.Refused
			rep.EdgesRemoved += res.EdgesRemoved
			rep.NeedsRead = append(rep.NeedsRead, res.NeedsRead...)
			rep.Ingested = res.Ingested
			if err != nil {
				return rep, err
			}
			if final {
				break
			}
		}
	}
	slices.Sort(rep.NeedsRead) // an object named in two rounds is listed once
	rep.NeedsRead = slices.Compact(rep.NeedsRead)
	return rep, nil
}
