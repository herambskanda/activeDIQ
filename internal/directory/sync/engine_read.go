package sync

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/skenzeriq/activediq/internal/directory/client"
	"github.com/skenzeriq/activediq/internal/directory/connection"
	"github.com/skenzeriq/activediq/internal/directory/inventory"
	"github.com/skenzeriq/activediq/internal/platform/jobs"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// readJob is the full read of one domain NC.
type readJob struct {
	e        *Engine
	tid      tenant.ID
	conn     connection.ID
	ref      *connectorv1.ConnectionRef
	cc       client.Connector
	key      Key
	lease    jobs.Lease
	nc       inventory.GUID
	pageSize uint32
	rep      *DomainReport

	// observed is the as-of of the read: the start of the main pass.
	observed time.Time
}

// prescan is what the first pass learns about a domain: the parent link of every object and the groups' SIDs.
type prescan struct {
	// parent maps an object (the 16 bytes of its GUID text) to its parent; the head maps to the zero key.
	parent map[[16]byte][16]byte
	groups *GroupIndex
	// pin is the DC the pre-scan was served by; the main pass is pinned to it, so the two passes agree.
	pin *connectorv1.Guid
}

func (r *readJob) run(ctx context.Context) error {
	r.rep.RefusedBy = map[RefusalKey]int{}
	pre, err := r.prescan(ctx)
	if err != nil {
		return &DomainError{NC: r.nc, Phase: "prescan", Err: err}
	}
	// The pre-scan can take minutes: the connection may have been suspended or removed, or the partition
	// paused, since the read began. A stop is not a domain failure, it ends the cycle.
	if err := r.stillAllowed(ctx); err != nil {
		return err
	}
	mp, err := NewMapper(Config{NC: r.nc, Groups: pre.groups})
	if err != nil {
		return err
	}
	r.observed = r.e.utc()
	dsa := ""
	if v := pre.pin.GetValue(); len(v) == 16 {
		dsa = textOf(v)
	}

	buf := make([]inventory.Observation, 0, inventory.IngestBatchSize)
	err = func() error {
		_, err := r.stream(ctx, searchSpec{attrs: mp.Attributes(), pageSize: r.pageSize, pin: pre.pin}, func(en *connectorv1.DirectoryEntry) error {
			r.rep.Entries++
			o, ok, err := r.mapEntry(mp, pre, en, dsa)
			if err != nil {
				return err
			}
			if !ok {
				return nil
			}
			buf = append(buf, o)
			if len(buf) < inventory.IngestBatchSize {
				return nil
			}
			// More may follow: this batch is not the last. If the stream then ends exactly here, the last
			// batch is an empty one that carries the pass and the cursor.
			if err := r.flush(ctx, buf, false); err != nil {
				return err
			}
			clear(buf)
			buf = buf[:0]
			return nil
		})
		return err
	}()
	if err != nil {
		return r.wrap(err, "read")
	}
	if err := r.flush(ctx, buf, true); err != nil {
		return err
	}
	r.rep.Completed = true
	return nil
}

func (r *readJob) wrap(err error, phase string) error {
	var de *DomainError
	if errors.As(err, &de) || errors.Is(err, ErrFenced) || errors.Is(err, ErrPaused) || errors.Is(err, ErrRefused) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	return &DomainError{NC: r.nc, Phase: phase, Err: err}
}

// prescan streams the domain asking only for objectClass and objectSid.
func (r *readJob) prescan(ctx context.Context) (*prescan, error) {
	pre := &prescan{parent: map[[16]byte][16]byte{}, groups: NewGroupIndex()}
	done, err := r.stream(ctx, searchSpec{attrs: []string{"objectClass", "objectSid"}, pageSize: r.pageSize}, func(en *connectorv1.DirectoryEntry) error {
		self := en.GetObjectGuid().GetValue()
		if len(self) != 16 {
			return nil // the main pass refuses it; it can have no children we could place
		}
		var k, p [16]byte
		copy(k[:], self)
		if pv := en.GetParentGuid().GetValue(); len(pv) == 16 {
			copy(p[:], pv)
		}
		pre.parent[k] = p
		if sid := groupSID(en); sid != nil {
			pre.groups.Add(sid, inventory.GUID(textOf(self)))
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	pre.pin = done.GetDc().GetDsaGuid()
	return pre, nil
}

// groupSID is the binary SID of a group entry, nil for any other entry.
func groupSID(en *connectorv1.DirectoryEntry) []byte {
	var sid []byte
	group := false
	for _, a := range en.GetAttributes() {
		switch strings.ToLower(a.GetName()) {
		case "objectclass":
			for _, v := range a.GetValues() {
				if strings.EqualFold(v.GetText(), "group") {
					group = true
				}
			}
		case "objectsid":
			if vs := a.GetValues(); len(vs) == 1 {
				sid = vs[0].GetSid().GetValue()
			}
		}
	}
	if !group || len(sid) == 0 {
		return nil
	}
	return sid
}

// mapEntry maps one entry of the main pass. ok is false for an entry that was refused as malformed (counted,
// and skipped without aborting the batch). Any other error aborts the read.
func (r *readJob) mapEntry(mp *Mapper, pre *prescan, en *connectorv1.DirectoryEntry, dsa string) (inventory.Observation, bool, error) {
	m, err := mp.Map(en)
	if err != nil {
		var me *Error
		if !errors.As(err, &me) {
			return inventory.Observation{}, false, err
		}
		r.rep.Refused++
		r.rep.RefusedBy[RefusalKey{Attr: me.Attr, Code: me.Code}]++
		return inventory.Observation{}, false, nil
	}
	o := m.Observation
	o.ObservedDSA = dsa
	r.rep.Mapped++
	if o.State == inventory.ObjLive && o.Parent != "" {
		if chain, ok := pre.chain(o.Parent, r.nc); ok {
			o.Ancestry = chain
		} else {
			r.rep.AncestryUnresolved++
		}
	}
	if o.Kind == inventory.KindGroup && o.State == inventory.ObjLive {
		if !hasAttr(en, "member") {
			// The connector omits an attribute with no values, and this read asked for member: a live group
			// without it has none. The set is complete (and empty), so edges from an earlier read are removed.
			o.MembersComplete = true
		}
		if !o.MembersComplete {
			r.rep.GroupsPartial++
		}
		r.rep.MembersUnresolved += m.MembersUnresolved
	}
	if m.PrimaryGroup == PrimaryGroupUnresolved {
		r.rep.PrimaryGroupUnresolved++
	}
	return o, true, nil
}

func hasAttr(en *connectorv1.DirectoryEntry, name string) bool {
	for _, a := range en.GetAttributes() {
		if strings.EqualFold(a.GetName(), name) {
			return true
		}
	}
	return false
}

// chain is the ancestors of an object whose parent is the given one, nearest first up to and including the
// naming context head, from the links the pre-scan collected. It is not ok when a link is missing, the chain
// does not end at the head, it loops, or it is longer than the store keeps.
func (p *prescan) chain(parent, head inventory.GUID) ([]inventory.GUID, bool) {
	cur, ok := keyOf(string(parent))
	if !ok {
		return nil, false
	}
	top, ok := keyOf(string(head))
	if !ok {
		return nil, false
	}
	var out []inventory.GUID
	for len(out) < maxChainHops {
		out = append(out, inventory.GUID(textOf(cur[:])))
		if cur == top {
			return out, true
		}
		next, known := p.parent[cur]
		if !known || next == ([16]byte{}) {
			return nil, false // an ancestor the search did not deliver, or a root that is not the head
		}
		cur = next
	}
	return nil, false
}

// stillAllowed re-reads the connection and re-applies the gate of FullCycle: a connection suspended, retired
// or decommissioning since the read began is a typed *Refusal (DM-10 I10: suspended stops sync). It does not
// depend on the partition cursor having been paused. A failure to read the connection is ErrSource.
func (r *readJob) stillAllowed(ctx context.Context) error {
	conn, err := r.e.Conns.Get(ctx, r.tid, r.conn)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("%w: connection: %w", ErrSource, err)
	}
	if _, err := r.e.refuse(conn, r.conn); err != nil {
		return err
	}
	return r.e.Tenants.WithTenant(ctx, r.tid, func(ctx context.Context, tx store.Tx) error {
		cur, err := r.e.Cursors.Claim(ctx, tx, r.key, r.lease)
		if err != nil {
			return err
		}
		if cur.State == StatePaused {
			return ErrPaused
		}
		return nil
	})
}

// flush commits one batch in a tenant transaction of its own: it claims the cursor again (the compare-and-set
// that fences a deposed holder out of every batch, not only the last), ingests, and on the last batch records
// the pass and moves the cursor in the same transaction.
func (r *readJob) flush(ctx context.Context, obs []inventory.Observation, last bool) error {
	// Before every batch: a suspended, retired or decommissioning connection stops the read, whatever the
	// partition cursor says (nothing may rely on PauseConnection having been called).
	if conn, err := r.e.Conns.Get(ctx, r.tid, r.conn); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("%w: connection: %w", ErrSource, err)
	} else if _, err := r.e.refuse(conn, r.conn); err != nil {
		return err
	}
	var res inventory.Ingested
	err := r.e.Tenants.WithTenant(ctx, r.tid, func(ctx context.Context, tx store.Tx) error {
		cur, err := r.e.Cursors.Claim(ctx, tx, r.key, r.lease)
		if err != nil {
			return err
		}
		if cur.State == StatePaused {
			return ErrPaused // checked in the batch's own transaction, before anything is written
		}
		c := inventory.Cycle{Connection: inventory.ConnectionID(r.conn), Observed: r.observed, Observations: obs,
			Now: r.e.utc(), MoreBatches: !last}
		if last {
			c.PassNCs = []inventory.GUID{r.nc}
		}
		if res, err = r.e.Ingester.Ingest(ctx, tx, c); err != nil {
			return err
		}
		if last {
			if _, err := r.e.Cursors.CompleteScan(ctx, tx, r.key, r.lease, r.observed); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return r.wrap(err, "store")
	}
	r.rep.Batches++
	r.rep.Inserted += res.Inserted
	r.rep.Updated += res.Updated
	r.rep.Stale += res.Stale
	r.rep.Members += res.Members
	r.rep.PrimaryGroups += res.PrimaryGroups
	return nil
}
