package inventory

import (
	"context"
	"sort"
	"sync"

	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// Fake is an in-memory CorrelationSource, Designations and GroupSource for consumers' tests
// (directory/client, T-0109). It mirrors the Postgres reader's contract: tenant-scoped, removed
// links hidden, no state filter, errors never become empty results. Set Err to make every read fail.
type Fake struct {
	mu     sync.Mutex
	Err    error
	links  map[tenant.ID][]Link
	desig  map[tenant.ID]map[ConnectionID]map[GUID]bool
	groups map[tenant.ID]map[Ref][]GUID
}

var (
	_ CorrelationSource = (*Fake)(nil)
	_ Designations      = (*Fake)(nil)
	_ GroupSource       = (*Fake)(nil)
)

// NewFake returns an empty fake.
func NewFake() *Fake {
	return &Fake{links: map[tenant.ID][]Link{}, desig: map[tenant.ID]map[ConnectionID]map[GUID]bool{}, groups: map[tenant.ID]map[Ref][]GUID{}}
}

// AddLink stores l, a link seen from l.Self; it is returned from either side. The fake stores the
// link once per side, oriented, as the Postgres reader would present it.
func (f *Fake) AddLink(tid tenant.ID, l Link) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.links[tid] = append(f.links[tid], l)
	mirror := l
	mirror.Self, mirror.Peer = l.Peer, l.Self
	mirror.SelfTier0, mirror.PeerTier0 = l.PeerTier0, l.SelfTier0
	mirror.SelfBases, mirror.PeerBases = l.PeerBases, l.SelfBases
	if l.PeerKind == "entra_tenant" {
		mirror.PeerKind = "ad_forest"
	} else {
		mirror.PeerKind = "entra_tenant"
	}
	f.links[tid] = append(f.links[tid], mirror)
}

// Designate marks object as designated in the connection.
func (f *Fake) Designate(tid tenant.ID, c ConnectionID, object GUID) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.desig[tid] == nil {
		f.desig[tid] = map[ConnectionID]map[GUID]bool{}
	}
	if f.desig[tid][c] == nil {
		f.desig[tid][c] = map[GUID]bool{}
	}
	f.desig[tid][c][object] = true
}

// AddMembership records that member is (transitively) in group.
func (f *Fake) AddMembership(tid tenant.ID, c ConnectionID, member, group GUID) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.groups[tid] == nil {
		f.groups[tid] = map[Ref][]GUID{}
	}
	k := Ref{c, member}
	f.groups[tid][k] = append(f.groups[tid][k], group)
}

// CorrelationsFor implements CorrelationSource.
func (f *Fake) CorrelationsFor(_ context.Context, tid tenant.ID, ref Ref) ([]Link, error) {
	if f.Err != nil {
		return nil, f.Err
	}
	if tid.IsZero() {
		return nil, ErrNoTenant
	}
	if !ref.Valid() {
		return nil, ErrInvalid
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	out := []Link{}
	for _, l := range f.links[tid] {
		if l.Self == ref && l.State != StateRemoved {
			out = append(out, l)
		}
	}
	sortLinks(out)
	return out, nil
}

// GroupsOf implements GroupSource.
func (f *Fake) GroupsOf(_ context.Context, tid tenant.ID, c ConnectionID, member GUID) ([]GUID, error) {
	if f.Err != nil {
		return nil, f.Err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]GUID(nil), f.groups[tid][Ref{c, member}]...), nil
}

// DesignationsFor implements Designations.
func (f *Fake) DesignationsFor(ctx context.Context, tid tenant.ID, c ConnectionID, refs []GUID) ([]GUID, error) {
	if f.Err != nil {
		return nil, f.Err
	}
	if tid.IsZero() {
		return nil, ErrNoTenant
	}
	// Same input checks as Reader, so consumers' tests exercise the same inputs.
	if cs, ok := canon(string(c)); !ok || cs != string(c) {
		return nil, ErrInvalid
	}
	for _, g := range refs {
		if cg, ok := canon(string(g)); !ok || cg != string(g) {
			return nil, ErrInvalid
		}
	}
	if len(refs) > MaxDesignationRefs {
		return nil, ErrTooMany
	}
	set := map[GUID]bool{}
	f.mu.Lock()
	d := f.desig[tid][c]
	for _, g := range refs {
		if d[g] {
			set[g] = true
		}
		for _, grp := range f.groups[tid][Ref{c, g}] {
			if d[grp] {
				set[grp] = true
			}
		}
	}
	f.mu.Unlock()
	out := make([]GUID, 0, len(set))
	for g := range set {
		out = append(out, g)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out, nil
}

// Undesignate removes a designation, as the soft delete of the Postgres writer hides it from reads.
func (f *Fake) Undesignate(tid tenant.ID, c ConnectionID, object GUID) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.desig[tid][c], object)
}
