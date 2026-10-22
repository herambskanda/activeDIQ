// Package connectiontest holds an in-memory fake of the connection package's read ports, for the
// unit tests of callers (the write gate, correlations). It enforces the same lifecycle rules as the
// SQL store, and a fault can be injected to prove a caller fails closed. It is not a substitute for
// the store's own tests, which run against a real database.
package connectiontest

import (
	"context"
	"fmt"
	"sync"

	"github.com/skenzeriq/activediq/internal/directory/connection"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// HybridLinks is an in-memory connection.HybridLinks, tenant-scoped like the real one.
type HybridLinks struct {
	mu    sync.Mutex
	seq   int
	links map[tenant.ID][]connection.HybridLink
	// Err, when set, is returned by every read, as a failing database would.
	Err error
}

var _ connection.HybridLinks = (*HybridLinks)(nil)

// NewHybridLinks returns an empty fake.
func NewHybridLinks() *HybridLinks {
	return &HybridLinks{links: map[tenant.ID][]connection.HybridLink{}}
}

func (f *HybridLinks) add(tid tenant.ID, n connection.NewHybridLink, origin connection.LinkOrigin, state connection.LinkState) (connection.HybridLink, error) {
	if tid.IsZero() {
		return connection.HybridLink{}, connection.ErrNoTenant
	}
	ad, err := connection.ParseID(string(n.ADConnectionID))
	if err != nil {
		return connection.HybridLink{}, err
	}
	nc, err := connection.ParseNCGUID(string(n.NCGUID))
	if err != nil {
		return connection.HybridLink{}, err
	}
	en, err := connection.ParseID(string(n.EntraConnectionID))
	if err != nil {
		return connection.HybridLink{}, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, l := range f.links[tid] {
		if l.ADConnectionID == ad && l.NCGUID == nc && l.EntraConnectionID == en && l.State != connection.LinkRemoved {
			return connection.HybridLink{}, connection.ErrDuplicateHybridLink
		}
	}
	f.seq++
	l := connection.HybridLink{
		ID:             connection.HybridLinkID(fmt.Sprintf("00000000-0000-4000-8000-%012x", f.seq)),
		ADConnectionID: ad, NCGUID: nc, EntraConnectionID: en, Origin: origin, State: state,
	}
	f.links[tid] = append(f.links[tid], l)
	return l, nil
}

// Declare stores a confirmed, declared link.
func (f *HybridLinks) Declare(tid tenant.ID, n connection.NewHybridLink) (connection.HybridLink, error) {
	return f.add(tid, n, connection.OriginDeclared, connection.LinkConfirmed)
}

// Discover stores a proposed, discovered link.
func (f *HybridLinks) Discover(tid tenant.ID, n connection.NewHybridLink) (connection.HybridLink, error) {
	return f.add(tid, n, connection.OriginDiscovered, connection.LinkProposed)
}

// Transition applies a declared DM-21 edge, compare-and-set on from.
func (f *HybridLinks) Transition(tid tenant.ID, id connection.HybridLinkID, from, to connection.LinkState) (connection.HybridLink, error) {
	if !connection.CanTransitionLink(from, to) {
		return connection.HybridLink{}, fmt.Errorf("%w: %s → %s", connection.ErrIllegalLinkTransition, from, to)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for i, l := range f.links[tid] {
		if l.ID == id {
			if l.State != from {
				return connection.HybridLink{}, connection.ErrLinkStateConflict
			}
			f.links[tid][i].State = to
			return f.links[tid][i], nil
		}
	}
	return connection.HybridLink{}, connection.ErrHybridLinkNotFound
}

// Confirmed implements connection.HybridLinks.
func (f *HybridLinks) Confirmed(_ context.Context, tid tenant.ID, adConn connection.ID, nc connection.NCGUID, entraConn connection.ID) (bool, error) {
	if f.Err != nil {
		return false, f.Err
	}
	if tid.IsZero() {
		return false, connection.ErrNoTenant
	}
	// Same input validation as the real store: bad input is an error, never "no link".
	adConn, err := connection.ParseID(string(adConn))
	if err != nil {
		return false, err
	}
	nc, err = connection.ParseNCGUID(string(nc))
	if err != nil {
		return false, err
	}
	entraConn, err = connection.ParseID(string(entraConn))
	if err != nil {
		return false, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, l := range f.links[tid] {
		if l.ADConnectionID == adConn && l.NCGUID == nc && l.EntraConnectionID == entraConn && l.State == connection.LinkConfirmed {
			return true, nil
		}
	}
	return false, nil
}

// HasHybridLink implements connection.HybridLinks.
func (f *HybridLinks) HasHybridLink(_ context.Context, tid tenant.ID, adConn connection.ID) (bool, error) {
	if f.Err != nil {
		return false, f.Err
	}
	if tid.IsZero() {
		return false, connection.ErrNoTenant
	}
	adConn, err := connection.ParseID(string(adConn))
	if err != nil {
		return false, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, l := range f.links[tid] {
		if l.ADConnectionID == adConn && l.State != connection.LinkRemoved {
			return true, nil
		}
	}
	return false, nil
}
