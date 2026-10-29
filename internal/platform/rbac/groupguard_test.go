package rbac

import (
	"context"
	"errors"
	"testing"

	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

type fakeReach struct {
	g   authz.Groups
	err error
}

func (f fakeReach) ReachedFrom(context.Context, tenant.ID, authority.TargetRef) (authz.Groups, error) {
	return f.g, f.err
}

func withRoots(r RootResolver) Option { return func(a *Authorizer) { a.roots = r } }

const addMember = authz.Permission("objects.group.add_member")

var groupTarget = authority.TargetRef{Connection: conn, GUID: grpGUID, Class: "group"}

// The member-of-a-role-granting-group path is an indirect grant (DM-36.I1, TM-D18, TM-F-AUTHZ).
func TestGroupMembershipGuard(t *testing.T) {
	reached := authz.Groups{Complete: true, Groups: []authz.Group{{Connection: conn, GUID: grpGUID}}}
	granted := groupAssign([]authz.Permission{del}, ouRoot) // the group grants delete over ouA
	holdsAll := Assignment{ID: "t", Permissions: []authz.Permission{addMember, del}, Roots: ouRoot}
	onlyAdd := Assignment{ID: "t", Permissions: []authz.Permission{addMember}, Roots: ouRoot}
	run := func(a *Authorizer) error {
		return a.Authorize(ctxT(), human(acct), addMember, groupTarget, authority.Facts{Exists: true, Ancestors: []string{ouA}, AncestorsComplete: true})
	}
	t.Run("unwired guard refuses", func(t *testing.T) {
		a := newAz(t, fakeSrc{as: []Assignment{holdsAll}})
		if err := run(a); !contains(err, ReasonGroupNoResolver) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("incomplete answer refuses", func(t *testing.T) {
		a := newAz(t, fakeSrc{as: []Assignment{holdsAll}, sub: []Assignment{granted}}, WithGroupGuard(fakeReach{g: authz.Groups{Groups: reached.Groups}}))
		if err := run(a); !contains(err, ReasonGroupIncomplete) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("resolver error is not a grant", func(t *testing.T) {
		a := newAz(t, fakeSrc{as: []Assignment{holdsAll}, sub: []Assignment{granted}}, WithGroupGuard(fakeReach{err: errors.New("down")}))
		if err := run(a); err == nil {
			t.Fatal("allowed")
		}
	})
	t.Run("actor lacks a privilege the group grants", func(t *testing.T) {
		a := newAz(t, fakeSrc{as: []Assignment{onlyAdd}, sub: []Assignment{granted}}, WithGroupGuard(fakeReach{g: reached}), withRoots(fakeRoots{}))
		if err := run(a); !contains(err, ReasonGroupEscalation) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("group nested into a role-granting group", func(t *testing.T) {
		// The reach answer lists the outer group: the target is a child of it.
		outer := authz.Groups{Complete: true, Groups: []authz.Group{{Connection: conn, GUID: grpGUID}, {Connection: conn, GUID: ouB}}}
		a := newAz(t, fakeSrc{as: []Assignment{onlyAdd}, sub: []Assignment{granted}}, WithGroupGuard(fakeReach{g: outer}), withRoots(fakeRoots{}))
		if err := run(a); !contains(err, ReasonGroupEscalation) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("actor holds everything", func(t *testing.T) {
		a := newAz(t, fakeSrc{as: []Assignment{holdsAll}, sub: []Assignment{granted}}, WithGroupGuard(fakeReach{g: reached}), withRoots(fakeRoots{}))
		if err := run(a); err != nil {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("a group that grants nothing needs nothing more", func(t *testing.T) {
		a := newAz(t, fakeSrc{as: []Assignment{onlyAdd}}, WithGroupGuard(fakeReach{g: reached}), withRoots(fakeRoots{}))
		if err := run(a); err != nil {
			t.Fatalf("got %v", err)
		}
	})
}

// A directory-class target without a connection is malformed, not a store row (it would skip the
// Tier-0 and ancestry facts).
func TestEmptyConnectionIsNotAStoreTarget(t *testing.T) {
	tr := Root{Kind: TenantStore, Connection: tenantID, GUID: tenantID}
	a := newAz(t, fakeSrc{as: []Assignment{{ID: "a", Permissions: []authz.Permission{del}, Roots: []Root{tr}}}})
	bad := authority.TargetRef{GUID: obj, Class: "user"}
	if err := a.Authorize(ctxT(), human(acct), del, bad, authority.Facts{}); !contains(err, ReasonBadTarget) {
		t.Fatalf("directory class, no connection: %v", err)
	}
	if q := a.FactsQuery(human(acct), del, bad); q.Tier0 || q.Ancestry {
		t.Log("facts are requested for a malformed target only if it has a connection")
	}
	withConn := authority.TargetRef{Connection: conn, GUID: rowID, Class: "role"}
	if err := a.Authorize(ctxT(), human(acct), del, withConn, authority.Facts{}); !contains(err, ReasonBadTarget) {
		t.Fatalf("store class with a connection: %v", err)
	}
}
