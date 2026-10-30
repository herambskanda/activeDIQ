package inventory_test

import (
	"context"
	"errors"
	"testing"

	"github.com/skenzeriq/activediq/internal/directory/inventory"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

const (
	rc     = "aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa"
	inner  = "11111111-aaaa-4aaa-8aaa-111111111111"
	middle = "22222222-aaaa-4aaa-8aaa-222222222222"
	outer  = "33333333-aaaa-4aaa-8aaa-333333333333"
)

func grp(g string) authority.TargetRef {
	return authority.TargetRef{Connection: rc, GUID: g, Class: "group"}
}

type tooMany struct{}

func (tooMany) GroupExists(context.Context, tenant.ID, inventory.ConnectionID, inventory.GUID) (bool, error) {
	return true, nil
}

func (tooMany) GroupsOf(context.Context, tenant.ID, inventory.ConnectionID, inventory.GUID) ([]inventory.GUID, error) {
	return nil, inventory.ErrTooMany
}

func idSet(r []string) map[string]bool {
	m := map[string]bool{}
	for _, g := range r {
		m[g] = true
	}
	return m
}

func TestReachedFromIsTargetPlusOuterGroups(t *testing.T) {
	f := inventory.NewFake()
	tid := tenant.New()
	f.AddGroup(tid, rc, inner)
	f.AddMembership(tid, rc, inner, middle)
	f.AddMembership(tid, rc, inner, outer) // the source answers transitively
	got, err := inventory.NewReach(f).ReachedFrom(context.Background(), tid, grp(inner))
	if err != nil || !got.Complete {
		t.Fatalf("%v %+v", err, got)
	}
	var ids []string
	for _, g := range got.Groups {
		if g.Connection != rc {
			t.Errorf("connection %q", g.Connection)
		}
		if len(g.Path) != 0 { // the source returns the closure, not the chain: no invented path
			t.Errorf("path %v", g.Path)
		}
		ids = append(ids, g.GUID)
	}
	if m := idSet(ids); len(ids) != 3 || !m[inner] || !m[middle] || !m[outer] {
		t.Fatalf("reach %v", ids)
	}
}

func TestReachedFromFailsClosed(t *testing.T) {
	tid := tenant.New()
	ctx := context.Background()
	f := inventory.NewFake()
	f.AddGroup(tid, rc, inner)
	cases := map[string]struct {
		r *inventory.Reach
		t authority.TargetRef
	}{
		"member class, not a group":     {inventory.NewReach(f), authority.TargetRef{Connection: rc, GUID: inner, Class: "user"}},
		"unknown group (no active row)": {inventory.NewReach(f), grp(middle)},
		"malformed guid":                {inventory.NewReach(f), grp("not-a-guid")},
		"truncated closure":             {inventory.NewReach(tooMany{}), grp(inner)},
	}
	for name, c := range cases {
		got, err := c.r.ReachedFrom(ctx, tid, c.t)
		if err != nil || got.Complete || len(got.Groups) != 0 {
			t.Errorf("%s: %v %+v", name, err, got)
		}
	}
	f.Err = errors.New("db down")
	if got, err := inventory.NewReach(f).ReachedFrom(ctx, tid, grp(inner)); err == nil || got.Complete {
		t.Errorf("read error: %v %+v", err, got)
	}
	if _, err := (*inventory.Reach)(nil).ReachedFrom(ctx, tid, grp(inner)); err == nil {
		t.Error("nil reach allowed")
	}
}
