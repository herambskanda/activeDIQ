package inventory_test

import (
	"context"
	"testing"

	sidpkg "github.com/skenzeriq/activediq/internal/directory/attr/sid"
	"github.com/skenzeriq/activediq/internal/directory/inventory"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
)

func TestObjectsBySID(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		ctx := context.Background()
		u1, u2 := adUser(usr1, nc1), adUser(usr2, nc1)
		u1.SID = []byte{1, 2, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 9, 0, 0, 0}
		u2.SID = []byte{1, 2, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 10, 0, 0, 0}
		u2.State = inventory.ObjDeleted
		if _, err := e.populate(t, e.adA, t1, u1, u2); err != nil {
			t.Fatal(err)
		}
		s1, err := sidpkg.FromBytes(u1.SID)
		if err != nil {
			t.Fatal(err)
		}
		s2, err := sidpkg.FromBytes(u2.SID)
		if err != nil {
			t.Fatal(err)
		}
		got, err2 := e.r.ObjectsBySID(ctx, e.a, s1)
		if err2 != nil || len(got) != 1 || got[0].Object != usr1 || got[0].Connection != e.adA {
			t.Fatalf("live: %v %v", got, err2)
		}
		if got, err = e.r.ObjectsBySID(ctx, e.a, s2); err != nil || len(got) != 0 {
			t.Fatalf("deleted object must not map: %v %v", got, err)
		}
		if got, err = e.r.ObjectsBySID(ctx, e.b, s1); err != nil || len(got) != 0 {
			t.Fatalf("another tenant must not see it: %v %v", got, err)
		}
		if _, err = e.r.ObjectsBySID(ctx, e.a, sidpkg.SID{}); err == nil {
			t.Fatal("zero SID accepted")
		}
	})
}
