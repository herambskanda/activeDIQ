package inventory_test

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/skenzeriq/activediq/internal/directory/inventory"
	"github.com/skenzeriq/activediq/internal/platform/searchkey"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
)

const ncDN = `DC=corp,DC=example`

// rdns are the leaf RDNs of the subtree objects: commas, "+", Unicode and an edge space, which are what
// a text replace of the suffix gets wrong.
var rdns = map[string]string{
	ouA: `OU=Sales\, East`, ouB: `OU=B\+Team`, ouX: `OU=Ünï\, X`,
	uX: `CN=Raman\, Priya`, gX: `CN=Group X`, cX: `CN=PC-X`, ouY: `OU=Y\ `, uY: `CN=Üser Y`, gY: `CN=Group Y`,
	ouZ: `OU=Z`, cZ: `CN=PC-Z`, uZ: `CN=Z\, User`,
}

// withDN sets the DN a connector would send for o: its RDN, then its parent's DN.
func (f *forest) withDN(o inventory.Observation) inventory.Observation {
	o.RDN = rdns[string(o.Object)]
	o.DN = o.RDN + "," + f.dnOf(string(o.Parent))
	return o
}

func (f *forest) dnOf(g string) string {
	if g == nc1 {
		return ncDN
	}
	parts := []string{rdns[g]}
	for _, a := range f.chains[g] {
		if a != nc1 {
			parts = append(parts, rdns[a])
		}
	}
	return strings.Join(append(parts, ncDN), ",")
}

func withDNs(f *forest, obs []inventory.Observation) []inventory.Observation {
	out := make([]inventory.Observation, len(obs))
	for i, o := range obs {
		if o.Object == nc1 {
			o.DN = ncDN
			out[i] = o
			continue
		}
		out[i] = f.withDN(o)
	}
	return out
}

// dns reads dn and the dn search keys of the connection's rows.
func (e *env) dns(t *testing.T, c inventory.ConnectionID) (dn map[string]string, keys map[string][]string) {
	t.Helper()
	dn, keys = map[string]string{}, map[string][]string{}
	if err := e.tx(t, e.a, func(ctx context.Context, tx store.Tx) error {
		rs, err := tx.Query(ctx, `SELECT object_guid::text, dn FROM public.directory_objects WHERE connection_id = $1::uuid`, string(c))
		if err != nil {
			return err
		}
		for rs.Next() {
			var g, d string
			if err := rs.Scan(&g, &d); err != nil {
				rs.Close()
				return err
			}
			dn[g] = d
		}
		rs.Close()
		ks, err := tx.Query(ctx, `SELECT object_guid::text, key FROM public.inventory_search_keys
			WHERE connection_id = $1::uuid AND key_kind = $2::smallint ORDER BY object_guid, key`, string(c), int16(searchkey.KindDN))
		if err != nil {
			return err
		}
		defer ks.Close()
		for ks.Next() {
			var g, k string
			if err := ks.Scan(&g, &k); err != nil {
				return err
			}
			keys[g] = append(keys[g], k)
		}
		return ks.Err()
	}); err != nil {
		t.Fatal(err)
	}
	return dn, keys
}

func (e *env) checkDNs(t *testing.T, f *forest, c inventory.ConnectionID) {
	t.Helper()
	dn, keys := e.dns(t, c)
	for _, g := range subtreeGUIDs {
		want := f.dnOf(g)
		if dn[g] != want {
			t.Errorf("dn of %s = %q, want %q", g, dn[g], want)
		}
		searchable := g != ouX && g != ouY && g != ouZ // OUs are not indexed
		wantKeys := []string(nil)
		if searchable {
			wantKeys = []string{searchkey.NormDN(want)}
		}
		if !reflect.DeepEqual(keys[g], wantKeys) {
			t.Errorf("dn key of %s = %q, want %q", g, keys[g], wantKeys)
		}
	}
}

// Acceptance 1: every descendant's dn ends with the OU's new dn after a move, with its dn key.
func TestMoveRewritesDescendantsDN(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		f := newForest()
		obs := []inventory.Observation{head(), f.at(ouA, inventory.KindOU, nc1), f.at(ouB, inventory.KindOU, ouA)}
		obs = append(obs, f.subtree(ouA)...)
		if _, err := e.populate(t, e.adA, t1, withDNs(f, obs)...); err != nil {
			t.Fatal(err)
		}
		e.checkDNs(t, f, e.adA)

		// Move X under B (deeper) and observe only X.
		moved := f.subtree(ouB)[0]
		if _, err := e.populate(t, e.adA, t2, f.withDN(moved)); err != nil {
			t.Fatal(err)
		}
		e.checkDNs(t, f, e.adA)
		dn, _ := e.dns(t, e.adA)
		if want := `CN=Z\, User,OU=Z,OU=Y\ ,OU=Ünï\, X,OU=B\+Team,OU=Sales\, East,` + ncDN; dn[uZ] != want {
			t.Fatalf("uZ dn = %q, want %q", dn[uZ], want)
		}

		// And back up to the NC root: a shorter dn.
		top := f.subtree(nc1)[0]
		if _, err := e.populate(t, e.adA, t2.Add(1), f.withDN(top)); err != nil {
			t.Fatal(err)
		}
		e.checkDNs(t, f, e.adA)
	})
}

// A move that fails part-way or whose transaction rolls back leaves every dn and key as it was.
func TestMoveDNRolledBackWithMove(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		f := newForest()
		obs := []inventory.Observation{head(), f.at(ouA, inventory.KindOU, nc1), f.at(ouB, inventory.KindOU, ouA)}
		obs = append(obs, f.subtree(ouA)...)
		if _, err := e.populate(t, e.adA, t1, withDNs(f, obs)...); err != nil {
			t.Fatal(err)
		}
		beforeDN, beforeKeys := e.dns(t, e.adA)
		fault := fmt.Sprintf(`CREATE FUNCTION public.t0988_fault() RETURNS trigger LANGUAGE plpgsql AS $$
			BEGIN
				IF NEW.object_guid = '%s' AND NEW.dn IS DISTINCT FROM OLD.dn THEN
					RAISE EXCEPTION 'injected fault' USING ERRCODE = 'AD500';
				END IF;
				RETURN NEW;
			END $$;
			CREATE TRIGGER t0988_fault BEFORE UPDATE ON public.directory_objects FOR EACH ROW EXECUTE FUNCTION public.t0988_fault()`, uZ)
		if err := e.d.ExecOwner(context.Background(), fault); err != nil {
			t.Fatal(err)
		}
		moved := f.subtree(ouB)[0]
		if _, err := e.populate(t, e.adA, t2, f.withDN(moved)); err == nil || !strings.Contains(err.Error(), "rewrite descendants") {
			t.Fatalf("move err = %v, want the descendant dn rewrite to fail", err)
		}
		afterDN, afterKeys := e.dns(t, e.adA)
		if !reflect.DeepEqual(beforeDN, afterDN) || !reflect.DeepEqual(beforeKeys, afterKeys) {
			t.Fatalf("a failed move changed dn or keys:\n%v\n%v", beforeDN, afterDN)
		}
	})
}
