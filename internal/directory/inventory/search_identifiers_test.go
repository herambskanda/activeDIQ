package inventory_test

import (
	"context"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"strings"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/directory/inventory"
	"github.com/skenzeriq/activediq/internal/platform/store/reportsql"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
)

// A fake recovery password: the 48 digits the BitLocker recovery screen shows. It is put in every place the
// sync could carry it and must reach neither the object row nor a key (T-1129 AC2).
const seededRecoveryPassword = "123456-234567-345678-456789-567891-678912-789123-891234"

// T-1129 AC1: every identifier shape the 2a sync set could not serve finds its object, in the right class.
func Test_search_serves_the_synced_identifiers(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		e.hStructure(t, e.adA)
		sr := e.searcher(t)
		u := sSrchUser(1, "praman", "P. R.")
		u.Attributes = map[string]any{
			"givenName": "Priya", "sn": "Raman", "mail": "priya.raman@example.test",
			"proxyAddresses": []any{"SMTP:priya.raman@example.test", "smtp:praman@alias.example.test", "x400:c=us;a= ;p=x;o=y;s=Raman;", "sip:praman@example.test"},
			"employeeID":     "004211", "employeeNumber": "N-77", "mailNickname": "prayaman",
			"sIDHistory": []any{"S-1-5-21-1111-2222-3333-4444"}, "title": "Senior Analyst", "department": "Finance",
		}
		c := sSrchUser(2, "web01$", "WEB01")
		c.Kind = inventory.KindComputer
		c.Class = "computer"
		c.Attributes = map[string]any{"dNSHostName": "web01.example.test",
			"servicePrincipalName": []any{"HTTP/web01.example.test", "MSSQLSvc/db01.example.test:1433/inst", "HOST/WEB01"}}
		if _, err := e.populate(t, e.adA, hBase, u, c); err != nil {
			t.Fatal(err)
		}
		scope := e.scopeNC(e.adA)
		for _, tc := range []struct {
			name, text, want string
			class            reportsql.SearchClass
		}{
			{"given_sn", "Priya Raman", hGUID(1, 1), reportsql.ClassPrefix},
			{"sn_given", "Raman Priya", hGUID(1, 1), reportsql.ClassPrefix},
			{"sn_comma_given", "Raman, Priya", hGUID(1, 1), reportsql.ClassPrefix},
			{"given_alone", "Priya", hGUID(1, 1), reportsql.ClassPrefix},
			{"mail", "priya.raman@example.test", hGUID(1, 1), reportsql.ClassExact},
			{"mail_prefix", "priya.raman@ex", hGUID(1, 1), reportsql.ClassPrefix},
			{"proxy_primary_case", "PRIYA.RAMAN@EXAMPLE.TEST", hGUID(1, 1), reportsql.ClassExact},
			{"proxy_alias", "praman@alias.example.test", hGUID(1, 1), reportsql.ClassExact},
			{"nickname", "prayaman", hGUID(1, 1), reportsql.ClassExact},
			{"employee_id_leading_zeros", "004211", hGUID(1, 1), reportsql.ClassExact},
			{"employee_id_prefix", "0042", hGUID(1, 1), reportsql.ClassPrefix},
			{"employee_number", "n-77", hGUID(1, 1), reportsql.ClassExact},
			{"sid_history", "S-1-5-21-1111-2222-3333-4444", hGUID(1, 1), reportsql.ClassExact},
			{"title", "Senior Analyst", hGUID(1, 1), reportsql.ClassPrefix},
			{"title_word", "analyst", hGUID(1, 1), reportsql.ClassPrefix},
			{"department", "Finance", hGUID(1, 1), reportsql.ClassPrefix},
			{"spn_whole", "HTTP/web01.example.test", hGUID(1, 2), reportsql.ClassExact},
			{"spn_with_port_and_name", "mssqlsvc/db01.example.test:1433/inst", hGUID(1, 2), reportsql.ClassExact},
			{"spn_host", "db01.example.test", hGUID(1, 2), reportsql.ClassExact},
			{"spn_short_host", "HOST/WEB01", hGUID(1, 2), reportsql.ClassExact},
		} {
			t.Run(tc.name, func(t *testing.T) {
				res, err := e.search(t, sr, scope, inventory.SearchRequest{Text: tc.text})
				if err != nil {
					t.Fatal(err)
				}
				if len(res.Hits) == 0 || res.Hits[0].Object != tc.want || res.Hits[0].Class != tc.class {
					t.Fatalf("hits %+v, want %s first as %s", res.Hits, tc.want, tc.class)
				}
			})
		}
		// Not indexed: other proxy address types and the sip scheme are not mail.
		for _, text := range []string{"x400:c=us", "sip:praman@example.test"} {
			res, err := e.search(t, sr, scope, inventory.SearchRequest{Text: text})
			if err != nil {
				t.Fatal(err)
			}
			for _, h := range res.Hits {
				if h.Class == reportsql.ClassExact {
					t.Errorf("%q must not be an exact hit: %+v", text, h)
				}
			}
		}
	})
}

// T-1129 AC2: nothing secret reaches inventory or its search keys, whatever the entry carried, and a
// recovery password typed into the search box is refused before any read.
func Test_search_keys_never_hold_a_recovery_password(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		e.hStructure(t, e.adA)
		c := sSrchUser(2, "web02$", "WEB02")
		c.Kind = inventory.KindComputer
		c.Class = "computer"
		c.Attributes = map[string]any{"servicePrincipalName": []any{"HOST/WEB02"}, "description": "key 7C2A91F0"}
		if _, err := e.populate(t, e.adA, hBase, c); err != nil {
			t.Fatal(err)
		}
		// an object whose text values are shaped like a recovery password never gets such a key
		p := sSrchUser(3, "pw", "Pw")
		p.Attributes = map[string]any{"title": seededRecoveryPassword, "employeeID": seededRecoveryPassword}
		if _, err := e.populate(t, e.adA, hBase.Add(time.Minute), p); err != nil {
			t.Fatal(err)
		}
		if n := e.strings(t, `SELECT count(*)::text FROM public.inventory_search_keys WHERE key LIKE '%123456%' OR key LIKE '%234567%'`); len(n) != 1 || n[0] != "0" {
			t.Errorf("a recovery-password-shaped value reached the keys: %v", n)
		}
		// the object itself is still stored and findable by what is not secret-shaped
		if n := e.strings(t, `SELECT count(*)::text FROM public.inventory_search_keys WHERE key_kind = 3 AND key = 'pw'`); n[0] != "1" {
			t.Errorf("the object keeps its other keys: %v", n)
		}
		sr := e.searcher(t)
		if _, err := e.search(t, sr, e.scopeNC(e.adA), inventory.SearchRequest{Text: seededRecoveryPassword}); err == nil {
			t.Error("a recovery password is refused as a query")
		}
	})
}

// The backfill derives the same keys as the writer from the stored row, so a tenant synced before T-1129
// gains the new kinds on the next backfill without another sync.
func Test_backfill_rebuilds_the_identifier_keys(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		e.hStructure(t, e.adA)
		u := sSrchUser(1, "praman", "Priya Raman")
		u.Attributes = map[string]any{"givenName": "Priya", "sn": "Raman", "employeeID": "004211", "proxyAddresses": []any{"smtp:p@alias.test"},
			"sIDHistory": []any{"S-1-5-21-1-2-3-4"}, "servicePrincipalName": []any{"HTTP/web01.example.test"}, "title": "Analyst", "mailNickname": "pr"}
		if _, err := e.populate(t, e.adA, hBase, u); err != nil {
			t.Fatal(err)
		}
		before := e.keys(t, string(u.Object))
		if err := e.tx(t, e.a, func(ctx context.Context, tx store.Tx) error {
			_, err := tx.Exec(ctx, `DELETE FROM public.inventory_search_keys`)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := e.r.Backfill(context.Background(), e.a, nil); err != nil {
			t.Fatal(err)
		}
		after := e.keys(t, string(u.Object))
		if strings.Join(before, "|") != strings.Join(after, "|") {
			t.Errorf("backfill differs from the writer:\n%v\n%v", before, after)
		}
		for _, want := range []string{"11:pr", "12:004211", "13:s-1-5-21-1-2-3-4", "14:http/web01.example.test", "6:web01.example.test", "15:analyst", "5:p@alias.test"} {
			if !strings.Contains(strings.Join(after, "|"), want) {
				t.Errorf("no key %q in %v", want, after)
			}
		}
	})
}
