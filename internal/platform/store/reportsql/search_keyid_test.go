package reportsql_test

import (
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/authz/authztest"
	"github.com/skenzeriq/activediq/internal/platform/searchkey"
	"github.com/skenzeriq/activediq/internal/platform/store/reportsql"
)

// ADR-0011 rule 5a and SE3 ("the template itself"): key_id is the posting table's join key and never leaves the
// statement. It appears only inside the m_fuzzy stage; the outer SELECT, the window and ORDER BY clauses, the
// result row and the cursor (SearchAfter) carry no key_id.
func Test_search_template_never_outputs_key_id(t *testing.T) {
	sch := reportsql.MapSchema{
		"directory_objects": schema["directory_objects"],
		"inventory_search_keys": {"tenant_id": reportsql.KindGUID, "connection_id": reportsql.KindGUID, "object_guid": reportsql.KindGUID,
			"key_kind": reportsql.KindInt, "key": reportsql.KindText, "norm_version": reportsql.KindInt, "key_id": reportsql.KindInt},
		"inventory_search_trigrams": {"tenant_id": reportsql.KindGUID, "trgm": reportsql.KindText, "key_id": reportsql.KindInt},
	}
	src, err := reportsql.NewSearchSource(sch, "inventory_search_keys", "inventory_search_trigrams", anchorT(), "kind", "state", "enabled", "display_name")
	if err != nil {
		t.Fatal(err)
	}
	p, err := searchkey.Classify("priya raman")
	if err != nil {
		t.Fatal(err)
	}
	after := &reportsql.SearchAfter{Class: reportsql.ClassFuzzy, Name: "x", Connection: "00000000-0000-0000-0000-000000000001", Object: "00000000-0000-0000-0000-000000000002"}
	for name, a := range map[string]*reportsql.SearchAfter{"first page": nil, "with a cursor": after} {
		t.Run(name, func(t *testing.T) {
			scope := authztest.ReadScope(grant([]authz.ScopeTerm{term(authz.TermNamingContext, 1, 0x10)}))
			q, err := reportsql.CompileSearch(src, reportsql.SearchQuery{Exact: p.Exact, Prefix: p.Prefix, Fuzzy: p.Fuzzy, GroupLimit: 5, Ceiling: 100, Threshold: 0.3, After: a},
				reportsql.SearchScopes{"directory.read": scope})
			if err != nil {
				t.Fatal(err)
			}
			sql, _ := q.Statement()
			start := strings.Index(sql, "m_fuzzy AS MATERIALIZED (")
			end := strings.Index(sql, "ceil AS (")
			if start < 0 || end < start {
				t.Fatalf("the statement has no m_fuzzy stage before ceil:\n%s", sql)
			}
			outside := sql[:start] + sql[end:]
			if m := regexp.MustCompile(`(?i)\bkey_id\b`).FindStringIndex(outside); m != nil {
				t.Errorf("key_id appears outside the m_fuzzy stage: ...%s...", outside[max(0, m[0]-60):min(len(outside), m[1]+60)])
			}
			// the fuzzy stage itself exposes only the four columns the later stages read
			frag := sql[start:end]
			if !strings.Contains(frag, "SELECT r.connection_id, r.object_guid, r.key_kind, r.key FROM") {
				t.Errorf("m_fuzzy must project (connection_id, object_guid, key_kind, key) only:\n%s", frag)
			}
		})
	}
	// the cursor and the hit carry no key id either
	for _, v := range []any{reportsql.SearchAfter{}, reportsql.SearchHit{}, reportsql.SearchResult{}} {
		rt := reflect.TypeOf(v)
		for i := 0; i < rt.NumField(); i++ {
			if strings.Contains(strings.ToLower(rt.Field(i).Name), "keyid") {
				t.Errorf("%s.%s carries the posting key id", rt.Name(), rt.Field(i).Name)
			}
		}
	}
}
