package reportsql_test

import (
	"strings"
	"testing"

	"github.com/skenzeriq/activediq/internal/platform/report"
	"github.com/skenzeriq/activediq/internal/platform/store/reportsql"
)

func refused(t *testing.T, mut func(*report.Dataset), want ...string) {
	t.Helper()
	ds := usersDataset()
	mut(&ds)
	_, err := reportsql.NewRegistry(opts(), ds)
	if err == nil {
		t.Fatalf("NewRegistry accepted the dataset; want an error naming %q", want)
	}
	for _, w := range want {
		if !strings.Contains(err.Error(), w) {
			t.Fatalf("error %q does not name %q", err, w)
		}
	}
}

func TestNewRegistry_accepts_the_fixture(t *testing.T) {
	r := registry(t, usersDataset())
	if got := r.IDs(); len(got) != 1 || got[0] != "inventory.users" {
		t.Fatalf("IDs = %v", got)
	}
	if _, ok := r.Dataset("inventory.nothing"); ok {
		t.Fatal("unknown dataset found")
	}
}

// AC 1 (T-0865): a MaskAnchor's non-identity projection takes the same allowlist as a Rel's.
func TestNewRegistry_MaskAnchor_projection_allowlist(t *testing.T) {
	mask := func(project, identity []report.Ident) func(*report.Dataset) {
		return func(d *report.Dataset) {
			d.Anchors = append(d.Anchors, report.Anchor{ID: "owner", Table: "directory_objects", Mode: report.MaskAnchor,
				Project: project, Identity: identity, Connection: "connection_id", NC: "nc_guid", Object: "object_guid",
				Parent: "parent_guid", Ancestry: "ancestry", Complete: "ancestry_complete"})
		}
	}
	// A text column that is not an identity column is refused, and named.
	id := []report.Ident{"sam_account_name"}
	refused(t, mask([]report.Ident{"object_guid", "display_name"}, id), "owner", "display_name", "text")
	// So is jsonb (attributes), and a text list.
	refused(t, mask([]report.Ident{"object_guid", "attributes"}, id), "attributes", "json")
	refused(t, mask([]report.Ident{"groups"}, id), "groups")
	// A text column named as an identity column is masked outside the scope: allowed.
	ds := usersDataset()
	mask([]report.Ident{"object_guid", "sam_account_name"}, id)(&ds)
	if _, err := reportsql.NewRegistry(opts(), ds); err != nil {
		t.Fatalf("an identity text column is allowed: %v", err)
	}
	// GUID, int, bool, time and enum are allowed as plain projection.
	ds = usersDataset()
	mask([]report.Ident{"object_guid", "logon_count", "enabled", "pwd_last_set", "state", "sam_account_name"}, id)(&ds)
	if _, err := reportsql.NewRegistry(opts(), ds); err != nil {
		t.Fatalf("allowlisted kinds: %v", err)
	}
}

func TestNewRegistry_Rel_projection_allowlist(t *testing.T) {
	rel := func(project ...report.Ident) func(*report.Dataset) {
		return func(d *report.Dataset) {
			d.Rels = append(d.Rels, report.Rel{ID: "links", Kind: report.RelEdge, Table: "group_links", Project: project})
			d.Tables = append(d.Tables, "group_links")
		}
	}
	refused(t, rel("group_guid", "note"), "links", "note", "text")
	refused(t, rel("meta"), "meta", "json")
	refused(t, rel("nope"), "nope")
	ds := usersDataset()
	rel("group_guid", "member_guid", "link_kind", "since")(&ds)
	if _, err := reportsql.NewRegistry(opts(), ds); err != nil {
		t.Fatalf("allowlisted kinds: %v", err)
	}
}

func TestNewRegistry_refuses_what_the_schema_does_not_have(t *testing.T) {
	refused(t, func(d *report.Dataset) { d.Columns[1].Source = report.Attr{Col: "nope"} }, "sam", "nope")
	refused(t, func(d *report.Dataset) { d.Anchors[0].Parent = "nope" }, "nope")
	refused(t, func(d *report.Dataset) { d.Anchors[0].Ancestry = "enabled" }, "ancestry")
	refused(t, func(d *report.Dataset) { d.Columns[1].Source = report.Attr{Col: "pwd_last_set"} }, "sam", "pwd_last_set")
	refused(t, func(d *report.Dataset) { d.Tables = []string{"directory_objects", "ghosts"} }, "ghosts")
	refused(t, func(d *report.Dataset) { d.Anchors[0].Project = []report.Ident{"nope"} }, "nope")
}

func TestNewRegistry_fragments_name_no_table(t *testing.T) {
	refused(t, func(d *report.Dataset) {
		d.Columns[2].Source = report.Derived{SQL: report.SQL("(SELECT 1 FROM group_links)")}
	}, "table", "group_links")
	refused(t, func(d *report.Dataset) {
		d.Columns[2].Source = report.Derived{SQL: report.SQL("pg_sleep(1)")}
	}, "pg_sleep")
	refused(t, func(d *report.Dataset) {
		d.Columns[2].Source = report.Derived{SQL: report.SQL("current_setting({t}.kind)")}
	}, "current_setting")
	// An alias that is also a table name could make a subselect read the table.
	refused(t, func(d *report.Dataset) {
		d.Rels = append(d.Rels, report.Rel{ID: "group_links", Kind: report.RelEdge, Table: "group_links", Project: []report.Ident{"group_guid"}})
		d.Tables = append(d.Tables, "group_links")
	}, "group_links", "table name")
}

// T-1033 AC1: a fragment's words come from an allowlist. A function that reads a table from a string,
// a schema-qualified name or an unlisted function is refused, and the error names the word.
func TestNewRegistry_fragments_use_an_allowlist(t *testing.T) {
	derived := func(sql string) func(*report.Dataset) {
		return func(d *report.Dataset) { d.Columns[2].Source = report.Derived{SQL: report.SQL(sql)} }
	}
	for _, c := range []struct{ sql, word string }{
		{`query_to_xml('select * from directory_objects', true, true, '')`, "query_to_xml"},
		{`(query_to_xml('select 1', true, true, ''))::text`, "query_to_xml"},
		{`table_to_xml('directory_objects', true, true, '')`, "table_to_xml"},
		{`cursor_to_xml('c', 1, true, true, '')`, "cursor_to_xml"},
		{`xpath('/a', 'x')`, "xpath"},
		{`ts_stat('select 1')`, "ts_stat"},
		{`to_regclass('directory_objects')`, "to_regclass"},
		{`'directory_objects'::regclass`, "regclass"},
		{`(SELECT count(*) FROM information_schema.tables)`, "information_schema"},
		{`(SELECT 1 FROM pg_catalog.pg_class)`, "pg_catalog"},
		{`public.now()`, "public"},
		{`pg_sleep(1)`, "pg_sleep"},
		{`current_setting({t}.kind)`, "current_setting"},
		{`now()`, "now"},
		{`current_timestamp`, "current_timestamp"},
		{`random()`, "random"},
		{`generate_series(1, 3)`, "generate_series"},
		{`md5({t}.kind)`, "md5"},
		{`{t}.kind::xml`, "xml"},
		{`E'x'`, "e"},
		{`(TABLE directory_objects)`, "TABLE"},
		{`(VALUES (1))`, "VALUES"},
		{`(WITH x AS MATERIALIZED (SELECT 1) SELECT 1)`, "MATERIALIZED"},
		{`zzz`, "zzz"},
		{`(SELECT 1 FROM group_links)`, "group_links"},
		{`(SELECT 1 FROM Directory_Objects)`, "Directory_Objects"},
		{`(SELECT 1 FROM (directory_objects) x)`, "from"},
		{`(SELECT 1 FROM (SELECT 1 FROM group_links) x)`, "group_links"},
		{`(SELECT 1 FROM {t})`, "from"},
		{`count`, "count"},
		{`{t}.kind(1)`, "kind"},
		{`'abc {t} def'`, "literal"},
		{"{t}.kind é", "character"},
		{`{rel.p}.a.b`, "dotted"},
	} {
		t.Run(c.sql, func(t *testing.T) {
			refused(t, func(d *report.Dataset) {
				d.Rels = append(d.Rels, report.Rel{ID: "p", Kind: report.RelEdge, Table: "group_links", Project: []report.Ident{"group_guid"}})
				d.Tables = append(d.Tables, "group_links")
				derived(c.sql)(d)
			}, c.word)
		})
	}
}

// T-1033 review (security): a joined RowAnchor's {rel.<id>} is a bare alias, which FROM would resolve
// as a table on the search_path (pg_class, pg_roles, …). It may not follow FROM; a Rel, FilterAnchor
// or MaskAnchor, which expand to compiler-built subselects, may. An ID starting pg_ is refused.
func TestNewRegistry_RowAnchor_slot_may_not_follow_from(t *testing.T) {
	joined := func(id report.AnchorID) func(*report.Dataset) {
		return func(d *report.Dataset) {
			a := anchorT()
			a.ID = id
			d.Anchors = append(d.Anchors, a)
			d.Base.Joins = append(d.Base.Joins, report.RowJoin{Anchor: id,
				On: report.SQL("{rel." + string(id) + "}.object_guid = {t}.object_guid")})
		}
	}
	count := func(id string) func(*report.Dataset) {
		return func(d *report.Dataset) {
			d.Columns[2].Source = report.Derived{SQL: report.SQL("(SELECT count(*) FROM {rel." + id + "})::text")}
		}
	}
	both := func(fs ...func(*report.Dataset)) func(*report.Dataset) {
		return func(d *report.Dataset) {
			for _, f := range fs {
				f(d)
			}
		}
	}
	refused(t, both(joined("g"), count("g")), "g", "RowAnchor", "from")
	refused(t, both(joined("pg_class"), count("pg_class")), "pg_class", "pg_")
	refused(t, func(d *report.Dataset) {
		d.Rels = append(d.Rels, report.Rel{ID: "pg_roles", Kind: report.RelEdge, Table: "group_links", Project: []report.Ident{"group_guid"}})
		d.Tables = append(d.Tables, "group_links")
	}, "pg_roles", "pg_")

	for name, mut := range map[string]func(*report.Dataset){
		"rel": func(d *report.Dataset) {
			d.Rels = append(d.Rels, report.Rel{ID: "p", Kind: report.RelEdge, Table: "group_links", Project: []report.Ident{"group_guid"}})
			d.Tables = append(d.Tables, "group_links")
			count("p")(d)
		},
		"filter anchor": func(d *report.Dataset) {
			a := anchorT()
			a.ID, a.Mode = "f", report.FilterAnchor
			d.Anchors = append(d.Anchors, a)
			count("f")(d)
		},
		"joined row anchor read as a column": both(joined("g"), func(d *report.Dataset) {
			d.Columns[2].Source = report.Derived{SQL: report.SQL("{rel.g}.object_guid::text")}
		}),
	} {
		t.Run(name, func(t *testing.T) {
			ds := usersDataset()
			mut(&ds)
			if _, err := reportsql.NewRegistry(opts(), ds); err != nil {
				t.Fatalf("refused: %v", err)
			}
		})
	}
}

// T-1033 (second security review): the FROM list is exactly one non-RowAnchor {rel.x} slot. The
// IS [NOT] DISTINCT FROM exemption is exact, a comma adds no second item, a dot qualifies nothing,
// and a RowAnchor or Rel may not be named after a schema.
func TestNewRegistry_FROM_is_one_scoped_slot(t *testing.T) {
	withRel := func(d *report.Dataset) {
		d.Rels = append(d.Rels, report.Rel{ID: "p", Kind: report.RelEdge, Table: "group_links", Project: []report.Ident{"group_guid"}})
		d.Tables = append(d.Tables, "group_links")
	}
	withRow := func(id report.AnchorID) func(*report.Dataset) {
		return func(d *report.Dataset) {
			a := anchorT()
			a.ID = id
			d.Anchors = append(d.Anchors, a)
			d.Base.Joins = append(d.Base.Joins, report.RowJoin{Anchor: id,
				On: report.SQL("{rel." + string(id) + "}.object_guid = {t}.object_guid")})
		}
	}
	with := func(sql string, pre ...func(*report.Dataset)) func(*report.Dataset) {
		return func(d *report.Dataset) {
			for _, f := range pre {
				f(d)
			}
			d.Columns[2].Source = report.Derived{SQL: report.SQL(sql)}
		}
	}
	for _, c := range []struct {
		name string
		mut  func(*report.Dataset)
		want []string
	}{
		{"distinct before from", with(`(SELECT 1 distinct FROM {rel.g})::text`, withRow("g")), []string{"g", "RowAnchor"}},
		{"distinct before from over a Rel", with(`(SELECT 1 distinct FROM x)::text`, withRel), []string{"x", "from"}},
		{"not distinct before from", with(`(SELECT 1 not distinct FROM {rel.g})::text`, withRow("g")), []string{"g", "RowAnchor"}},
		{"alias distinct", with(`(SELECT count(*) AS distinct FROM {rel.g})::text`, withRow("g")), []string{"distinct", "reserved"}},
		{"comma item", with(`(SELECT count(*) FROM {rel.p}, {rel.p})::text`, withRel), []string{","}},
		{"comma item after where", with(`(SELECT count(*) FROM {rel.p} WHERE true, {rel.p})::text`, withRel), []string{","}},
		{"comma item bare table", with(`(SELECT count(*) FROM {rel.p}, day)::text`, withRel), []string{","}},
		{"second from after extract", with(`(SELECT extract(day FROM now FROM {rel.g}))::text`, withRow("g")), []string{"now"}},
		{"slot then dot", with(`(SELECT count(*) FROM {rel.p}.directory_objects)::text`, withRel), []string{"p", "dot"}},
		{"anchor named public", with(`(SELECT count(*) FROM {rel.public}.directory_objects)::text`, withRow("public")), []string{"public"}},
		{"anchor named information_schema", withRow("information_schema"), []string{"information_schema"}},
		{"rel named public", func(d *report.Dataset) {
			d.Rels = append(d.Rels, report.Rel{ID: "public", Kind: report.RelEdge, Table: "group_links", Project: []report.Ident{"group_guid"}})
			d.Tables = append(d.Tables, "group_links")
		}, []string{"public"}},
	} {
		t.Run(c.name, func(t *testing.T) { refused(t, c.mut, c.want...) })
	}

	for name, sql := range map[string]string{
		"is distinct from":     `{t}.sam_account_name IS DISTINCT FROM {t}.display_name`,
		"is not distinct from": `{t}.sam_account_name IS NOT DISTINCT FROM {t}.display_name`,
		"one slot":             `(SELECT count(*) FROM {rel.p} WHERE {rel.p}.group_guid IS NOT NULL)::text`,
		"commas elsewhere":     `(SELECT coalesce(max({rel.p}.group_guid::text), 'x') FROM {rel.p} WHERE {rel.p}.group_guid = ANY (ARRAY[{t}.object_guid, {t}.object_guid]))::text`,
		"extract":              `extract(epoch FROM {t}.when_created)::text`,
	} {
		t.Run("ok "+name, func(t *testing.T) {
			ds := usersDataset()
			with(sql, withRel)(&ds)
			if _, err := reportsql.NewRegistry(opts(), ds); err != nil {
				t.Fatalf("refused: %v", err)
			}
		})
	}
}

func TestNewRegistry_fragments_the_allowlist_admits_what_datasets_need(t *testing.T) {
	for _, sql := range []string{
		`'not_locked'`,
		`CASE WHEN {t}.enabled IS NULL THEN 'unknown' WHEN {t}.lockout_time IS NULL THEN 'a' ELSE 'b' END`,
		`COALESCE({t}.logon_count, 0)::bigint + 1`,
		`CAST({t}.logon_count AS text)`,
		`{t}.kind IN ('user', 'group') AND NOT {t}.enabled OR {t}.sam_account_name ILIKE 'a%'`,
		`{t}.kind = ANY (ARRAY['user', 'it''s'])`,
		`GREATEST({t}.pwd_last_set, {now}) IS DISTINCT FROM {t}.lockout_time`,
		`EXTRACT(day FROM ({now} - {t}.pwd_last_set))`,
		`{now} - interval '90 days'`,
		`(SELECT count(*) FROM {rel.p} WHERE {rel.p}.group_guid = {t}.object_guid)`,
		`EXISTS (SELECT 1 FROM {rel.p} WHERE {rel.p}.member_guid = {t}.object_guid)`,
		`{t}.attributes ->> 'department'`,
		`LOWER({t}.sam_account_name) || 'x'`,
		`{t}.ancestry @> ARRAY[{t}.parent_guid]`,
		`{t}.groups IS NULL`,
		`1.5 * {t}.logon_count`,
	} {
		t.Run(sql, func(t *testing.T) {
			ds := usersDataset()
			ds.Rels = append(ds.Rels, report.Rel{ID: "p", Kind: report.RelEdge, Table: "group_links", Project: []report.Ident{"group_guid", "member_guid"}})
			ds.Tables = append(ds.Tables, "group_links")
			ds.Columns[2].Source = report.Derived{SQL: report.SQL(sql)}
			if _, err := reportsql.NewRegistry(opts(), ds); err != nil {
				t.Fatalf("the allowlist refused a fragment datasets need: %v", err)
			}
		})
	}
}

// AC 5: a secret attribute is not readable, whatever the definition says.
func TestNewRegistry_refuses_secret_json_keys(t *testing.T) {
	refused(t, func(d *report.Dataset) {
		d.Columns[0].Source = report.JSONAttr{Col: "attributes", Key: "unicodePwd", As: report.TypeText}
	}, "secret")
	refused(t, func(d *report.Dataset) {
		d.Columns[0].Source = report.JSONAttr{Col: "attributes", Key: "ntPwdHistory", As: report.TypeText}
	}, "secret")
	refused(t, func(d *report.Dataset) {
		d.Columns[0].Source = report.JSONAttr{Col: "attributes", Key: "whenCreated", As: report.TypeTime}
	}, "time")
	refused(t, func(d *report.Dataset) {
		d.Columns[0].Source = report.JSONAttr{Col: "sam_account_name", Key: "cn", As: report.TypeText}
	}, "json")
}

func TestNewRegistry_without_a_secret_predicate_fails_closed(t *testing.T) {
	_, err := reportsql.NewRegistry(reportsql.Options{Schema: schema}, usersDataset())
	if err == nil || !strings.Contains(err.Error(), "SecretKey") {
		t.Fatalf("err = %v", err)
	}
	if _, err := reportsql.NewRegistry(reportsql.Options{}, usersDataset()); err == nil {
		t.Fatal("a registry without a schema was built")
	}
}

func TestNewRegistry_refuses_duplicates_and_invalid_datasets(t *testing.T) {
	if _, err := reportsql.NewRegistry(opts(), usersDataset(), usersDataset()); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("duplicate: %v", err)
	}
	refused(t, func(d *report.Dataset) { d.RowKey = report.Fragment{} }, "row key")
}

func TestNewRegistry_RowAnchor_must_be_joined(t *testing.T) {
	refused(t, func(d *report.Dataset) {
		a := anchorT()
		a.ID = "other"
		d.Anchors = append(d.Anchors, a)
	}, "other", "joined")
}

// T-1033 (third security review): the allowlist admits what the inventory datasets write (CTEs, JOIN,
// derived tables, alias.col, substring … FROM … FOR) and still refuses every way to name a table.
func TestNewRegistry_CTE_JOIN_and_alias_rules(t *testing.T) {
	rels := func(d *report.Dataset) {
		for _, id := range []report.AnchorID{"p", "q"} {
			d.Rels = append(d.Rels, report.Rel{ID: id, Kind: report.RelEdge, Table: "group_links", Project: []report.Ident{"group_guid", "member_guid"},
				Where: report.SQL("link_kind = 'member' AND since IS NOT NULL")})
		}
		d.Tables = append(d.Tables, "group_links")
	}
	rowAnchor := func(d *report.Dataset) {
		a := anchorT()
		a.ID = "g"
		d.Anchors = append(d.Anchors, a)
		d.Base.Joins = append(d.Base.Joins, report.RowJoin{Anchor: "g", On: report.SQL("{rel.g}.object_guid = {t}.object_guid")})
	}
	build := func(sql string) report.Dataset {
		ds := usersDataset()
		rels(&ds)
		rowAnchor(&ds)
		ds.Columns[2].Source = report.Derived{SQL: report.SQL(sql)}
		return ds
	}
	for name, sql := range map[string]string{
		"cte":                  `(WITH x AS (SELECT p.group_guid AS g1 FROM {rel.p}) SELECT count(*) FROM x WHERE g1 IS NOT NULL)::text`,
		"cte columns":          `(WITH x(a, b) AS (SELECT p.group_guid, p.member_guid FROM {rel.p}) SELECT count(*) FROM x WHERE a = b)::text`,
		"recursive cte":        `(WITH RECURSIVE x(a) AS (SELECT p.group_guid FROM {rel.p} UNION SELECT p.group_guid FROM x JOIN {rel.p} ON p.member_guid = x.a) SELECT count(*) FROM x)::text`,
		"two ctes":             `(WITH x AS (SELECT 1 AS a), y AS (SELECT a FROM x) SELECT count(*) FROM y)::text`,
		"join rel":             `(SELECT count(*) FROM {rel.p} JOIN {rel.q} ON q.group_guid = p.group_guid)::text`,
		"left join rel":        `(SELECT count(*) FROM {rel.p} LEFT JOIN {rel.q} ON q.group_guid = p.group_guid WHERE q.group_guid IS NULL)::text`,
		"join cte":             `(WITH x AS (SELECT 1 AS a) SELECT count(*) FROM {rel.p} INNER JOIN x ON x.a = 1)::text`,
		"derived table":        `(SELECT s.n FROM (SELECT count(*) AS n FROM {rel.p}) s)::text`,
		"derived table as":     `(SELECT s.n FROM (SELECT count(*) AS n FROM {rel.p}) AS s LEFT JOIN {rel.q} ON true)::text`,
		"derived with":         `(SELECT s.n FROM (WITH x AS (SELECT 1 AS n) SELECT n FROM x) s)::text`,
		"order limit nulls":    `(SELECT p.group_guid FROM {rel.p} ORDER BY p.since NULLS FIRST, p.group_guid DESC LIMIT 1)::text`,
		"union all":            `(SELECT count(*) FROM (SELECT p.group_guid AS a FROM {rel.p} UNION ALL SELECT q.group_guid FROM {rel.q}) u)::text`,
		"substring from for":   `substring({t}.sam_account_name from 1 for 2)`,
		"substring from":       `substring({t}.sam_account_name from length({t}.sam_account_name) - 3)`,
		"nested substring":     `substring({t}.sam_account_name from position('=' in {t}.sam_account_name) + 1)`,
		"pure functions":       `left(lower(decode('f6010000', 'hex')::text), 7) || floor(1.5)::text || jsonb_typeof({t}.attributes -> 'a') || uuid_send({t}.object_guid)::text`,
		"jsonb array length":   `jsonb_array_length({t}.attributes -> 'a') > 0`,
		"alias dot star":       `(SELECT count(s.*) FROM (SELECT 1) s)::text`,
		"select alias used":    `(SELECT t2.one FROM (SELECT 1 AS one) t2)::text`,
		"row anchor as column": `{rel.g}.object_guid::text`,
	} {
		t.Run("ok "+name, func(t *testing.T) {
			if _, err := reportsql.NewRegistry(opts(), build(sql)); err != nil {
				t.Fatalf("refused: %v", err)
			}
		})
	}

	for _, c := range []struct{ name, sql, word string }{
		{"raw table beside a declared CTE", `(WITH x AS (SELECT 1 AS a) SELECT count(*) FROM x WHERE EXISTS (SELECT 1 FROM directory_objects))::text`, "directory_objects"},
		{"raw table in a CTE body", `(WITH x AS (SELECT 1 FROM directory_objects) SELECT count(*) FROM x)::text`, "directory_objects"},
		{"comma after a CTE item", `(WITH x AS (SELECT 1 AS a) SELECT count(*) FROM x, directory_objects)::text`, ","},
		{"undeclared name after from", `(WITH x AS (SELECT 1 AS a) SELECT count(*) FROM y)::text`, "y"},
		{"CTE named pg_class", `(WITH pg_class AS (SELECT 1 AS a) SELECT count(*) FROM pg_class)::text`, "pg_class"},
		{"CTE named public", `(WITH public AS (SELECT 1 AS a) SELECT count(*) FROM public)::text`, "public"},
		{"CTE named information_schema", `(WITH information_schema AS (SELECT 1 AS a) SELECT 1)::text`, "information_schema"},
		{"CTE named as a schema table", `(WITH group_links AS (SELECT 1 AS a) SELECT count(*) FROM group_links)::text`, "group_links"},
		{"CTE named as the dataset table", `(WITH directory_objects AS (SELECT 1 AS a) SELECT 1)::text`, "directory_objects"},
		{"CTE named as a relation ID", `(WITH p AS (SELECT 1 AS a) SELECT 1)::text`, "p"},
		{"CTE named as a function", `(WITH lower AS (SELECT 1 AS a) SELECT 1)::text`, "lower"},
		{"CTE column named as a table", `(WITH x(group_links) AS (SELECT 1) SELECT 1)::text`, "group_links"},
		{"CTE with an option", `(WITH x AS NOT MATERIALIZED (SELECT 1) SELECT 1)::text`, "AS"},
		{"CTE writes", `(WITH x AS (DELETE FROM directory_objects RETURNING 1) SELECT 1)::text`, "DELETE"},
		{"CTE name dotted", `(WITH x AS (SELECT 1 AS a) SELECT count(*) FROM x.directory_objects)::text`, "x"},
		{"join raw table", `(SELECT count(*) FROM {rel.p} JOIN directory_objects ON true)::text`, "directory_objects"},
		{"left join raw table", `(SELECT count(*) FROM {rel.p} LEFT JOIN directory_objects ON true)::text`, "directory_objects"},
		{"join a RowAnchor", `(SELECT count(*) FROM {rel.p} JOIN {rel.g} ON true)::text`, "RowAnchor"},
		{"join a dotted slot", `(SELECT count(*) FROM {rel.p} JOIN {rel.q}.directory_objects ON true)::text`, "dot"},
		{"comma after a join item", `(SELECT count(*) FROM {rel.p} JOIN {rel.q} ON true, t)::text`, ","},
		{"comma after a join item and a raw table", `(SELECT count(*) FROM {rel.p} JOIN {rel.q} ON true, directory_objects)::text`, ","},
		{"natural join", `(SELECT count(*) FROM {rel.p} NATURAL JOIN {rel.q})::text`, "NATURAL"},
		{"join function", `(SELECT count(*) FROM {rel.p} JOIN lower('x') ON true)::text`, "lower"},
		{"join lateral", `(SELECT count(*) FROM {rel.p} JOIN LATERAL (SELECT 1) x ON true)::text`, "LATERAL"},
		{"from only", `(SELECT count(*) FROM ONLY directory_objects)::text`, "ONLY"},
		{"derived table with a raw table", `(SELECT 1 FROM (SELECT 1 FROM directory_objects) s)::text`, "directory_objects"},
		{"derived alias is a table", `(SELECT 1 FROM (SELECT 1) group_links)::text`, "group_links"},
		{"derived alias is an ID", `(SELECT 1 FROM (SELECT 1) p)::text`, "p"},
		{"derived alias is a keyword", `(SELECT 1 FROM (SELECT 1) AS select)::text`, "select"},
		{"derived alias then a keyword the list lacks", `(SELECT 1 FROM (SELECT 1) s tablesample bernoulli (1))::text`, "alias"},
		{"substring over a raw table", `substring((SELECT 1 FROM directory_objects) from 1 for 2)`, "directory_objects"},
		{"substring select at its level", `substring(SELECT 1 FROM directory_objects)`, "directory_objects"},
		{"second from after substring", `(SELECT substring({t}.sam_account_name from 1 from directory_objects))::text`, "from"},
		{"for outside substring", `(SELECT 1 FROM {rel.p} FOR UPDATE)::text`, "for"},
		{"undeclared dotted name", `undeclared.col`, "undeclared"},
		{"undeclared dotted after a CTE", `(WITH x AS (SELECT 1 AS a) SELECT y.a FROM x)::text`, "y"},
		{"public dotted", `public.directory_objects`, "public"},
		{"pg_catalog dotted", `pg_catalog.pg_class`, "pg_catalog"},
		{"information_schema dotted", `information_schema.tables`, "information_schema"},
		{"dotted after a column", `{t}.attributes.x.y`, "dotted"},
		{"alias.col.field", `(SELECT s.a.b FROM (SELECT 1 AS a) s)::text`, "dotted"},
		{"undeclared bare word", `(SELECT zzz FROM {rel.p})::text`, "zzz"},
		{"cast to a declared alias", `(SELECT 'x'::regclass AS regclass FROM {rel.p})::text`, "regclass"},
		{"CAST to a declared alias", `(SELECT CAST('x' AS regclass) AS regclass FROM {rel.p})::text`, "fragTypes"},
		{"typed literal of a declared alias", `(SELECT regclass 'directory_objects' AS regclass FROM {rel.p})::text`, "regclass"},
		{"second union branch reads a raw table", `(SELECT 1 FROM {rel.p} UNION SELECT 1 FROM directory_objects)::text`, "directory_objects"},
		{"second union branch comma", `(SELECT 1 FROM {rel.p} UNION SELECT 1 FROM {rel.p}, {rel.q})::text`, ","},
		{"line comment", "(SELECT 1 FROM {rel.p} -- x\n)::text", "--"},
		{"block comment", `(SELECT 1 FROM /* x */ {rel.p})::text`, "/*"},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := reportsql.NewRegistry(opts(), build(c.sql))
			if err == nil {
				t.Fatalf("NewRegistry accepted %s", c.sql)
			}
			if !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(c.word)) {
				t.Fatalf("error %q does not name %q", err, c.word)
			}
		})
	}

	// The session and clock words are refused by name, wherever they stand.
	for _, w := range []string{"current_user", "session_user", "user", "current_role", "current_schema", "current_catalog",
		"current_timestamp", "current_date", "current_time", "localtime", "localtimestamp", "system_user"} {
		for _, sql := range []string{w + "::text", "(SELECT " + w + " FROM {rel.p})::text", "COALESCE(" + w + "::text, 'x')"} {
			t.Run(w+" in "+sql, func(t *testing.T) {
				_, err := reportsql.NewRegistry(opts(), build(sql))
				if err == nil || !strings.Contains(err.Error(), w) {
					t.Fatalf("err = %v; want an error naming %q", err, w)
				}
			})
		}
	}
}
