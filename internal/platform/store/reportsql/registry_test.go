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
		{`(WITH x AS (SELECT 1) SELECT 1)`, "WITH"},
		{`kind`, "kind"},
		{`(SELECT 1 FROM group_links)`, "group_links"},
		{`(SELECT 1 FROM Directory_Objects)`, "Directory_Objects"},
		{`(SELECT 1 FROM (SELECT 1) x)`, "from"},
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
		{"alias distinct", with(`(SELECT count(*) AS distinct FROM {rel.g})::text`, withRow("g")), []string{"g", "RowAnchor"}},
		{"alias distinct over a Rel", with(`(SELECT count(*) AS distinct FROM x)::text`, withRel), []string{"x", "from"}},
		{"not distinct alias", with(`(SELECT count(*) AS not distinct FROM {rel.g})::text`, withRow("g")), []string{"g", "RowAnchor"}},
		{"comma item", with(`(SELECT count(*) FROM {rel.p}, {rel.p})::text`, withRel), []string{","}},
		{"comma item after where", with(`(SELECT count(*) FROM {rel.p} WHERE true, {rel.p})::text`, withRel), []string{","}},
		{"comma item bare table", with(`(SELECT count(*) FROM {rel.p}, day)::text`, withRel), []string{","}},
		{"second from after extract", with(`(SELECT extract(day FROM now FROM {rel.g}))::text`, withRow("g")), []string{"now"}},
		{"slot then dot", with(`(SELECT count(*) FROM {rel.p}.directory_objects)::text`, withRel), []string{"p", "dot"}},
		{"anchor named public", with(`(SELECT count(*) AS distinct FROM {rel.public}.directory_objects)::text`, withRow("public")), []string{"public"}},
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
