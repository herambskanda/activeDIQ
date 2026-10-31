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
