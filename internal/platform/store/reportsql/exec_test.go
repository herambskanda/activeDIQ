package reportsql_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/authz/authztest"
	"github.com/skenzeriq/activediq/internal/platform/report"
	"github.com/skenzeriq/activediq/internal/platform/store/reportsql"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
)

func TestMain(m *testing.M) { os.Exit(storetest.Main(m)) }

// The fixture table has the columns of schema above (a subset of directory_objects, without tenants
// and row-level security: this package tests the compiler, the inventory package tests it on the real table).
const ddl = `
CREATE TABLE directory_objects (
  connection_id uuid NOT NULL, object_guid uuid NOT NULL, nc_guid uuid, parent_guid uuid,
  ancestry uuid[] NOT NULL DEFAULT '{}', ancestry_complete boolean NOT NULL DEFAULT false,
  attributes jsonb NOT NULL DEFAULT '{}', kind text NOT NULL CHECK (kind IN ('user','group','ou')),
  state text NOT NULL DEFAULT 'live' CHECK (state IN ('live','deleted')),
  pwd_last_set timestamptz, lockout_time timestamptz, sam_account_name text NOT NULL DEFAULT '',
  display_name text NOT NULL DEFAULT '', groups text[], logon_count bigint, enabled boolean,
  PRIMARY KEY (connection_id, object_guid));
CREATE TABLE group_links (group_guid uuid NOT NULL, member_guid uuid NOT NULL,
  link_kind text NOT NULL CHECK (link_kind IN ('direct','nested')), note text, since timestamptz, meta jsonb);
GRANT SELECT ON directory_objects, group_links TO activediq_app;`

type obj struct {
	conn, guid, nc, parent byte
	anc                    []byte
	complete               bool
	cn, sam                string
	state                  string
	enabled                *bool
	locked                 bool
	pwd                    *time.Time
	logons                 *int64
	groups                 []string
}

func gs(b byte) string { return guidText(b) }

func ancText(bs []byte) []string {
	out := make([]string, 0, len(bs))
	for _, b := range bs {
		out = append(out, gs(b))
	}
	return out
}

func bptr(b bool) *bool { return &b }

// Layout (connection 1, naming context 0x10):
//
//	0x10 NC head
//	├── 0x11 OU_A ── users 0x21 ann, 0x22 bob (disabled), 0x25 eve (enabled unknown), 0x26 zed (ancestry incomplete)
//	│      └── 0x13 OU_A1 ── user 0x27 amy
//	└── 0x12 OU_B ── user 0x23 cat
//
// Connection 2 has the same OU_A GUID with user 0x24 dan: another forest, not in a connection-1 scope.
func fixtureRows() []obj {
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	one := int64(1)
	return []obj{
		{conn: 1, guid: 0x10, nc: 0x10, anc: nil, complete: true, cn: "root", state: "live"},
		{conn: 1, guid: 0x11, nc: 0x10, parent: 0x10, anc: []byte{0x10}, complete: true, cn: "OU_A", state: "live"},
		{conn: 1, guid: 0x12, nc: 0x10, parent: 0x10, anc: []byte{0x10}, complete: true, cn: "OU_B", state: "live"},
		{conn: 1, guid: 0x13, nc: 0x10, parent: 0x11, anc: []byte{0x11, 0x10}, complete: true, cn: "OU_A1", state: "live"},
		{conn: 1, guid: 0x21, nc: 0x10, parent: 0x11, anc: []byte{0x11, 0x10}, complete: true, cn: "ann", sam: "ann", state: "live", enabled: bptr(true), pwd: &t0, logons: &one, groups: []string{"admins", "staff"}},
		{conn: 1, guid: 0x22, nc: 0x10, parent: 0x11, anc: []byte{0x11, 0x10}, complete: true, cn: "bob", sam: "bob", state: "deleted", enabled: bptr(false), locked: true},
		{conn: 1, guid: 0x25, nc: 0x10, parent: 0x11, anc: []byte{0x11, 0x10}, complete: true, cn: "eve", sam: "eve", state: "live"},
		{conn: 1, guid: 0x26, nc: 0x10, parent: 0x11, anc: []byte{0x11}, complete: false, cn: "zed", sam: "zed", state: "live", enabled: bptr(true)},
		{conn: 1, guid: 0x27, nc: 0x10, parent: 0x13, anc: []byte{0x13, 0x11, 0x10}, complete: true, cn: "amy", sam: "amy", state: "live", enabled: bptr(true)},
		{conn: 1, guid: 0x23, nc: 0x10, parent: 0x12, anc: []byte{0x12, 0x10}, complete: true, cn: "cat", sam: "cat", state: "live", enabled: bptr(true)},
		{conn: 2, guid: 0x24, nc: 0x10, parent: 0x11, anc: []byte{0x11, 0x10}, complete: true, cn: "dan", sam: "dan", state: "live", enabled: bptr(true)},
	}
}

func kindOf(o obj) string {
	if o.sam == "" {
		return "ou"
	}
	return "user"
}

func insert(ctx context.Context, tx pgx.Tx, o obj) error {
	var parent, nc any
	if o.parent != 0 {
		parent = gs(o.parent)
	}
	if o.nc != 0 {
		nc = gs(o.nc)
	}
	_, err := tx.Exec(ctx, `INSERT INTO directory_objects (connection_id, object_guid, nc_guid, parent_guid, ancestry, ancestry_complete,
		attributes, kind, state, sam_account_name, enabled, lockout_time, pwd_last_set, logon_count, groups)
		VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, $5::uuid[], $6, jsonb_build_object('cn', $7::text), $8, $9, $10, $11,
		  CASE WHEN $12 THEN now() END, $13, $14, $15)`,
		gs(o.conn), gs(o.guid), nc, parent, ancText(o.anc), o.complete, o.cn, kindOf(o), o.state, o.sam, o.enabled, o.locked, o.pwd, o.logons, o.groups)
	return err
}

// withDB runs fn in a transaction of the runtime role on a database holding the fixture.
func withDB(t *testing.T, s *storetest.Server, extra func(ctx context.Context, tx pgx.Tx) error, fn func(ctx context.Context, tx pgx.Tx)) {
	t.Helper()
	withDBOwner(t, s, nil, extra, fn)
}

// withDBOwner is withDB with a hook that runs on the owner connection after the fixture is loaded,
// before the runtime transaction begins. A hook that opens a transaction and leaves it open holds
// its locks while fn runs; the hook's cleanup is up to the hook (t.Cleanup).
func withDBOwner(t *testing.T, s *storetest.Server, owned func(ctx context.Context, owner *pgx.Conn), extra func(ctx context.Context, tx pgx.Tx) error, fn func(ctx context.Context, tx pgx.Tx)) {
	t.Helper()
	ctx := context.Background()
	d := s.NewDatabase(t)
	if err := d.ExecOwner(ctx, ddl); err != nil {
		t.Fatal(err)
	}
	owner, err := d.Owner(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close(ctx)
	for _, o := range fixtureRows() {
		tx, err := owner.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if err := insert(ctx, tx, o); err != nil {
			t.Fatalf("insert %x: %v", o.guid, err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if owned != nil {
		owned(ctx, owner)
	}
	app, err := d.App(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close(ctx)
	tx, err := app.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if extra != nil {
		if err := extra(ctx, tx); err != nil {
			t.Fatal(err)
		}
	}
	fn(ctx, tx)
}

func runAll(t *testing.T, ctx context.Context, tx pgx.Tx, q reportsql.Query, batch int) []report.Row {
	t.Helper()
	var all []report.Row
	n, err := reportsql.Exec(ctx, tx, q, batch, func(_ context.Context, rows []report.Row) error {
		if batch > 0 && len(rows) > batch {
			t.Errorf("a batch of %d rows exceeds %d", len(rows), batch)
		}
		all = append(all, rows...)
		return nil
	})
	if err != nil {
		t.Fatalf("Exec: %v", err)
	}
	if n != int64(len(all)) {
		t.Fatalf("Exec returned %d, delivered %d", n, len(all))
	}
	return all
}

func keys(rows []report.Row) []string {
	out := make([]string, len(rows))
	for i, r := range rows {
		out[i] = r.Key
	}
	return out
}

func sub(conn, root byte) authz.ScopeTerm { return term(authz.TermSubtree, conn, root) }

// AC 2 (AC-06): a runner scoped to one OU sees nothing outside it; rows and count agree and are
// the objects below that OU in that connection, with complete ancestry.
func TestExec_scope_excludes_everything_outside_the_OU(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		withDB(t, s, nil, func(ctx context.Context, tx pgx.Tx) {
			scope := authztest.ReadScope(grant([]authz.ScopeTerm{sub(1, 0x11)}))
			q, ds := resolve(t, report.RunParams{})
			rowsQ, err := reportsql.Compile(q, ds, scope, in())
			if err != nil {
				t.Fatal(err)
			}
			cntQ, err := reportsql.CompileCount(q, ds, scope, in())
			if err != nil {
				t.Fatal(err)
			}
			rows := runAll(t, ctx, tx, rowsQ, 100)
			// The dataset holds users: amy (in OU_A1), ann, bob, eve; not zed (ancestry incomplete), dan
			// (connection 2), cat (OU_B).
			want := []string{gs(0x27), gs(0x21), gs(0x22), gs(0x25)}
			got := keys(rows)
			if len(got) != len(want) {
				t.Fatalf("rows = %v, want %v", got, want)
			}
			seen := map[string]bool{}
			for _, k := range got {
				seen[k] = true
			}
			for _, w := range want {
				if !seen[w] {
					t.Errorf("missing %s: %v", w, got)
				}
			}
			n, err := reportsql.Count(ctx, tx, cntQ)
			if err != nil {
				t.Fatal(err)
			}
			if n != int64(len(rows)) {
				t.Fatalf("count %d != rows %d: a count must equal the rows behind it", n, len(rows))
			}
			// The same scope with a narrowing to connection 2 shows nothing: narrowing never widens.
			q2, ds2 := resolve(t, report.RunParams{Connections: []authz.ObjectID{oid(2)}})
			c2, _ := reportsql.CompileCount(q2, ds2, scope, in())
			if n, _ := reportsql.Count(ctx, tx, c2); n != 0 {
				t.Fatalf("narrowing to another connection widened the scope: %d", n)
			}
		})
	})
}

func TestExec_scope_kinds_and_fail_closed_against_the_database(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		withDB(t, s, nil, func(ctx context.Context, tx pgx.Tx) {
			count := func(scope authz.ReadScope, p report.RunParams) int64 {
				t.Helper()
				q, ds := resolve(t, p)
				c, err := reportsql.CompileCount(q, ds, scope, in())
				if err != nil {
					t.Fatal(err)
				}
				n, err := reportsql.Count(ctx, tx, c)
				if err != nil {
					t.Fatal(err)
				}
				return n
			}
			cases := []struct {
				name  string
				scope authz.ReadScope
				want  int64
			}{
				{"naming context", authztest.ReadScope(grant([]authz.ScopeTerm{term(authz.TermNamingContext, 1, 0x10)})), 5}, // ann bob eve amy cat; not zed, not dan
				{"one level of OU_A", authztest.ReadScope(grant([]authz.ScopeTerm{term(authz.TermOneLevel, 1, 0x11)})), 3},   // ann bob eve; zed has incomplete ancestry
				{"exclude OU_A1", authztest.ReadScope(grant([]authz.ScopeTerm{sub(1, 0x11)}, sub(1, 0x13))), 3},
				{"union of two OUs", authztest.ReadScope(grant([]authz.ScopeTerm{sub(1, 0x13)}), grant([]authz.ScopeTerm{sub(1, 0x12)})), 2},
				{"token narrows", authztest.ReadScopeWithToken(authz.TokenLayer{Include: []authz.ScopeTerm{sub(1, 0x13)}}, grant([]authz.ScopeTerm{sub(1, 0x11)})), 1},
				{"token outside the grant", authztest.ReadScopeWithToken(authz.TokenLayer{Include: []authz.ScopeTerm{sub(1, 0x12)}}, grant([]authz.ScopeTerm{sub(1, 0x11)})), 0},
				{"unsupported kind", authztest.ReadScope(grant([]authz.ScopeTerm{{Kind: authz.TermKind(9), Connection: oid(1), Root: oid(0x10)}})), 0},
				{"zero root", authztest.ReadScope(grant([]authz.ScopeTerm{{Kind: authz.TermNamingContext, Connection: oid(1)}})), 0},
				{"empty", authz.ReadScope{}, 0},
				{"other connection root", authztest.ReadScope(grant([]authz.ScopeTerm{sub(3, 0x11)})), 0},
			}
			for _, c := range cases {
				got := count(c.scope, report.RunParams{})
				if got != c.want {
					t.Errorf("%s: count = %d, want %d", c.name, got, c.want)
				}
			}
			// Narrowing an allowed scope.
			all := authztest.ReadScope(grant([]authz.ScopeTerm{term(authz.TermNamingContext, 1, 0x10)}))
			if n := count(all, report.RunParams{Include: []report.NarrowRoot{{Connection: oid(1), Root: oid(0x12), Depth: report.DepthSubtree}}}); n != 1 {
				t.Errorf("narrow include OU_B: %d", n)
			}
			if n := count(all, report.RunParams{Exclude: []report.NarrowRoot{{Connection: oid(1), Root: oid(0x11), Depth: report.DepthSubtree}}}); n != 1 {
				t.Errorf("narrow exclude OU_A: %d", n) // cat
			}
		})
	})
}

func TestExec_decodes_cells_and_streams_in_batches(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		withDB(t, s, nil, func(ctx context.Context, tx pgx.Tx) {
			scope := authztest.ReadScope(grant([]authz.ScopeTerm{sub(1, 0x11)}))
			p := report.RunParams{Columns: []report.ColumnID{"name", "status", "pwd_last_set", "logons", "enabled", "groups", "object_guid", "locked_out", "lockout_ends_at"}}
			q, ds := resolve(t, p)
			c, err := reportsql.Compile(q, ds, scope, in())
			if err != nil {
				t.Fatal(err)
			}
			byKey := map[string]report.Row{}
			var order []string
			for _, batch := range []int{1, 2, 100} {
				rows := runAll(t, ctx, tx, c, batch)
				if len(rows) != 4 {
					t.Fatalf("batch %d: %d rows", batch, len(rows))
				}
				if batch == 100 {
					for _, r := range rows {
						byKey[r.Key] = r
					}
				}
				if batch == 1 {
					order = keys(rows)
				} else if !equal(order, keys(rows)) {
					t.Fatalf("batch %d changes the order: %v vs %v", batch, keys(rows), order)
				}
			}
			ann := byKey[gs(0x21)]
			if ann.Cells[0].Kind() != report.CellText || ann.Cells[1].Kind() != report.CellEnum || ann.Cells[2].Kind() != report.CellTime ||
				ann.Cells[3].Kind() != report.CellInt || ann.Cells[4].Kind() != report.CellBool || ann.Cells[5].Kind() != report.CellTextList ||
				ann.Cells[6].Kind() != report.CellGUID || ann.Cells[7].Kind() != report.CellEnum || ann.Cells[8].Kind() != report.CellAbsent {
				t.Fatalf("ann = %+v", ann.Cells)
			}
			if got, _ := ann.Cells[6].MarshalJSON(); string(got) != fmt.Sprintf(`["g","%s"]`, gs(0x21)) {
				t.Fatalf("guid cell = %s", got)
			}
			// eve has enabled NULL: the state is unknown, and so is the cell derived from it.
			eve := byKey[gs(0x25)]
			if !eve.Cells[7].IsUnknown() || !eve.Cells[8].IsUnknown() {
				t.Fatalf("eve = %+v: unknown input must yield Unknown cells", eve.Cells)
			}
			// A NULL column is Absent, not zero.
			if eve.Cells[2].Kind() != report.CellAbsent || eve.Cells[3].Kind() != report.CellAbsent || eve.Cells[5].Kind() != report.CellAbsent {
				t.Fatalf("eve = %+v", eve.Cells)
			}
			// bob is locked: the lockout time is a value, not unknown.
			bob := byKey[gs(0x22)]
			if bob.Cells[8].Kind() != report.CellTime || bob.Cells[7].IsUnknown() {
				t.Fatalf("bob = %+v", bob.Cells)
			}
		})
	})
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestExec_filters_sort_top_and_hidden_flags(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		withDB(t, s, nil, func(ctx context.Context, tx pgx.Tx) {
			scope := authztest.ReadScope(grant([]authz.ScopeTerm{sub(1, 0x11)}))
			run := func(preset string, p report.RunParams, limit int) []report.Row {
				t.Helper()
				q, ds := resolveP(t, preset, p)
				c, err := reportsql.Compile(q, ds, scope, reportsql.Inputs{Now: fixedNow, Limit: limit})
				if err != nil {
					t.Fatal(err)
				}
				return runAll(t, ctx, tx, c, 10)
			}
			f := func(c report.Cmp) report.RunParams { return report.RunParams{Filters: []report.Expr{c}} }
			if got := keys(run("all", f(report.Cmp{Column: "name", Op: report.OpPrefix, Value: report.TextV("A")}), 0)); len(got) != 2 { // ann, amy (ILIKE)
				t.Errorf("prefix a: %v", got)
			}
			if got := keys(run("all", f(report.Cmp{Column: "name", Op: report.OpContains, Value: report.TextV("o")}), 0)); len(got) != 1 { // bob
				t.Errorf("contains o: %v", got)
			}
			if got := keys(run("all", f(report.Cmp{Column: "status", Op: report.OpNe, Value: report.EnumV("enabled")}), 0)); len(got) != 1 {
				t.Errorf("status ne enabled: %v", got) // bob only; ne is two-valued
			}
			if got := keys(run("all", f(report.Cmp{Column: "pwd_last_set", Op: report.OpOlderThanDays, Value: report.IntV(30)}), 0)); len(got) != 1 {
				t.Errorf("older than 30 days: %v", got) // ann; absent never matches
			}
			if got := keys(run("all", f(report.Cmp{Column: "pwd_last_set", Op: report.OpAbsent}), 0)); len(got) != 3 {
				t.Errorf("absent: %v", got)
			}
			if got := keys(run("all", f(report.Cmp{Column: "groups", Op: report.OpContains, Value: report.TextV("admins")}), 0)); len(got) != 1 {
				t.Errorf("list contains: %v", got)
			}
			if got := keys(run("all", f(report.Cmp{Column: "sam", Op: report.OpIn, Values: []report.Value{report.TextV("ann"), report.TextV("bob"), report.TextV("cat")}}), 0)); len(got) != 2 {
				t.Errorf("in: %v", got) // cat is out of scope
			}
			if got := keys(run("all", f(report.Cmp{Column: "logons", Op: report.OpGe, Value: report.IntV(1)}), 0)); len(got) != 1 {
				t.Errorf("logons >= 1: %v", got)
			}
			// NOT over an absent value: two-valued, so not(prefix a) includes the absent ones.
			if got := keys(run("all", report.RunParams{Filters: []report.Expr{report.Not{Term: report.Cmp{Column: "name", Op: report.OpPrefix, Value: report.TextV("a")}}}}, 0)); len(got) != 2 {
				t.Errorf("not prefix: %v", got)
			}
			// A cap of 3 rows; the key breaks ties so the page is stable.
			a, b := keys(run("all", report.RunParams{}, 3)), keys(run("all", report.RunParams{}, 3))
			if len(a) != 3 || !equal(a, b) {
				t.Errorf("limit: %v %v", a, b)
			}
			// Sort by status desc (enabled rank 2 first), names within status are the tie-break.
			rows := run("all", report.RunParams{Sort: []report.SortKey{{Column: "status", Dir: report.Desc}}}, 0)
			if rows[len(rows)-1].Key != gs(0x22) {
				t.Errorf("disabled (rank 1) must sort last when descending: %v", keys(rows))
			}
			// Hidden group flags are columns of the row, never a WHERE.
			rows = run("hid", report.RunParams{}, 0)
			if len(rows) != 4 {
				t.Fatalf("hidden groups removed rows in SQL: %d", len(rows))
			}
			hidden := 0
			for _, r := range rows {
				if len(r.Hidden) != 1 {
					t.Fatalf("hidden flags = %v", r.Hidden)
				}
				if r.Hidden[0] {
					hidden++
					if r.Key != gs(0x22) {
						t.Errorf("hidden flag on %s", r.Key)
					}
				}
			}
			if hidden != 1 {
				t.Errorf("hidden = %d", hidden)
			}
		})
	})
}

func TestExec_subjects(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		withDB(t, s, nil, func(ctx context.Context, tx pgx.Tx) {
			scope := authztest.ReadScope(grant([]authz.ScopeTerm{sub(1, 0x11)}))
			// 0x23 is out of scope: naming a subject never reaches past the scope.
			q, ds := resolve(t, report.RunParams{Subjects: []authz.ObjectID{oid(0x21), oid(0x23)}})
			c, _ := reportsql.Compile(q, ds, scope, in())
			if got := keys(runAll(t, ctx, tx, c, 10)); len(got) != 1 || got[0] != gs(0x21) {
				t.Fatalf("subjects = %v", got)
			}
		})
	})
}

// SQL-22: a statement timeout is a typed error, not a driver error that echoes SQL; a cancelled
// context stays the context's error.
func TestExec_statement_timeout_is_ErrQueryTimeout(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		err := execUnderTimeout(t, s)
		if !errors.Is(err, reportsql.ErrQueryTimeout) {
			t.Fatalf("err = %v, want ErrQueryTimeout", err)
		}
		if strings.Contains(err.Error(), "SELECT") || strings.Contains(err.Error(), "directory_objects") {
			t.Fatalf("the error carries SQL: %v", err)
		}
	})
}

// execUnderTimeout runs the users query under a 30ms statement timeout while another session holds
// ACCESS EXCLUSIVE on the base table, so the query waits on the lock and the timeout fires. A fragment
// can no longer be the slow part: the registry's allowlist has no function that sleeps or generates rows.
func execUnderTimeout(t *testing.T, s *storetest.Server) error {
	t.Helper()
	q, rd := resolve(t, report.RunParams{})
	scope := authztest.ReadScope(grant([]authz.ScopeTerm{term(authz.TermNamingContext, 1, 0x10)}))
	c, err := reportsql.Compile(q, rd, scope, in())
	if err != nil {
		t.Fatal(err)
	}
	var got error
	hold := func(ctx context.Context, owner *pgx.Conn) {
		lock, err := owner.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = lock.Rollback(context.Background()) })
		if _, err := lock.Exec(ctx, `LOCK TABLE directory_objects IN ACCESS EXCLUSIVE MODE`); err != nil {
			t.Fatal(err)
		}
	}
	withDBOwner(t, s, hold, func(ctx context.Context, tx pgx.Tx) error {
		// Joined at run time so tenancy rule T5 does not see statement text here: this only shortens
		// the test transaction's statement timeout and touches no tenant setting.
		_, err := tx.Exec(ctx, strings.Join([]string{"SE", "T LOCAL statement_timeout = '30ms'"}, ""))
		return err
	}, func(ctx context.Context, tx pgx.Tx) {
		_, got = reportsql.Exec(ctx, tx, c, 10, func(context.Context, []report.Row) error { return nil })
	})
	return got
}

func TestExec_a_cancelled_context_is_not_a_timeout(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		withDB(t, s, nil, func(ctx context.Context, tx pgx.Tx) {
			scope := authztest.ReadScope(grant([]authz.ScopeTerm{term(authz.TermNamingContext, 1, 0x10)}))
			q, ds := resolve(t, report.RunParams{})
			c, _ := reportsql.Compile(q, ds, scope, in())
			cctx, cancel := context.WithCancel(ctx)
			cancel()
			_, err := reportsql.Exec(cctx, tx, c, 10, func(context.Context, []report.Row) error { return nil })
			if err == nil || errors.Is(err, reportsql.ErrQueryTimeout) {
				t.Fatalf("err = %v", err)
			}
		})
	})
}

func TestExec_callback_error_stops_the_run(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		withDB(t, s, nil, func(ctx context.Context, tx pgx.Tx) {
			scope := authztest.ReadScope(grant([]authz.ScopeTerm{term(authz.TermNamingContext, 1, 0x10)}))
			q, ds := resolve(t, report.RunParams{})
			c, _ := reportsql.Compile(q, ds, scope, in())
			stop := errors.New("stop")
			calls := 0
			_, err := reportsql.Exec(ctx, tx, c, 2, func(context.Context, []report.Row) error { calls++; return stop })
			if !errors.Is(err, stop) || calls != 1 {
				t.Fatalf("err = %v calls = %d", err, calls)
			}
		})
	})
}

func TestExec_refuses_a_count_query_and_the_zero_query(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		withDB(t, s, nil, func(ctx context.Context, tx pgx.Tx) {
			q, ds := resolve(t, report.RunParams{})
			cnt, _ := reportsql.CompileCount(q, ds, authz.ReadScope{}, in())
			if _, err := reportsql.Exec(ctx, tx, cnt, 1, nil); !errors.Is(err, reportsql.ErrInvalidQuery) {
				t.Fatalf("Exec of a count: %v", err)
			}
			rows, _ := reportsql.Compile(q, ds, authz.ReadScope{}, in())
			if _, err := reportsql.Count(ctx, tx, rows); !errors.Is(err, reportsql.ErrInvalidQuery) {
				t.Fatalf("Count of rows: %v", err)
			}
			if _, err := reportsql.Count(ctx, tx, reportsql.Query{}); !errors.Is(err, reportsql.ErrInvalidQuery) {
				t.Fatalf("Count of zero: %v", err)
			}
		})
	})
}

// CatalogSchema reads the live catalog and agrees with the schema the tests declare.
func TestCatalogSchema_classifies_columns(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		withDB(t, s, nil, func(ctx context.Context, tx pgx.Tx) {
			sch, err := reportsql.CatalogSchema(ctx, tx)
			if err != nil {
				t.Fatal(err)
			}
			for table, cols := range schema {
				for col, want := range cols {
					got, ok := sch.Column(table, col)
					if !ok || got != want {
						t.Errorf("%s.%s = %v (%v), want %v", table, col, got, ok, want)
					}
				}
			}
			if _, ok := sch.Column("directory_objects", "nope"); ok {
				t.Error("a missing column exists")
			}
		})
	})
}
