package preflight_test

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/jackc/pgx/v5"

	"github.com/skenzeriq/activediq/internal/platform/store/preflight"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
	"github.com/skenzeriq/activediq/migrations"
)

func TestMain(m *testing.M) { os.Exit(storetest.Main(m)) }

// rows answers the three preflight queries in order from canned values: no database, so the branches that
// a real server cannot be put into (a superuser-only extension) are still pinned.
type rows struct {
	version                           int
	available, installed, creatable   bool
	super                             bool
	encoding, provider, ctype, locale string
}

type row struct{ vals []any }

func (r row) Scan(dest ...any) error {
	for i, d := range dest {
		switch p := d.(type) {
		case *int:
			*p = r.vals[i].(int)
		case *bool:
			*p = r.vals[i].(bool)
		case *string:
			*p = r.vals[i].(string)
		}
	}
	return nil
}

func (f rows) QueryRow(_ context.Context, sql string, _ ...any) pgx.Row {
	switch {
	case strings.Contains(sql, "server_version_num"):
		return row{[]any{f.version}}
	case strings.Contains(sql, "pg_available_extensions"):
		return row{[]any{f.available, f.installed, f.creatable, f.super}}
	default:
		return row{[]any{f.encoding, f.provider, f.ctype, f.locale}}
	}
}

func good() rows {
	return rows{version: 160014, available: true, creatable: true, encoding: "UTF8", provider: "c", ctype: "en_US.utf8"}
}

func refusalCodes(t *testing.T, err error) []preflight.Code {
	t.Helper()
	var out []preflight.Code
	for _, e := range unwrapAll(err) {
		var r *preflight.Refusal
		if !errors.As(e, &r) {
			t.Fatalf("not a Refusal: %v", e)
		}
		out = append(out, r.Code)
	}
	return out
}

func unwrapAll(err error) []error {
	if err == nil {
		return nil
	}
	if j, ok := err.(interface{ Unwrap() []error }); ok {
		return j.Unwrap()
	}
	return []error{err}
}

func TestCheckBranches(t *testing.T) {
	ctx := context.Background()
	t.Run("passes", func(t *testing.T) {
		rep, err := preflight.Check(ctx, good())
		if err != nil || len(rep.Warnings) != 0 {
			t.Fatalf("err=%v warnings=%v", err, rep.Warnings)
		}
	})
	t.Run("missing extension names pg_trgm and the contrib package", func(t *testing.T) {
		f := good()
		f.available, f.creatable = false, false
		_, err := preflight.Check(ctx, f)
		if c := refusalCodes(t, err); len(c) != 1 || c[0] != preflight.CodeExtensionMissing {
			t.Fatalf("codes = %v", c)
		}
		for _, want := range []string{"pg_trgm", "contrib", "allow-list", "Nothing has been changed"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("message lacks %q: %v", want, err)
			}
		}
	})
	t.Run("already installed passes even if the package is gone", func(t *testing.T) {
		f := good()
		f.available, f.installed, f.creatable = false, true, false
		if _, err := preflight.Check(ctx, f); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("superuser-only extension and a plain owner is refused", func(t *testing.T) {
		f := good()
		f.creatable = false
		_, err := preflight.Check(ctx, f)
		if c := refusalCodes(t, err); len(c) != 1 || c[0] != preflight.CodeExtensionNotCreatable {
			t.Fatalf("codes = %v (%v)", c, err)
		}
		f.super = true
		if _, err := preflight.Check(ctx, f); err != nil {
			t.Fatalf("a superuser owner can create it: %v", err)
		}
	})
	t.Run("non-UTF8 is refused and reported with the extension problem", func(t *testing.T) {
		f := good()
		f.available, f.creatable, f.encoding = false, false, "LATIN1"
		_, err := preflight.Check(ctx, f)
		c := refusalCodes(t, err)
		if len(c) != 2 || c[0] != preflight.CodeExtensionMissing || c[1] != preflight.CodeEncoding {
			t.Fatalf("codes = %v", c)
		}
	})
	t.Run("C and POSIX ctype warn, never refuse", func(t *testing.T) {
		for _, c := range []struct{ provider, ctype, locale string }{{"c", "C", ""}, {"c", "POSIX", ""}, {"b", "C.UTF-8", "C"}} {
			f := good()
			f.provider, f.ctype, f.locale = c.provider, c.ctype, c.locale
			f.version = 180000
			rep, err := preflight.Check(ctx, f)
			if err != nil || len(rep.Warnings) != 1 {
				t.Fatalf("%+v: err=%v warnings=%v", c, err, rep.Warnings)
			}
		}
		f := good()
		f.provider, f.ctype, f.locale, f.version = "b", "C.UTF-8", "C.UTF-8", 180000
		if rep, err := preflight.Check(ctx, f); err != nil || len(rep.Warnings) != 0 {
			t.Fatalf("builtin C.UTF-8 must pass quietly: err=%v warnings=%v", err, rep.Warnings)
		}
	})
}

// renameExt answers the catalog queries on a real server as if the extension had another name, which is
// what a PostgreSQL without the contrib package looks like to the preflight (AC1's "stubbed catalog query").
type renameExt struct{ *pgx.Conn }

func (r renameExt) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	if len(args) == 1 && args[0] == preflight.Extension {
		args = []any{"pg_trgm_not_shipped"}
	}
	return r.Conn.QueryRow(ctx, sql, args...)
}

func objectCount(t *testing.T, db *storetest.Database) string {
	t.Helper()
	got, err := db.OwnerStrings(context.Background(),
		`SELECT (SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'public')::text
		      || '/' || (SELECT count(*) FROM pg_extension WHERE extname = 'pg_trgm')::text`)
	if err != nil || len(got) != 1 {
		t.Fatal(err)
	}
	return got[0]
}

func TestRealServers(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		ctx := context.Background()

		t.Run("pinned image passes and CREATE EXTENSION works as the non-superuser owner", func(t *testing.T) {
			db := s.NewDatabase(t)
			c, err := db.Owner(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close(ctx)
			rep, err := preflight.Check(ctx, c)
			if err != nil {
				t.Fatalf("preflight refused the pinned image: %v", err)
			}
			if rep.Encoding != "UTF8" {
				t.Errorf("encoding = %q", rep.Encoding)
			}
			t.Logf("server_version_num=%d warnings=%v", rep.ServerVersionNum, rep.Warnings)
			if _, err := c.Exec(ctx, `CREATE EXTENSION IF NOT EXISTS pg_trgm`); err != nil {
				t.Fatalf("CREATE EXTENSION as the owner: %v", err)
			}
		})

		t.Run("an absent pg_trgm refuses and leaves the database unchanged", func(t *testing.T) {
			db := s.NewDatabase(t)
			before := objectCount(t, db)
			c, err := db.Owner(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close(ctx)
			_, err = preflight.Check(ctx, renameExt{c})
			if cs := refusalCodes(t, err); len(cs) != 1 || cs[0] != preflight.CodeExtensionMissing {
				t.Fatalf("err = %v", err)
			}
			if after := objectCount(t, db); after != before {
				t.Fatalf("database changed: %s -> %s", before, after)
			}
		})
	})
}

func TestApplyAppliesNothingWhenRefused(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		ctx := context.Background()
		db := s.NewLatin1Database(t)
		err := db.Apply(ctx, migrations.FS)
		if cs := refusalCodes(t, err); len(cs) != 1 || cs[0] != preflight.CodeEncoding {
			t.Fatalf("err = %v", err)
		}
		if got := objectCount(t, db); got != "0/0" {
			t.Fatalf("a refused Apply changed the database: %s", got)
		}
		// A passing database still migrates through the same Apply.
		ok := s.NewDatabase(t)
		if err := ok.Apply(ctx, fstest.MapFS{"0001_x.sql": {Data: []byte(`CREATE TABLE t (id int)`)}}); err != nil {
			t.Fatal(err)
		}
	})
}
