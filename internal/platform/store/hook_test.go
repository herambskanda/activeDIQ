package store

import "testing"

func TestIsTxControl(t *testing.T) {
	for sql, want := range map[string]bool{
		"COMMIT": true, " rollback ": true, "SAVEPOINT s": true, "release s": true, "BEGIN": true, "start transaction": true,
		"END": true, "abort": true, "PREPARE TRANSACTION 'x'": true, "SELECT 1; COMMIT": true, "select 1;\n  rollback;": true,
		"-- x\nCOMMIT": true, "/**/COMMIT": true, "/* ; */ COMMIT": true, "/* a /* nested */ b */ ROLLBACK": true,
		"SELECT 1; -- c\n COMMIT": true, "SELECT 'it''s -- not a comment'": false, "SELECT 1 -- COMMIT": false, "/* COMMIT */ SELECT 1": false,
		"SELECT 'a;b'":                false,
		`select "a'b" from t; commit`: true, "SELECT $$ ' $$; COMMIT": true, "SELECT $t$ ; commit $t$": false,
		"SELECT E'\\'; commit'": false, "SELECT $1; COMMIT": true,
		"INSERT INTO t VALUES (1)": false, "": false,
	} {
		if got := IsTxControl(sql); got != want {
			t.Errorf("IsTxControl(%q) = %v; want %v", sql, got, want)
		}
	}
}

func TestSlotRefusesForeignTx(t *testing.T) {
	s := NewSlot[int]()
	if err := s.Update(nil, func(*int) error { return nil }); err != ErrNotStoreTx {
		t.Fatalf("Update on a non-store Tx = %v; want ErrNotStoreTx", err)
	}
	if HasHook(nil) {
		t.Fatal("HasHook(nil) = true")
	}
}

func TestStatements(t *testing.T) {
	for _, c := range []struct {
		sql  string
		want []string
	}{
		{"", nil},
		{"SELECT 1;; ;", []string{"SELECT 1"}},
		{"/* x */ INSERT INTO t VALUES (1)", []string{"INSERT INTO t VALUES (1)"}},
		{"-- note\nINSERT INTO t VALUES (1)", []string{"INSERT INTO t VALUES (1)"}},
		{"SELECT 1; DELETE FROM t", []string{"SELECT 1", "DELETE FROM t"}},
		{`select "a'b" from t; insert into t values (1)`, []string{"select '' from t", "insert into t values (1)"}},
		{"SELECT 'INSERT INTO x'", []string{"SELECT ''"}},
		{"SELECT 'it''s; fine'", []string{"SELECT ''"}},
		{"SELECT $q$ a ; ' b $q$; UPDATE t SET a = $1", []string{"SELECT ''", "UPDATE t SET a = $1"}},
		{"SELECT 1 /* open", []string{"SELECT 1"}},
	} {
		got := Statements(c.sql)
		if len(got) != len(c.want) {
			t.Errorf("Statements(%q) = %q; want %q", c.sql, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("Statements(%q)[%d] = %q; want %q", c.sql, i, got[i], c.want[i])
			}
		}
	}
}
