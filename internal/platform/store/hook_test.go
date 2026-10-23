package store

import "testing"

func TestIsTxControl(t *testing.T) {
	for sql, want := range map[string]bool{
		"COMMIT": true, " rollback ": true, "SAVEPOINT s": true, "release s": true, "BEGIN": true, "start transaction": true,
		"END": true, "abort": true, "PREPARE TRANSACTION 'x'": true, "SELECT 1; COMMIT": true, "select 1;\n  rollback;": true,
		"-- x\nCOMMIT": true, "/**/COMMIT": true, "/* ; */ COMMIT": true, "/* a /* nested */ b */ ROLLBACK": true,
		"SELECT 1; -- c\n COMMIT": true, "SELECT 'it''s -- not a comment'": false, "SELECT 1 -- COMMIT": false, "/* COMMIT */ SELECT 1": false,
		"SELECT 'a;b'":             false,
		"INSERT INTO t VALUES (1)": false, "": false,
	} {
		if got := isTxControl(sql); got != want {
			t.Errorf("isTxControl(%q) = %v; want %v", sql, got, want)
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
