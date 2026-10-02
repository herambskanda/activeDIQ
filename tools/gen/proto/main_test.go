package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGenerateIsReproducibleAndCheckDetectsDrift(t *testing.T) {
	out := t.TempDir()
	if err := run("../../../proto", out, false); err != nil {
		t.Fatal(err)
	}
	if err := run("../../../proto", out, true); err != nil {
		t.Fatalf("fresh generation must pass -check: %v", err)
	}
	// A second generation into a second tree is byte-identical.
	out2 := t.TempDir()
	if err := run("../../../proto", out2, false); err != nil {
		t.Fatal(err)
	}
	if err := compareTrees(out, out2); err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(out, "activediq/connector/v1/connector_grpc.pb.go")
	if _, err := os.Stat(f); err != nil {
		t.Fatalf("grpc code not generated: %v", err)
	}
	if err := os.WriteFile(f, []byte("package connectorv1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := run("../../../proto", out, true); err == nil || !strings.Contains(err.Error(), "stale") {
		t.Fatalf("-check must flag a stale file, got %v", err)
	}
}

func compareTrees(a, b string) error {
	files, err := existing(a)
	if err != nil {
		return err
	}
	for _, f := range files {
		x, _ := os.ReadFile(filepath.Join(a, f))
		y, err := os.ReadFile(filepath.Join(b, f))
		if err != nil || string(x) != string(y) {
			return os.ErrInvalid
		}
	}
	return nil
}
