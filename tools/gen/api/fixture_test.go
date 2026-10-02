package main

import (
	"flag"
	"os"
	"path/filepath"
	"testing"
)

var update = flag.Bool("update", false, "rewrite the fixture's golden generated tree")

const fixtureModule = "github.com/skenzeriq/activediq/tools/gen/api/internal/fixture"

// fixtureConfig generates tools/gen/api/testdata/fixture/openapi into tools/gen/api/internal/fixture,
// a package tree `go test` compiles, so the golden output is also proven to build.
func fixtureConfig(t testing.TB) *Config {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	return &Config{
		Root:           filepath.Join(wd, "testdata", "fixture", "openapi"),
		Out:            filepath.Join(wd, "internal", "fixture"),
		Module:         fixtureModule,
		ApitypesImport: "github.com/skenzeriq/activediq/internal/platform/apihost/apitypes",
		ApihostImport:  "github.com/skenzeriq/activediq/internal/platform/apihost",
		SharedDir:      "shared",
		BundlePath:     "openapi.gen.json",
		EmitProblems:   false,
		Bindings: []Binding{
			{Schema: "SecretInput", Import: fixtureModule + "/stub/secret", Type: "Secret", Secret: true},
			{Schema: "Int64String", Import: "github.com/skenzeriq/activediq/internal/platform/apihost/apitypes", Type: "Int64String"},
			{Schema: "FilterAst", Import: fixtureModule + "/stub/filter", Type: "Filter"},
		},
	}
}

// TestFixtureGolden regenerates the fixture in memory and compares it with the committed tree.
// `go test ./tools/gen/api -run Golden -update` rewrites it.
func TestFixtureGolden(t *testing.T) {
	cfg := fixtureConfig(t)
	res, err := Generate(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if *update {
		if err := Write(cfg, res); err != nil {
			t.Fatal(err)
		}
		return
	}
	if diffs := Diff(cfg, res); len(diffs) > 0 {
		t.Fatalf("the fixture's generated tree is stale (go test ./tools/gen/api -run Golden -update):\n%v", diffs)
	}
}
