package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// GenerateTS runs openapi-typescript over the bundle (ADR-0004 rule 4). It is third-party and
// pinned in web/package.json; the wrapper script web/scripts/gen-api-types.mjs widens open enums.
// The bundle goes through a temporary file: nothing reads the per-tag sources.
func GenerateTS(cfg *Config, bundle []byte) ([]byte, error) {
	web := filepath.Join(filepath.Dir(filepath.Join(cfg.Out, filepath.FromSlash(cfg.TSOut))), "..", "..")
	script := filepath.Join(web, "scripts", "gen-api-types.mjs")
	if _, err := os.Stat(filepath.Join(web, "node_modules", "openapi-typescript")); err != nil {
		return nil, fmt.Errorf("openapi-typescript is not installed: run `make web-install` (npm ci --prefix web)")
	}
	dir, err := os.MkdirTemp("", "gen-api-ts")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	in, out := filepath.Join(dir, "openapi.json"), filepath.Join(dir, "schema.gen.d.ts")
	if err := os.WriteFile(in, bundle, 0o600); err != nil {
		return nil, err
	}
	cmd := exec.Command("node", script, in, out)
	cmd.Dir = web
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("openapi-typescript failed: %v\n%s", err, stderr.String())
	}
	return os.ReadFile(out)
}
