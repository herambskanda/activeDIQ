package config

import (
	"fmt"
	"path/filepath"
	"strings"
)

// validateKEKPlacement refuses a KEK file inside the API TLS directory: the sealed key and its KEK would
// then travel together in every copy or backup of that directory (TM-TB5-T4). Both paths are made absolute
// and symlink-resolved (the deepest existing ancestor, since the TLS directory may not exist yet).
func (c Config) validateKEKPlacement() error {
	if c.KEKFile == "" || c.APITLSDir == "" {
		return nil
	}
	kek, err := resolveLoose(c.KEKFile)
	if err != nil {
		return fmt.Errorf("%s: %w", EnvKEKFile, err)
	}
	dir, err := resolveLoose(c.APITLSDir)
	if err != nil {
		return fmt.Errorf("%s: %w", EnvAPITLSDir, err)
	}
	if rel, err := filepath.Rel(dir, kek); err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fmt.Errorf("%s must not be inside %s: the sealed key and its KEK would be backed up together", EnvKEKFile, EnvAPITLSDir)
	}
	return nil
}

// resolveLoose returns the absolute path with symlinks resolved in its existing part; a missing tail is
// appended unchanged.
func resolveLoose(p string) (string, error) {
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	rest := ""
	cur := abs
	for {
		if r, err := filepath.EvalSymlinks(cur); err == nil {
			return filepath.Join(r, rest), nil
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return abs, nil
		}
		rest = filepath.Join(filepath.Base(cur), rest)
		cur = parent
	}
}
