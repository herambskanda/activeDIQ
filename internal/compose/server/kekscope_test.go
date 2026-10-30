package server

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Acceptance 6 (keys-custody-design K1): the KEK settings are named, and so read, only in this package.
func TestKEKSettingsAreReadOnlyInComposeServer(t *testing.T) {
	root := filepath.Join("..", "..", "..")
	own, _ := filepath.Abs(".")
	needle := "ACTIVEDIQ_KEK_"
	for _, top := range []string{"cmd", "internal", "tools"} {
		err := filepath.WalkDir(filepath.Join(root, top), func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(p, ".go") {
				return err
			}
			if abs, _ := filepath.Abs(filepath.Dir(p)); abs == own {
				return nil
			}
			b, err := os.ReadFile(p)
			if err == nil && strings.Contains(string(b), needle) {
				t.Errorf("%s names %s*: KEK settings are read only in internal/compose/server", p, needle)
			}
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}
