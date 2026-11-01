package library_test

import (
	"crypto/sha256"
	"encoding/hex"
	"io/fs"

	"github.com/skenzeriq/activediq/internal/modules/reports/library"
)

func fsReadFile(name string) ([]byte, error) { return fs.ReadFile(library.Shipped(), name) }

func lockOf(name string, body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:]) + "  " + name + "\n"
}
