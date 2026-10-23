//go:build !unix

package dial

import (
	"os"
	"path/filepath"
)

// ACL checks for Windows and OCI hosts are T-0104, as in apitls; until then only symlinks and
// non-regular files are refused. CreateTemp files are private to the creating user by default there.
func ensureDir(dir string) error { return os.MkdirAll(dir, 0o700) }

func checkDir(dir string) error {
	st, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !st.IsDir() {
		return os.ErrInvalid
	}
	return nil
}

func checkFile(path string, _ bool) error {
	st, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() {
		return os.ErrInvalid
	}
	return nil
}

func writeFile(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}
