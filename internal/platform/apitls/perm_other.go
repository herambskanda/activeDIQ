//go:build !unix

package apitls

import "os"

// Windows and OCI ACL checks are T-0104; until then only symlinks and non-regular files are refused.
func checkDir(string) error { return nil }

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
