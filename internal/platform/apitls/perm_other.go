//go:build !unix

package apitls

import "os"

// The installer sets the Windows ACL (T-0104); the runtime owner/DACL check here is T-0413. Until then only symlinks and non-regular files are refused.
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
