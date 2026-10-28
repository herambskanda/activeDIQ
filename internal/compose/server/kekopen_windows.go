//go:build windows

package server

import (
	"errors"
	"os"
)

func kekFileSupported(goos string) error {
	if goos == "windows" {
		return errors.New("the KEK file profile is not available on Windows (no DACL check yet): use the DPAPI-NG/TPM profile")
	}
	return nil
}

func openKEKFile(path string) (*os.File, error) {
	return nil, errors.New("the KEK file profile is not available on Windows")
}
