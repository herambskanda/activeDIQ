//go:build !windows

package agent

import "os"

// configPath returns the path named by ConfigEnv. Non-Windows builds and tests only: on Windows the
// path is fixed beside the executable (configpath_windows.go).
func configPath() (string, error) {
	p := os.Getenv(ConfigEnv)
	if p == "" {
		return "", ErrNoConfig
	}
	return p, nil
}
