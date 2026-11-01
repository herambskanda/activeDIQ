//go:build windows

package agent

import (
	"os"
	"path/filepath"
)

// configFile is the name of the local configuration, written by the MSI beside the executable.
const configFile = "agent.json"

// configPath returns agent.json beside the running executable. On Windows the path is not an input:
// the install directory under Program Files is writable only by administrators, and no environment
// variable or service-key value can redirect the service to another file (T-0688 ruling 4c).
func configPath() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.Join(filepath.Dir(exe), configFile), nil
}
