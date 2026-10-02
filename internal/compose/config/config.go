// Package config is the configuration loader of the composition root. It is the only package in
// the repository allowed to read environment variables (blueprint §1); everything else receives
// a Config value.
package config

import (
	"fmt"
	"log/slog"
)

// EnvLogLevel selects the log level: debug, info, warn or error. The default is info.
const EnvLogLevel = "ACTIVEDIQ_LOG_LEVEL"

// Config is what a role package receives from its cmd/<role> main. It grows per setting, never per
// module.
type Config struct {
	LogLevel slog.Level
}

// Load reads the configuration through getenv (os.Getenv in the binaries, a map in tests).
// An invalid value is an error; it is never silently replaced by a default.
func Load(getenv func(string) string) (Config, error) {
	c := Config{LogLevel: slog.LevelInfo}
	if v := getenv(EnvLogLevel); v != "" {
		if err := c.LogLevel.UnmarshalText([]byte(v)); err != nil {
			return Config{}, fmt.Errorf("%s: %w", EnvLogLevel, err)
		}
	}
	return c, nil
}
