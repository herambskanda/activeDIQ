// Package config is the configuration loader of the composition root. It is the only package in
// the repository allowed to read environment variables (blueprint §1); everything else receives
// a Config value.
package config

import (
	"errors"
	"fmt"
	"log/slog"
	"time"
)

// EnvLogLevel selects the log level: debug, info, warn or error. The default is info.
const EnvLogLevel = "ACTIVEDIQ_LOG_LEVEL"

// Further settings. The DSN carries credentials: it is read here and handed to the store, never logged.
const (
	// EnvDatabaseDSN is the pgx connection string of the runtime role (never the migration role).
	EnvDatabaseDSN = "ACTIVEDIQ_DATABASE_DSN"
	// EnvInstanceID names this process in platform leases. It must be unique among running servers and is
	// validated by the job worker (letters, digits and ._:@-, 1..200). Empty means a random per-process id.
	EnvInstanceID = "ACTIVEDIQ_INSTANCE_ID"
	// EnvShutdownGrace is how long in-flight jobs may finish after SIGTERM before they are cancelled.
	EnvShutdownGrace = "ACTIVEDIQ_SHUTDOWN_GRACE"
	// EnvStopTimeout is the service manager's stop timeout (systemd TimeoutStopSec, Kubernetes
	// terminationGracePeriodSeconds) that this process must finish inside.
	EnvStopTimeout = "ACTIVEDIQ_STOP_TIMEOUT"
)

// Defaults for the shutdown settings. systemd's TimeoutStopSec defaults to 90 s.
const (
	DefaultShutdownGrace = 30 * time.Second
	DefaultStopTimeout   = 90 * time.Second
)

// Config is what a role package receives from its cmd/<role> main. It grows per setting, never per
// module.
type Config struct {
	LogLevel slog.Level
	// DatabaseDSN is empty only in tests that never reach the database; the server role refuses it.
	DatabaseDSN string
	InstanceID  string
	// ShutdownGrace is the job worker's drain period. The worker may wait it twice (graceful drain, then
	// the drain after cancelling stragglers), so Load requires 2 x ShutdownGrace < StopTimeout.
	ShutdownGrace time.Duration
	StopTimeout   time.Duration
}

// Load reads the configuration through getenv (os.Getenv in the binaries, a map in tests).
// An invalid value is an error; it is never silently replaced by a default.
func Load(getenv func(string) string) (Config, error) {
	c := Config{LogLevel: slog.LevelInfo, ShutdownGrace: DefaultShutdownGrace, StopTimeout: DefaultStopTimeout}
	if v := getenv(EnvLogLevel); v != "" {
		if err := c.LogLevel.UnmarshalText([]byte(v)); err != nil {
			return Config{}, fmt.Errorf("%s: %w", EnvLogLevel, err)
		}
	}
	c.DatabaseDSN = getenv(EnvDatabaseDSN)
	c.InstanceID = getenv(EnvInstanceID)
	var err error
	if c.ShutdownGrace, err = duration(getenv, EnvShutdownGrace, c.ShutdownGrace); err != nil {
		return Config{}, err
	}
	if c.StopTimeout, err = duration(getenv, EnvStopTimeout, c.StopTimeout); err != nil {
		return Config{}, err
	}
	if 2*c.ShutdownGrace >= c.StopTimeout {
		return Config{}, fmt.Errorf("%s: twice the shutdown grace (%s) must be less than the stop timeout (%s) or the service manager kills the process mid-drain",
			EnvShutdownGrace, c.ShutdownGrace, c.StopTimeout)
	}
	return c, nil
}

func duration(getenv func(string) string, key string, def time.Duration) (time.Duration, error) {
	v := getenv(key)
	if v == "" {
		return def, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", key, err)
	}
	if d <= 0 {
		return 0, fmt.Errorf("%s: %w", key, errNotPositive)
	}
	return d, nil
}

var errNotPositive = errors.New("must be a positive duration")

const redacted = "[redacted]"

// redactedCopy hides the credential-bearing DSN; it is the only form of Config that is ever printed.
func (c Config) redactedCopy() Config {
	if c.DatabaseDSN != "" {
		c.DatabaseDSN = redacted
	}
	return c
}

type plain Config // no methods, so formatting it cannot recurse into String

// String implements fmt.Stringer so %v and %+v never print the DSN.
func (c Config) String() string { return fmt.Sprintf("%+v", plain(c.redactedCopy())) }

// GoString does the same for %#v.
func (c Config) GoString() string { return c.String() }

// LogValue implements slog.LogValuer so structured logging never prints the DSN.
func (c Config) LogValue() slog.Value {
	r := c.redactedCopy()
	return slog.GroupValue(
		slog.String("log_level", r.LogLevel.String()),
		slog.String("database_dsn", r.DatabaseDSN),
		slog.String("instance_id", r.InstanceID),
		slog.Duration("shutdown_grace", r.ShutdownGrace),
		slog.Duration("stop_timeout", r.StopTimeout),
	)
}
