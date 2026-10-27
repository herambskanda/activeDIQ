// Package config is the configuration loader of the composition root. It is the only package in
// the repository allowed to read environment variables (blueprint §1); everything else receives
// a Config value.
package config

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"strings"
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
	// EnvAPIAddr is the address the API listener binds (host:port).
	EnvAPIAddr = "ACTIVEDIQ_API_ADDR"
	// EnvAPITLSDir is the directory holding the API's per-install certificate and key. The listener always
	// serves TLS; with a directory the certificate persists across restarts, without one it is generated in
	// memory for each process, which is only acceptable on a loopback bind.
	EnvAPITLSDir = "ACTIVEDIQ_API_TLS_DIR"
	// EnvAPIBodyBudget is the total bytes of request-body buffers the API may hold at once across all
	// in-flight requests. It must be a positive integer.
	EnvAPIBodyBudget = "ACTIVEDIQ_API_BODY_BUDGET"
	// EnvTrustedProxies is a comma-separated list of CIDRs (or bare IPs) of reverse proxies whose
	// X-Forwarded-For is believed. Empty (the default) means forwarded headers are never trusted.
	EnvTrustedProxies = "ACTIVEDIQ_TRUSTED_PROXIES"
	// EnvNodes is the number of server nodes in this install (a positive integer, default 1). More than one
	// node needs the shared principal store: the server refuses to start with the in-memory store.
	EnvNodes = "ACTIVEDIQ_NODES"
	// EnvPrincipalStore selects where per-principal rate budgets live: "postgres" (the default, shared by
	// every node) or "memory" (one process; only valid with a single node).
	EnvPrincipalStore = "ACTIVEDIQ_PRINCIPAL_STORE"
)

// Values of EnvPrincipalStore.
const (
	PrincipalStorePostgres = "postgres"
	PrincipalStoreMemory   = "memory"
)

// Defaults for the shutdown settings. systemd's TimeoutStopSec defaults to 90 s.
const (
	DefaultShutdownGrace = 30 * time.Second
	DefaultStopTimeout   = 90 * time.Second
	// DefaultAPIAddr binds loopback only. A non-loopback bind needs EnvAPITLSDir (the listener is TLS-only).
	DefaultAPIAddr = "127.0.0.1:8080"
	// DefaultAPIBodyBudget is 64 MiB, the same default as apihost.DefaultBodyBudget.
	DefaultAPIBodyBudget int64 = 64 << 20
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
	// APIAddr is the API listener's bind address.
	APIAddr string
	// APITLSDir is where the per-install API certificate lives; empty means an ephemeral in-memory one.
	APITLSDir string
	// APIBodyBudget is passed to apihost.WithBodyBudget. Non-positive values fail startup.
	APIBodyBudget int64
	// TrustedProxies is passed to apihost.WithTrustedProxies.
	TrustedProxies []netip.Prefix
	// Nodes is the number of server nodes; PrincipalStore is PrincipalStorePostgres or PrincipalStoreMemory.
	Nodes          int
	PrincipalStore string
}

// Load reads the configuration through getenv (os.Getenv in the binaries, a map in tests).
// An invalid value is an error; it is never silently replaced by a default.
func Load(getenv func(string) string) (Config, error) {
	c := Config{LogLevel: slog.LevelInfo, ShutdownGrace: DefaultShutdownGrace, StopTimeout: DefaultStopTimeout,
		APIAddr: DefaultAPIAddr, APIBodyBudget: DefaultAPIBodyBudget, Nodes: 1, PrincipalStore: PrincipalStorePostgres}
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
	if v := getenv(EnvAPIAddr); v != "" {
		c.APIAddr = v
	}
	c.APITLSDir = getenv(EnvAPITLSDir)
	if err := c.ValidateAPIListen(); err != nil {
		return Config{}, err
	}
	if v := getenv(EnvAPIBodyBudget); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return Config{}, fmt.Errorf("%s: %w", EnvAPIBodyBudget, err)
		}
		if n <= 0 {
			return Config{}, fmt.Errorf("%s: must be a positive number of bytes, got %d", EnvAPIBodyBudget, n)
		}
		c.APIBodyBudget = n
	}
	if v := getenv(EnvTrustedProxies); v != "" {
		for part := range strings.SplitSeq(v, ",") {
			part = strings.TrimSpace(part)
			pfx, err := netip.ParsePrefix(part)
			if err != nil {
				a, aerr := netip.ParseAddr(part)
				if aerr != nil {
					return Config{}, fmt.Errorf("%s: %q is not a CIDR or IP address", EnvTrustedProxies, part)
				}
				pfx = netip.PrefixFrom(a, a.BitLen())
			}
			if pfx.Bits() == 0 {
				return Config{}, fmt.Errorf("%s: %q would trust every address; list the proxies' own networks", EnvTrustedProxies, part)
			}
			c.TrustedProxies = append(c.TrustedProxies, pfx.Masked())
		}
	}
	if v := getenv(EnvNodes); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			return Config{}, fmt.Errorf("%s: must be a positive integer, got %q", EnvNodes, v)
		}
		c.Nodes = n
	}
	if v := getenv(EnvPrincipalStore); v != "" {
		c.PrincipalStore = v
	}
	if err := c.ValidatePrincipalStore(); err != nil {
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
		slog.String("api_addr", r.APIAddr),
		slog.String("api_tls_dir", r.APITLSDir),
		slog.Int64("api_body_budget", r.APIBodyBudget),
		slog.Any("trusted_proxies", r.TrustedProxies),
		slog.Int("nodes", r.Nodes),
		slog.String("principal_store", r.PrincipalStore),
	)
}

// ValidateAPIListen refuses a non-loopback API bind unless a persistent TLS identity directory is
// configured (TM-TB1-T2): without one the certificate would differ on every start and the admin
// could never pin its fingerprint. The listener never serves plaintext either way.
func (c Config) ValidateAPIListen() error {
	if c.APITLSDir != "" {
		return nil
	}
	if err := requireLoopback(c.APIAddr); err != nil {
		return fmt.Errorf("%s: TLS is not configured (%s is empty): %w", EnvAPIAddr, EnvAPITLSDir, err)
	}
	return nil
}

// requireLoopback accepts only "localhost" or a literal loopback IP; empty and unspecified hosts bind
// all interfaces.
func requireLoopback(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("must be a loopback host:port: %w", err)
	}
	if host == "localhost" {
		return nil
	}
	ip, err := netip.ParseAddr(host)
	if err == nil && ip.IsLoopback() {
		return nil
	}
	return errors.New("must bind a loopback address (127.0.0.0/8, ::1 or localhost) unless a TLS directory is configured")
}

// ValidatePrincipalStore refuses an unknown store and the in-memory store on more than one node: each
// node would keep its own budget, so a principal's reveal and secret limits would multiply by the node
// count (TM-TB2-T7). A zero Nodes or empty store is a Config built by hand, not by Load, and is refused.
func (c Config) ValidatePrincipalStore() error {
	if c.Nodes < 1 {
		return fmt.Errorf("%s: node count %d is not positive", EnvNodes, c.Nodes)
	}
	switch c.PrincipalStore {
	case PrincipalStorePostgres:
		return nil
	case PrincipalStoreMemory:
		if c.Nodes > 1 {
			return fmt.Errorf("%s=%s with %s=%d: every node would keep its own rate budget; use %s",
				EnvPrincipalStore, PrincipalStoreMemory, EnvNodes, c.Nodes, PrincipalStorePostgres)
		}
		return nil
	}
	return fmt.Errorf("%s: %q is not %q or %q", EnvPrincipalStore, c.PrincipalStore, PrincipalStorePostgres, PrincipalStoreMemory)
}
