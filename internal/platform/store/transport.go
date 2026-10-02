package store

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// ErrInsecureTransport is returned (wrapped in a *TransportError) when a DSN would reach a remote
// PostgreSQL without a verified TLS connection. No connection has been attempted.
var ErrInsecureTransport = errors.New("store: insecure database transport")

// TransportError says which host the policy refused and why. It carries no password, no DSN and no
// certificate material.
type TransportError struct {
	Host    string // host as written in the DSN
	Problem string // what the DSN would have done
}

func (e *TransportError) Error() string {
	return fmt.Sprintf("store: refusing the database connection to %q: %s; a remote PostgreSQL needs sslmode=verify-full, "+
		"or sslmode=verify-ca with sslrootcert set to the pinned CA file (loopback and unix sockets are exempt; "+
		"an operator may set the platform-scope insecure-transport override, which is logged and shown on the health page)",
		e.Host, e.Problem)
}

func (e *TransportError) Is(target error) bool { return target == ErrInsecureTransport }

// TransportStatus is what the health page shows about the database transport.
type TransportStatus struct {
	// OverrideConfigured is true when the operator set the insecure-transport override.
	OverrideConfigured bool
	// RelaxedHosts lists the remote hosts the override let through although the DSN does not verify the
	// server (sorted, unique). Empty when the DSN is compliant, whatever the override says.
	RelaxedHosts []string
}

// Insecure is true when at least one remote host is reached without a verified connection.
func (s TransportStatus) Insecure() bool { return len(s.RelaxedHosts) > 0 }

// CheckTransport applies the transport policy (safe-primitives §7 rule 14, ADR-0002 rule 6) to a DSN
// without connecting: every TCP host other than loopback must be reached over TLS that verifies the
// server, either sslmode=verify-full, or sslmode=verify-ca with sslrootcert pinning the CA. Unix sockets
// and loopback addresses are exempt. Every host of a multi-host DSN, and every fallback pgx would try
// (sslmode=allow and prefer fall back to, or start with, plaintext), is checked, whether the settings
// come from the DSN or from the PG* environment variables.
//
// allowInsecure is the explicit operator override: the refusal becomes a start-up warning and an entry
// in the returned status. Open uses this for the runtime DSN; the migration step must call it for the
// owner DSN as well, with the same override.
func CheckTransport(dsn string, allowInsecure bool) (TransportStatus, error) {
	pc, err := pgx.ParseConfig(dsn)
	if err != nil {
		// pgx redacts the password in this message.
		return TransportStatus{}, fmt.Errorf("store: invalid DSN: %w", err)
	}
	return checkTransport(pc, allowInsecure)
}

func checkTransport(cc *pgx.ConnConfig, allowInsecure bool) (TransportStatus, error) {
	st := TransportStatus{OverrideConfigured: allowInsecure}
	relaxed := map[string]struct{}{}
	targets := make([]pgconn.FallbackConfig, 0, 1+len(cc.Fallbacks))
	targets = append(targets, pgconn.FallbackConfig{Host: cc.Host, Port: cc.Port, TLSConfig: cc.TLSConfig})
	for _, f := range cc.Fallbacks {
		targets = append(targets, *f)
	}
	for _, t := range targets {
		if exemptHost(t.Host) {
			continue
		}
		problem := tlsProblem(t.TLSConfig)
		if problem == "" {
			continue
		}
		if !allowInsecure {
			return TransportStatus{}, &TransportError{Host: t.Host, Problem: problem}
		}
		relaxed[t.Host] = struct{}{}
	}
	for h := range relaxed {
		st.RelaxedHosts = append(st.RelaxedHosts, h)
	}
	sort.Strings(st.RelaxedHosts)
	return st, nil
}

// exemptHost: a unix socket (pgx treats an absolute path as one) or a loopback address. The name
// "localhost" is accepted because it resolves through the hosts file; any other name is remote, since
// DNS decides where it points.
func exemptHost(host string) bool {
	if host == "" || strings.HasPrefix(host, "/") || strings.HasPrefix(host, "@") {
		return true
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	a, err := netip.ParseAddr(host)
	return err == nil && a.Unmap().IsLoopback()
}

// tlsProblem classifies the TLS configuration pgx derived from sslmode and sslrootcert. It reads the
// result rather than the DSN text so that PGSSLMODE, option spellings and pgx's own defaults cannot get
// around it. "" means the server is verified.
func tlsProblem(c *tls.Config) string {
	switch {
	case c == nil:
		return "the connection would be unencrypted (sslmode disable, allow or prefer)"
	case !c.InsecureSkipVerify:
		return "" // verify-full (or sslrootcert=system): chain and host name are checked
	case c.VerifyPeerCertificate == nil:
		return "TLS would not verify the server certificate (sslmode allow, prefer or require without sslrootcert)"
	case c.RootCAs == nil:
		return "sslmode=verify-ca without sslrootcert would trust whatever the system store trusts; pin the CA with sslrootcert"
	}
	return "" // verify-ca against a pinned sslrootcert: the chain is checked
}
