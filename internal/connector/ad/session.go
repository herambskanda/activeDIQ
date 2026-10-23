package ad

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/skenzeriq/activediq/internal/directory/ldapfilter"
	"github.com/skenzeriq/activediq/internal/platform/secret"
)

// Credential is the connection credential unsealed for one session. It is the only holder of the
// bind secret in this package and redacts itself everywhere it can be printed.
type Credential struct {
	BindName string        // UPN or DN of the connector identity
	Password secret.Secret // exposed only inside bind(); never stored on a Session
}

func (Credential) String() string   { return "ad.Credential{redacted}" }
func (Credential) GoString() string { return "ad.Credential{redacted}" }

// LogValue keeps the credential out of slog output.
func (c Credential) LogValue() slog.Value {
	return slog.GroupValue(slog.String("bind_name", c.BindName), slog.String("password", secret.Redacted))
}

var _ slog.LogValuer = Credential{}

// Config configures a Session. There is no field that weakens TLS.
type Config struct {
	Servers    []string       // DC host or host:port, tried in order; LDAPS only (port 636 by default)
	RootCAs    *x509.CertPool // customer CA bundle; nil means the system roots
	ServerName string         // optional TLS name override when Servers are addresses; empty = the host
	Credential Credential
	Schema     *ldapfilter.Schema // filter and attribute allowlist; nil means DefaultSchema()
	Timeout    time.Duration      // per-request timeout, default 30 s
	PageSize   uint32             // default page size, default 500, clamped to MaxPageSize
	Dialer     *net.Dialer        // optional, for tests and proxies
}

// Limits.
const (
	DefaultPageSize = 500
	MaxPageSize     = 1000
	defaultTimeout  = 30 * time.Second
)

// Session is one bound LDAPS connection to one DC. Requests are serialised: the paging cookie and
// the DC are pinned to the connection (connector-contract §5.1). Not for concurrent use of Read and
// Search from a Search callback; the callback must not call back into the Session.
type Session struct {
	mu       sync.Mutex
	conn     *ldap.Conn
	cfg      Config
	schema   *ldapfilter.Schema
	server   string
	pageSize uint32
}

// Open connects to the first reachable server in cfg.Servers and binds. It never downgrades: a
// server that does not offer LDAPS with a valid certificate is skipped, never contacted in clear.
func Open(ctx context.Context, cfg Config) (*Session, error) {
	if len(cfg.Servers) == 0 || cfg.Credential.BindName == "" || cfg.Credential.Password.IsEmpty() {
		return nil, fail(CodeInvalidArgument, "servers and credential are required", nil)
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = defaultTimeout
	}
	ps := cfg.PageSize
	if ps == 0 {
		ps = DefaultPageSize
	}
	if ps > MaxPageSize {
		ps = MaxPageSize
	}
	sc := cfg.Schema
	if sc == nil {
		sc = DefaultSchema()
	}
	var lastErr error
	for _, srv := range cfg.Servers {
		if err := ctx.Err(); err != nil {
			return nil, fail(CodeCanceled, "", err)
		}
		host, port := splitHostPort(srv)
		if host == "" {
			return nil, fail(CodeInvalidArgument, "empty server", nil)
		}
		if port == "3268" || port == "3269" {
			return nil, fail(CodeGlobalCatalog, "", nil) // LF-33
		}
		conn, err := dial(ctx, cfg, host, port)
		if err != nil {
			lastErr = err
			continue
		}
		bindCred := cfg.Credential
		cfg.Credential = Credential{} // the Session never holds the secret
		s := &Session{conn: conn, cfg: cfg, schema: sc, server: net.JoinHostPort(host, port), pageSize: ps}
		if err := s.bind(ctx, bindCred); err != nil {
			conn.Close()
			// A rejected credential is not a reason to hammer the next DC (lockout).
			return nil, err
		}
		return s, nil
	}
	return nil, fail(CodeUnreachable, "", lastErr)
}

func splitHostPort(srv string) (host, port string) {
	srv = strings.TrimSpace(srv)
	if h, p, err := net.SplitHostPort(srv); err == nil {
		return h, p
	}
	return strings.Trim(srv, "[]"), "636"
}

func dial(ctx context.Context, cfg Config, host, port string) (*ldap.Conn, error) {
	name := cfg.ServerName
	if name == "" {
		name = host
	}
	tc := &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: cfg.RootCAs, ServerName: name}
	d := cfg.Dialer
	if d == nil {
		d = &net.Dialer{Timeout: cfg.Timeout}
	}
	dctx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()
	raw, err := d.DialContext(dctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		return nil, err
	}
	tlsConn := tls.Client(raw, tc)
	if err := tlsConn.HandshakeContext(dctx); err != nil {
		raw.Close()
		return nil, err
	}
	c := ldap.NewConn(tlsConn, true)
	c.SetTimeout(cfg.Timeout)
	c.Start()
	return c, nil
}

func (s *Session) bind(ctx context.Context, cred Credential) error {
	conn := s.conn
	stop := s.watch(ctx, conn)
	defer stop()
	var err error
	cred.Password.Expose(func(b []byte) {
		_, err = conn.SimpleBind(&ldap.SimpleBindRequest{Username: cred.BindName, Password: string(b)})
	})
	if err != nil {
		if ctx.Err() != nil {
			return fail(CodeCanceled, "", ctx.Err())
		}
		if ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
			return fail(CodeBindFailed, "invalid credentials", nil)
		}
		return fail(CodeBindFailed, ldapCode(err), nil)
	}
	return nil
}

// watch closes the connection when ctx ends, which aborts the request in flight and releases the
// DC's search state (CC-SRCH-14), so a cancelled ctx kills the Session. conn is captured by the
// caller under the lock; the returned func stops the watcher and waits for it to exit, and must be
// called when the request is done.
func (s *Session) watch(ctx context.Context, conn *ldap.Conn) func() {
	done := make(chan struct{})
	exited := make(chan struct{})
	go func() {
		defer close(exited)
		select {
		case <-ctx.Done():
			select {
			case <-done: // request already finished: leave the connection alone
			default:
				conn.Close()
			}
		case <-done:
		}
	}()
	return func() { close(done); <-exited }
}

// Server is the host:port this session is bound to.
func (s *Session) Server() string { return s.server }

// Close unbinds and closes. Safe to call twice.
func (s *Session) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn == nil {
		return nil
	}
	conn := s.conn
	s.conn = nil
	// Unbind can block on a connection a cancelled context already closed, so bound it.
	res := make(chan error, 1)
	go func() { res <- conn.Unbind() }()
	var err error
	select {
	case err = <-res:
	case <-time.After(2 * time.Second):
	}
	conn.Close()
	return err
}

func ldapCode(err error) string {
	if le, ok := err.(*ldap.Error); ok {
		return "ldap result " + strconv.Itoa(int(le.ResultCode))
	}
	return "transport error"
}
