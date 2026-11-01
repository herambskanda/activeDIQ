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
	// Kerberos, when set, replaces Credential: SASL GSSAPI over LDAPS with channel binding. Set one
	// of the two, never both.
	Kerberos *Kerberos
	Schema   *ldapfilter.Schema // filter and attribute allowlist; nil means DefaultSchema()
	Timeout  time.Duration      // per-request timeout, default 30 s
	PageSize uint32             // default page size, default 500, clamped to MaxPageSize
	Dialer   ContextDialer      // optional, for tests and proxies (a *net.Dialer fits)
	// SecretAudit receives one event per ReadSecret call (actor, target GUID, attribute, reason,
	// outcome — never a value). ReadSecret refuses to run without it.
	SecretAudit func(SecretReadEvent) error
}

// Limits.
const (
	DefaultPageSize = 500
	MaxPageSize     = 1000
	defaultTimeout  = 30 * time.Second
)

// ContextDialer is the part of net.Dialer that dial uses.
type ContextDialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

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
func Open(ctx context.Context, cfg Config) (*Session, error) { return open(ctx, cfg, false) }

// open is Open for the ordinary (domain) session, or for the GC resolver when gc is set. The two
// are separate door types: a GC port is refused for every Session (LF-33) and only OpenGC may use it.
func open(ctx context.Context, cfg Config, gc bool) (*Session, error) {
	hasPwd := cfg.Credential.BindName != "" || !cfg.Credential.Password.IsEmpty()
	if len(cfg.Servers) == 0 || (cfg.Kerberos == nil && (cfg.Credential.BindName == "" || cfg.Credential.Password.IsEmpty())) {
		return nil, fail(CodeInvalidArgument, "servers and credential are required", nil)
	}
	if cfg.Kerberos != nil {
		if hasPwd {
			return nil, fail(CodeInvalidArgument, "set either a password credential or a kerberos identity", nil)
		}
		if err := cfg.Kerberos.validate(); err != nil {
			return nil, err
		}
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
		isGC := port == "3268" || port == "3269"
		if isGC && !gc {
			return nil, fail(CodeGlobalCatalog, "", nil) // LF-33
		}
		if gc && port != "3269" { // the GC resolver is LDAPS only; there is no default port to fall to
			return nil, fail(CodeInvalidArgument, "the global catalog server must be host:3269", nil)
		}
		conn, err := dial(ctx, cfg, host, port)
		if err != nil {
			lastErr = err
			continue
		}
		bindCred, krb := cfg.Credential, cfg.Kerberos
		cfg.Credential, cfg.Kerberos = Credential{}, nil // the Session never holds the secret
		s := &Session{conn: conn, cfg: cfg, schema: sc, server: net.JoinHostPort(host, port), pageSize: ps}
		if err := s.bindAs(ctx, host, bindCred, krb); err != nil {
			conn.Close()
			// A rejected credential is not a reason to hammer the next DC (lockout).
			return nil, err
		}
		// SecretAttrs is computed at connect (safe-primitives §3.7). Failing to compute it fails the
		// connect: a session that cannot name its secrets must not search.
		if gc {
			// searchFlags is not in the GC partial attribute set, so the schema-flag search returns
			// nothing on 3269 (T-0619). Read it from the same host's LDAPS port (every DC holds the
			// schema NC) on a short-lived domain session, then keep only the resulting schema.
			err = s.loadSecretAttrsFromDC(ctx, host, bindCred, krb)
		} else {
			err = s.loadSecretAttrs(ctx)
		}
		if err != nil {
			s.Close()
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

func (s *Session) bindKerberos(ctx context.Context, k Kerberos, spnHost string) error {
	conn := s.conn
	stop := s.watch(ctx, conn)
	defer stop()
	err := bindGSSAPI(conn, k, spnHost)
	if err != nil && ctx.Err() != nil {
		return fail(CodeCanceled, "", ctx.Err())
	}
	return err
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

// FilterSchema is the schema allowlist the session renders filters against; a caller parses a
// request's filter AST with it (ldapfilter.ParseFilterAST) so the parse and the render agree.
func (s *Session) FilterSchema() *ldapfilter.Schema { return s.schema }

// AttrSyntax returns the value syntax the session's schema allowlist records for an attribute.
func (s *Session) AttrSyntax(name string) (ldapfilter.Syntax, bool) { return s.schema.Syntax(name) }

// CanonicalAttr resolves a requested attribute name (descr in any case, or numeric OID). A numeric
// OID comes back as the schema's ldapDisplayName; a descr comes back in the case it was typed in,
// NOT normalised. Callers must therefore compare the result case-insensitively (the SD hold uses
// EqualFold and the schema builder lowercases names).
func (s *Session) CanonicalAttr(name string) (string, error) {
	a, err := ldapfilter.ParseAttrName(name, s.schema)
	if err != nil {
		return "", fail(CodeInvalidArgument, "attribute: "+ldapfilter.Code(err), err)
	}
	return a.String(), nil
}

// bindAs binds s with a password or a kerberos identity.
func (s *Session) bindAs(ctx context.Context, host string, cred Credential, krb *Kerberos) error {
	if krb != nil {
		name := s.cfg.ServerName
		if name == "" {
			name = host
		}
		return s.bindKerberos(ctx, *krb, name)
	}
	return s.bind(ctx, cred)
}

// loadSecretAttrsFromDC computes the secret-attribute set for a GC session from host:636. The
// helper session reads the schema with the same credential, is closed before return, and never
// serves any other request; the set it yields is unioned into s.schema exactly as on a DC session,
// so a GC session refuses every attribute a domain session would (safe-primitives §3.7).
func (s *Session) loadSecretAttrsFromDC(ctx context.Context, host string, cred Credential, krb *Kerberos) error {
	conn, err := dial(ctx, s.cfg, host, "636")
	if err != nil {
		return fail(CodeUnreachable, "schema read on the domain controller port", err)
	}
	h := &Session{conn: conn, cfg: s.cfg, schema: s.schema, server: net.JoinHostPort(host, "636"), pageSize: s.pageSize}
	defer h.Close()
	if err := h.bindAs(ctx, host, cred, krb); err != nil {
		return err
	}
	if err := h.loadSecretAttrs(ctx); err != nil {
		return err
	}
	s.schema = h.schema
	return nil
}
