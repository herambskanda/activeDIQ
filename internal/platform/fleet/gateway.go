package fleet

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// The fleet gateway's transport rules (AN-6 L2, TM-O2, TM-TB6-T8). The gateway is contract-agnostic:
// it never imports the generated fleet stubs (blueprint §2 rule 1). Whoever composes the server
// registers the fleet service on the server NewServer builds, and states the auth class of every
// method in Config.Methods.
//
// Three rules, all enforced here and not in any handler:
//   - Every method has an explicit auth class, or the server does not start (deny by default).
//   - Only the Enroll method may be ClassPublic; every other method needs a client certificate that
//     one of the SAN tenant's own CAs signed.
//   - Only services of the fleet package are mounted on this listener.

// EnrollMethod is the one method that works without a client certificate.
const EnrollMethod = "/activediq.fleet.v1.Fleet/Enroll"

// servicePrefix is the proto package every service on the fleet listener must be in.
const servicePrefix = "activediq.fleet.v1."

// AuthClass says what a method requires of its caller. The zero value is deliberately not a class.
type AuthClass int

// Auth classes.
const (
	// ClassClientCert: a verified client certificate bound to its tenant's CA.
	ClassClientCert AuthClass = iota + 1
	// ClassPublic: no certificate required. Allowed for EnrollMethod only.
	ClassPublic
)

// TenantCAs gives the CA certificates of one tenant, active and retired (fleet_ca rows).
type TenantCAs interface {
	TenantCAs(ctx context.Context, tid tenant.ID) ([]*x509.Certificate, error)
}

// Config configures the fleet gateway.
type Config struct {
	// Methods maps every full gRPC method ("/pkg.Service/Method") to its auth class.
	Methods map[string]AuthClass
	CAs     TenantCAs
	Clock   func() time.Time // tests only
}

// Errors of NewServer. They name services and methods, never data.
var (
	ErrGatewayConfig = errors.New("fleet: gateway is not configured")
	ErrUnclassified  = errors.New("fleet: registered method has no explicit auth class")
	ErrPublicMethod  = errors.New("fleet: only Enroll may be public")
	ErrForeignMount  = errors.New("fleet: the fleet listener mounts only fleet services")
)

// The fixed refusals. They repeat nothing from the certificate or the request.
var (
	errNoCert  = status.Error(codes.Unauthenticated, "client certificate required")
	errBadCert = status.Error(codes.Unauthenticated, "client certificate not accepted")
	errUnavail = status.Error(codes.Unavailable, "authentication unavailable")
	errDenied  = status.Error(codes.PermissionDenied, "method not available")
)

type ctxKey struct{}

// IdentityFrom returns the authenticated identity of the calling component. It exists only for
// methods that required a client certificate; tenant and component never come from a message.
func IdentityFrom(ctx context.Context) (Identity, bool) {
	id, ok := ctx.Value(ctxKey{}).(Identity)
	return id, ok
}

// Gateway holds the per-RPC authentication.
type Gateway struct {
	methods map[string]AuthClass
	cas     TenantCAs
	now     func() time.Time
}

// NewGateway checks the static rules of the config. Registered methods are checked by NewServer.
func NewGateway(cfg Config) (*Gateway, error) {
	if cfg.CAs == nil || len(cfg.Methods) == 0 {
		return nil, ErrGatewayConfig
	}
	m := make(map[string]AuthClass, len(cfg.Methods))
	for name, c := range cfg.Methods {
		switch {
		case c != ClassClientCert && c != ClassPublic:
			return nil, fmt.Errorf("%w: %s", ErrUnclassified, name)
		case c == ClassPublic && name != EnrollMethod:
			return nil, fmt.Errorf("%w: %s", ErrPublicMethod, name)
		}
		m[name] = c
	}
	now := cfg.Clock
	if now == nil {
		now = time.Now
	}
	return &Gateway{methods: m, cas: cfg.CAs, now: now}, nil
}

// NewServer builds the gRPC server of the fleet listener: TLS built here from the server certificate
// and client-CA source (no caller-supplied tls.Config, and the gateway's own credentials and
// interceptors are applied after opts so no option can replace them), both interceptors, and
// whatever register mounts. It fails closed if register mounts a method without an explicit class, a
// public method other than Enroll, or a service outside the fleet package. Nothing is served until
// the caller calls Serve on the result.
func (g *Gateway) NewServer(server tls.Certificate, clientCAs func() *x509.CertPool, register func(grpc.ServiceRegistrar), opts ...grpc.ServerOption) (*grpc.Server, error) {
	if len(server.Certificate) == 0 || clientCAs == nil || register == nil {
		return nil, ErrGatewayConfig
	}
	base := []grpc.ServerOption{
		grpc.Creds(credentials.NewTLS(serverTLS(server, clientCAs))),
		grpc.ChainUnaryInterceptor(g.Unary),
		grpc.ChainStreamInterceptor(g.Stream),
	}
	srv := grpc.NewServer(append(append([]grpc.ServerOption{}, opts...), base...)...)
	register(srv)
	if err := g.checkMounted(srv); err != nil {
		srv.Stop()
		return nil, err
	}
	return srv, nil
}

// Routes lists every method mounted on srv, sorted. With the checks of NewServer it is the whole
// surface of the fleet listener (TM-TB6-T8).
func Routes(srv *grpc.Server) []string {
	var out []string
	for name, info := range srv.GetServiceInfo() {
		for _, m := range info.Methods {
			out = append(out, "/"+name+"/"+m.Name)
		}
	}
	sort.Strings(out)
	return out
}

func (g *Gateway) checkMounted(srv *grpc.Server) error {
	for name, info := range srv.GetServiceInfo() {
		if !strings.HasPrefix(name, servicePrefix) {
			return fmt.Errorf("%w: %s", ErrForeignMount, name)
		}
		for _, m := range info.Methods {
			full := "/" + name + "/" + m.Name
			if _, ok := g.methods[full]; !ok {
				return fmt.Errorf("%w: %s", ErrUnclassified, full)
			}
		}
	}
	return nil
}

// Unary is the unary interceptor.
func (g *Gateway) Unary(ctx context.Context, req any, info *grpc.UnaryServerInfo, h grpc.UnaryHandler) (any, error) {
	ctx, err := g.authenticate(ctx, info.FullMethod)
	if err != nil {
		return nil, err
	}
	return h(ctx, req)
}

// Stream is the stream interceptor.
func (g *Gateway) Stream(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, h grpc.StreamHandler) error {
	ctx, err := g.authenticate(ss.Context(), info.FullMethod)
	if err != nil {
		return err
	}
	return h(srv, &identityStream{ServerStream: ss, ctx: ctx})
}

type identityStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *identityStream) Context() context.Context { return s.ctx }

// authenticate runs before any handler. A method the gateway does not know is refused, whatever the
// caller presents.
func (g *Gateway) authenticate(ctx context.Context, method string) (context.Context, error) {
	switch g.methods[method] {
	case ClassPublic:
		return ctx, nil
	case ClassClientCert:
	default:
		return nil, errDenied
	}
	p, ok := peer.FromContext(ctx)
	if !ok {
		return nil, errNoCert
	}
	ti, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok || len(ti.State.PeerCertificates) == 0 {
		return nil, errNoCert
	}
	if len(ti.State.VerifiedChains) == 0 || len(ti.State.VerifiedChains[0]) == 0 {
		return nil, errBadCert
	}
	leaf := ti.State.VerifiedChains[0][0]
	now := g.now()
	if now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) || !hasClientAuth(leaf) {
		return nil, errBadCert
	}
	id, err := IdentityOf(leaf)
	if err != nil || id.Tenant.IsZero() {
		return nil, errBadCert
	}
	// A verified chain only proves that some tenant's CA signed the leaf (every tenant's CA is in
	// the listener's pool). The SAN names the tenant, so the signer must be that tenant's own CA
	// (TM-Q8): otherwise one tenant's CA could mint an identity in another.
	cas, err := g.cas.TenantCAs(ctx, id.Tenant)
	if err != nil {
		return nil, errUnavail
	}
	for _, c := range cas {
		if c != nil && !now.Before(c.NotBefore) && !now.After(c.NotAfter) && leaf.CheckSignatureFrom(c) == nil {
			return context.WithValue(ctx, ctxKey{}, id), nil
		}
	}
	return nil, errBadCert
}

func hasClientAuth(c *x509.Certificate) bool {
	for _, u := range c.ExtKeyUsage {
		if u == x509.ExtKeyUsageClientAuth || u == x509.ExtKeyUsageAny {
			return true
		}
	}
	return false
}

// serverTLS returns the fleet listener's TLS configuration: TLS 1.3, a client certificate requested
// and verified when presented (Enroll must work without one; the interceptor refuses its absence for
// every other method). clientCAs is read per handshake so CA changes take effect without a restart.
func serverTLS(server tls.Certificate, clientCAs func() *x509.CertPool) *tls.Config {
	conf := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{server},
		ClientAuth:   tls.VerifyClientCertIfGiven,
		ClientCAs:    x509.NewCertPool(),
	}
	conf.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) {
		c := conf.Clone()
		c.GetConfigForClient = nil
		if p := clientCAs(); p != nil {
			c.ClientCAs = p
		}
		return c, nil
	}
	return conf
}
