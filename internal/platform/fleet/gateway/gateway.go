package gateway

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/skenzeriq/activediq/internal/platform/fleet"
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

// ComponentStatus says whether a component may still use the fleet listener: its lifecycle state is
// enrolled or active (DM-12). It is asked on every client-certificate RPC and every stream
// establishment, so a revoked component whose certificate is still valid is refused (TM-TB6-T9). An
// error means "could not tell" and the caller fails closed.
type ComponentStatus interface {
	Usable(ctx context.Context, id fleet.Identity) (bool, error)
	// Current is Usable and the identity's certificate serial is the component's current one
	// (components.cert_serial). A certificate superseded by a rotation is not current, whatever its
	// validity (TM-TB6-T14). It is asked when a connection or RPC is established, never for an open
	// stream: Usable is the open-stream re-check, so a rotation does not drop the stream it was made on.
	Current(ctx context.Context, id fleet.Identity) (bool, error)
}

// SupersededReporter makes a theft signal visible outside the RPC: a genuine, unexpired certificate of
// a usable component was presented, but it is no longer the component's current one (TM-TB6-T14). The
// holder is either a stale component or whoever rotated first. The implementation raises a fleet alert
// and appends an audit event naming the component and both serials. The gateway calls it at most once
// per component per Config.SupersededWindow, and an error is logged; it never changes the refusal.
type SupersededReporter interface {
	Superseded(ctx context.Context, presented fleet.Identity) error
}

// DefaultSupersededWindow is the minimum time between two reports for one component.
const DefaultSupersededWindow = 10 * time.Minute

// maxSupersededTracked bounds the rate-limit table; at the cap the oldest entry is evicted.
const maxSupersededTracked = 4096

// DefaultRecheck is how often an open stream is re-checked against ComponentStatus. It bounds how
// long a stream outlives a revocation made through another server instance; a revocation made through
// this one closes its streams at once (CloseComponent).
const DefaultRecheck = 5 * time.Second

// Config configures the fleet gateway.
type Config struct {
	// Methods maps every full gRPC method ("/pkg.Service/Method") to its auth class.
	Methods    map[string]AuthClass
	CAs        TenantCAs
	Components ComponentStatus
	// Recheck is the open-stream re-check period; 0 means DefaultRecheck.
	Recheck time.Duration
	// CAStale is how long an open stream survives continuous failures of the per-tenant CA lookup on
	// re-check; 0 means DefaultPoolStale (60 s), the same rule as the client-CA pool.
	CAStale time.Duration
	// Superseded, when set, is told about superseded-certificate presentations (TM-TB6-T14), at most
	// once per component per SupersededWindow (0 means DefaultSupersededWindow).
	Superseded       SupersededReporter
	SupersededWindow time.Duration
	Logger           *slog.Logger     // nil: slog.Default()
	Clock            func() time.Time // tests only
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
	// errRevoked ends an open stream. It is also the cause the stream's context carries.
	errRevoked = status.Error(codes.Unauthenticated, "client certificate not accepted")
)

// Gateway holds the per-RPC authentication.
type Gateway struct {
	methods map[string]AuthClass
	cas     TenantCAs
	comps   ComponentStatus
	recheck time.Duration
	caStale time.Duration
	now     func() time.Time
	streams streamRegistry

	superseded SupersededReporter
	window     time.Duration
	log        *slog.Logger
	smu        sync.Mutex
	reported   map[streamKey]time.Time // last report per component
}

// NewGateway checks the static rules of the config. Registered methods are checked by NewServer.
func NewGateway(cfg Config) (*Gateway, error) {
	if cfg.CAs == nil || cfg.Components == nil || len(cfg.Methods) == 0 {
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
	recheck := cfg.Recheck
	if recheck <= 0 {
		recheck = DefaultRecheck
	}
	caStale := cfg.CAStale
	if caStale <= 0 {
		caStale = DefaultPoolStale
	}
	window := cfg.SupersededWindow
	if window <= 0 {
		window = DefaultSupersededWindow
	}
	lg := cfg.Logger
	if lg == nil {
		lg = slog.Default()
	}
	return &Gateway{methods: m, cas: cfg.CAs, comps: cfg.Components, recheck: recheck, caStale: caStale, now: now, streams: newStreamRegistry(),
		superseded: cfg.Superseded, window: window, log: lg, reported: map[streamKey]time.Time{}}, nil
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
		grpc.Creds(verifiedCreds{credentials.NewTLS(serverTLS(server, clientCAs)), clientCAs}),
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
	ctx, _, err := g.authenticate(ctx, info.FullMethod)
	if err != nil {
		return nil, err
	}
	return h(ctx, req)
}

// Stream is the stream interceptor.
func (g *Gateway) Stream(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, h grpc.StreamHandler) error {
	ctx, leaf, err := g.authenticate(ss.Context(), info.FullMethod)
	if err != nil {
		return err
	}
	id, ok := fleet.IdentityFrom(ctx)
	if !ok { // a public method: no component to revoke
		return h(srv, &identityStream{ServerStream: ss, ctx: ctx})
	}
	// An authenticated stream is registered under its component and ends when the component is
	// revoked (TM-TB6-T9): at once through CloseComponent, and within one recheck period when the
	// revocation was made elsewhere.
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	st := &identityStream{ServerStream: ss, ctx: ctx}
	unreg := g.streams.add(id, cancel)
	defer unreg()
	go g.watch(ctx, id, leaf, cancel)
	// The handler runs on its own goroutine so that revocation ends the RPC whether or not the
	// handler cooperates: a handler blocked in RecvMsg or SendMsg on the underlying transport never
	// observes our derived context. Returning from this interceptor makes grpc finish the
	// transport stream, which unblocks that handler's Recv/Send with an error so it exits.
	done := make(chan error, 1)
	go func() { done <- h(srv, st) }()
	select {
	case err = <-done:
		if errors.Is(context.Cause(ctx), errRevoked) {
			return errRevoked
		}
		return err
	case <-ctx.Done():
		if errors.Is(context.Cause(ctx), errRevoked) {
			return errRevoked
		}
		return <-done // the transport context ended (client gone): the handler is returning
	}
}

// CloseComponent closes every open stream of the component and reports how many it closed. The
// revoking code calls it after the Component row is committed as revoked.
func (g *Gateway) CloseComponent(tid tenant.ID, componentID string) int {
	return g.streams.close(tid, componentID)
}

// CloseTenant closes every open stream of the tenant and reports how many it closed. The process that
// commits a CA withdrawal calls it in the same step as the pool's Invalidate (F-POOL-8); other
// processes drop the tenant's withdrawn-CA streams on their next re-check.
func (g *Gateway) CloseTenant(tid tenant.ID) int {
	return g.streams.closeTenant(tid)
}

// watch re-checks the component while its stream is open (it ends when ctx does, which the stream's
// deferred cancel guarantees). Each tick asks two things: is the component still usable, and is the
// stream's leaf still signed by one of its tenant's own current CAs (a withdrawn CA's leaf loses its
// stream here on every node, TM-Q8, F-POOL-8). Either answering "no" ends the stream. A failure to
// tell leaves it open, so a database blip does not drop the whole fleet, but the CA question fails
// closed once it has gone unanswered for CAStale, as the pool does.
func (g *Gateway) watch(ctx context.Context, id fleet.Identity, leaf *x509.Certificate, cancel context.CancelCauseFunc) {
	t := time.NewTicker(g.recheck)
	defer t.Stop()
	lastCA := g.now()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			cctx, c := context.WithTimeout(ctx, g.recheck)
			ok, err := g.comps.Usable(cctx, id)
			var cas []*x509.Certificate
			var caErr error
			if err == nil && ok {
				cas, caErr = g.cas.TenantCAs(cctx, id.Tenant)
			}
			c()
			if err == nil && !ok {
				cancel(errRevoked)
				return
			}
			switch {
			case err != nil || caErr != nil:
				if g.now().Sub(lastCA) > g.caStale {
					cancel(errRevoked)
					return
				}
			case !g.signedByAny(leaf, cas):
				cancel(errRevoked)
				return
			default:
				lastCA = g.now()
			}
		}
	}
}

// signedByAny reports whether one of cas, valid now, signed leaf.
func (g *Gateway) signedByAny(leaf *x509.Certificate, cas []*x509.Certificate) bool {
	now := g.now()
	for _, c := range cas {
		if c != nil && !now.Before(c.NotBefore) && !now.After(c.NotAfter) && leaf.CheckSignatureFrom(c) == nil {
			return true
		}
	}
	return false
}

// identityStream carries the authenticated context and refuses traffic once that context has ended,
// so a handler that is blocked in Recv or Send returns promptly when its component is revoked.
type identityStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *identityStream) Context() context.Context { return s.ctx }

func (s *identityStream) closed() error {
	if s.ctx.Err() == nil {
		return nil
	}
	if errors.Is(context.Cause(s.ctx), errRevoked) {
		return errRevoked
	}
	return s.ctx.Err()
}

func (s *identityStream) SendMsg(m any) error {
	if err := s.closed(); err != nil {
		return err
	}
	return s.ServerStream.SendMsg(m)
}

func (s *identityStream) RecvMsg(m any) error {
	if err := s.closed(); err != nil {
		return err
	}
	return s.ServerStream.RecvMsg(m)
}

type streamKey struct {
	tenant tenant.ID
	comp   string
}

// streamRegistry holds the cancel function of every open authenticated stream, by component.
type streamRegistry struct {
	mu sync.Mutex
	m  map[streamKey]map[*context.CancelCauseFunc]struct{}
}

func newStreamRegistry() streamRegistry {
	return streamRegistry{m: map[streamKey]map[*context.CancelCauseFunc]struct{}{}}
}

func (r *streamRegistry) add(id fleet.Identity, cancel context.CancelCauseFunc) (remove func()) {
	k := streamKey{id.Tenant, id.ComponentID}
	p := &cancel
	r.mu.Lock()
	if r.m[k] == nil {
		r.m[k] = map[*context.CancelCauseFunc]struct{}{}
	}
	r.m[k][p] = struct{}{}
	r.mu.Unlock()
	return func() {
		r.mu.Lock()
		delete(r.m[k], p)
		if len(r.m[k]) == 0 {
			delete(r.m, k)
		}
		r.mu.Unlock()
	}
}

func (r *streamRegistry) closeTenant(tid tenant.ID) int {
	r.mu.Lock()
	var cancels []context.CancelCauseFunc
	for k, set := range r.m {
		if k.tenant != tid {
			continue
		}
		for p := range set {
			cancels = append(cancels, *p)
		}
	}
	r.mu.Unlock()
	for _, c := range cancels {
		c(errRevoked)
	}
	return len(cancels)
}

func (r *streamRegistry) close(tid tenant.ID, comp string) int {
	k := streamKey{tid, comp}
	r.mu.Lock()
	cancels := make([]context.CancelCauseFunc, 0, len(r.m[k]))
	for p := range r.m[k] {
		cancels = append(cancels, *p)
	}
	r.mu.Unlock()
	for _, c := range cancels {
		c(errRevoked)
	}
	return len(cancels)
}

// authenticate runs before any handler. A method the gateway does not know is refused, whatever the
// caller presents.
func (g *Gateway) authenticate(ctx context.Context, method string) (context.Context, *x509.Certificate, error) {
	switch g.methods[method] {
	case ClassPublic:
		return ctx, nil, nil
	case ClassClientCert:
	default:
		return nil, nil, errDenied
	}
	p, ok := peer.FromContext(ctx)
	if !ok {
		return nil, nil, errNoCert
	}
	ti, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok || len(ti.State.PeerCertificates) == 0 {
		return nil, nil, errNoCert
	}
	if len(ti.State.VerifiedChains) == 0 || len(ti.State.VerifiedChains[0]) == 0 {
		return nil, nil, errBadCert
	}
	leaf := ti.State.VerifiedChains[0][0]
	now := g.now()
	if now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) || !hasClientAuth(leaf) {
		return nil, nil, errBadCert
	}
	id, err := fleet.IdentityOf(leaf)
	if err != nil || id.Tenant.IsZero() {
		return nil, nil, errBadCert
	}
	// A verified chain only proves that some tenant's CA signed the leaf (every tenant's CA is in
	// the listener's pool). The SAN names the tenant, so the signer must be that tenant's own CA
	// (TM-Q8): otherwise one tenant's CA could mint an identity in another.
	cas, err := g.cas.TenantCAs(ctx, id.Tenant)
	if err != nil {
		return nil, nil, errUnavail
	}
	for _, c := range cas {
		if c != nil && !now.Before(c.NotBefore) && !now.After(c.NotAfter) && leaf.CheckSignatureFrom(c) == nil {
			// The certificate is genuine; the component may still have been revoked since it was
			// issued (TM-TB6-T9). Checked on every RPC, so a revoked component is refused whatever
			// it dials.
			// Establishment needs the current certificate (TM-TB6-T14); the stream re-check does not.
			usable, err := g.comps.Current(ctx, id)
			if err != nil {
				return nil, nil, errUnavail
			}
			if !usable {
				g.reportSuperseded(ctx, id)
				return nil, nil, errBadCert
			}
			return fleet.WithIdentity(ctx, id), leaf, nil
		}
	}
	return nil, nil, errBadCert
}

// reportSuperseded is called for a CA-verified, unexpired leaf that is not the component's current
// certificate. If the component is still usable, the presentation is a theft signal (TM-TB6-T14) and
// is reported, rate-limited per component. The caller refuses with errBadCert whatever happens here.
func (g *Gateway) reportSuperseded(ctx context.Context, id fleet.Identity) {
	if g.superseded == nil {
		return
	}
	rollback, ok := g.reserveReport(id)
	if !ok {
		return
	}
	// The caller (possibly a thief hanging up) must not be able to cancel the report or burn the
	// window: run detached with a deadline, and give the window back if the report did not happen.
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	usable, err := g.comps.Usable(rctx, id)
	if err != nil {
		rollback()
		g.log.Error("fleet: superseded certificate could not be checked", slog.String("tenant_id", id.Tenant.String()), slog.String("component", id.ComponentID))
		return
	}
	if !usable {
		return // revoked or unknown: nothing to add to the refusal; the window stays used
	}
	if err := g.superseded.Superseded(rctx, id); err != nil {
		rollback()
		g.log.Error("fleet: superseded certificate could not be reported", slog.String("tenant_id", id.Tenant.String()), slog.String("component", id.ComponentID))
	}
}

// reserveReport claims the component's report window. The returned func releases the claim (restoring
// the previous window) so a failed report never silences the next one.
func (g *Gateway) reserveReport(id fleet.Identity) (rollback func(), ok bool) {
	now, k := g.now(), streamKey{id.Tenant, id.ComponentID}
	g.smu.Lock()
	defer g.smu.Unlock()
	prev, had := g.reported[k]
	if had && now.Sub(prev) < g.window {
		return nil, false
	}
	if !had && len(g.reported) >= maxSupersededTracked {
		var oldest streamKey
		var ot time.Time
		for kk, t := range g.reported {
			if ot.IsZero() || t.Before(ot) {
				oldest, ot = kk, t
			}
		}
		delete(g.reported, oldest)
	}
	g.reported[k] = now
	return func() {
		g.smu.Lock()
		defer g.smu.Unlock()
		if g.reported[k] != now {
			return
		}
		if had {
			g.reported[k] = prev
		} else {
			delete(g.reported, k)
		}
	}, true
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
// when the peer has one (Enroll must work without; the interceptor refuses its absence for every other
// method). clientCAs is read per handshake so CA changes take effect without a restart.
//
// The client chain is verified against that pool by VerifyConnection, not by Go's ClientAuth: with
// ClientCAs set Go announces every CA subject in the CertificateRequest, and the extension's length
// field is 16 bits, so a pool of roughly a thousand same-subject CAs cannot complete any handshake
// (T-0714, F-POOL-7). The pool is therefore never given to the tls.Config; the forged-chain refusal
// stays in memory and before any database work, and verifiedCreds puts the chain it built into the
// connection's TLSInfo.VerifiedChains for the interceptors.
func serverTLS(server tls.Certificate, clientCAs func() *x509.CertPool) *tls.Config {
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{server},
		ClientAuth:   tls.RequestClientCert,
		VerifyConnection: func(cs tls.ConnectionState) error {
			_, err := verifyClientChain(cs, clientCAs())
			return err
		},
	}
}

// verifyClientChain verifies the peer's client certificate chain against pool (nil: refuse). No
// certificate is not an error: the interceptor decides whether the method needs one.
func verifyClientChain(cs tls.ConnectionState, pool *x509.CertPool) ([][]*x509.Certificate, error) {
	if len(cs.PeerCertificates) == 0 {
		return nil, nil
	}
	if pool == nil {
		return nil, errors.New("fleet: no client CAs")
	}
	inter := x509.NewCertPool()
	for _, c := range cs.PeerCertificates[1:] {
		inter.AddCert(c)
	}
	return cs.PeerCertificates[0].Verify(x509.VerifyOptions{
		Roots: pool, Intermediates: inter, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
}

// verifiedCreds wraps the TLS credentials so a connection's TLSInfo carries VerifiedChains, which Go
// only fills when it does the client verification itself.
type verifiedCreds struct {
	credentials.TransportCredentials
	clientCAs func() *x509.CertPool
}

func (c verifiedCreds) ServerHandshake(raw net.Conn) (net.Conn, credentials.AuthInfo, error) {
	conn, info, err := c.TransportCredentials.ServerHandshake(raw)
	if err != nil {
		return nil, nil, err
	}
	ti, ok := info.(credentials.TLSInfo)
	if !ok {
		_ = conn.Close()
		return nil, nil, errors.New("fleet: unexpected transport credentials")
	}
	chains, err := verifyClientChain(ti.State, c.clientCAs())
	if err != nil {
		_ = conn.Close()
		return nil, nil, err
	}
	ti.State.VerifiedChains = chains
	return conn, ti, nil
}

func (c verifiedCreds) Clone() credentials.TransportCredentials {
	return verifiedCreds{c.TransportCredentials.Clone(), c.clientCAs}
}
