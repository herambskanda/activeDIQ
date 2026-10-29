//go:build lab

package server

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	"github.com/skenzeriq/activediq/internal/connector/ad"
	"github.com/skenzeriq/activediq/internal/connector/read"
	"github.com/skenzeriq/activediq/internal/connector/write"
	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
	"github.com/skenzeriq/activediq/internal/directory/client"
	"github.com/skenzeriq/activediq/internal/directory/connection"
	"github.com/skenzeriq/activediq/internal/directory/dn"
	"github.com/skenzeriq/activediq/internal/platform/secret"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
	"github.com/skenzeriq/activediq/internal/platform/tenant/provision"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// Lab bootstrap (T-0684), compiled only under the `lab` build tag. A server built with -tags lab and
// started with a lab's environment seeds one ACTIVE AD connection per configured lab in the install's
// tenant and serves each from an IN-PROCESS connector (read and scoped search over a real LDAPS session
// to the lab DC, behind a real gRPC hop on an in-memory pipe), so a booted server can search VM 119 and
// the Samba lab with no fleet tunnel. It does not run the verification: the connection is activated by
// the lab seed (identity read from the DC, then draft → verifying → active), which is why it exists
// only in lab builds. Production builds compile labbootstrap_off.go instead.
//
// Environment (nothing configured = nothing seeded):
//
//	Windows lab (VM 119): WIN_LAB_DC_ADDR [WIN_LAB_TLS_NAME] WIN_LAB_SVC_PASSWORD WIN_LAB_CA (CA PEM path)
//	Samba lab:            LAB_LDAPS_PORT LAB_SVC_PASSWORD LAB_CA (CA PEM path)
//
// A lab that is partly configured fails boot, naming the missing variable; it never half-seeds.
// Passwords are read into a secret.Secret and are never logged.

type labSpec struct {
	Name       string // display name suffix: "win" or "samba"
	Server     string // host:port
	ServerName string // certificate name; "" = host
	BindName   string
	Password   secret.Secret
	CAPath     string
}

const (
	winLabBind   = "svc-activediq@win.activediq.test"
	winLabTLS    = "dc1.win.activediq.test"
	sambaLabBind = "svc-activediq@lab.activediq.test"
)

// errLabConfig names a missing variable only, never a value.
func errLabConfig(lab, missing string) error {
	return fmt.Errorf("server: lab bootstrap (%s): %s is not set", lab, missing)
}

// labSpecs reads the configured labs from the environment.
func labSpecs(getenv func(string) string) ([]labSpec, error) {
	var out []labSpec
	if addr := getenv("WIN_LAB_DC_ADDR"); addr != "" {
		if getenv("WIN_LAB_SVC_PASSWORD") == "" {
			return nil, errLabConfig("windows", "WIN_LAB_SVC_PASSWORD")
		}
		if getenv("WIN_LAB_CA") == "" {
			return nil, errLabConfig("windows", "WIN_LAB_CA")
		}
		if !strings.Contains(addr, ":") {
			addr += ":636"
		}
		tls := getenv("WIN_LAB_TLS_NAME")
		if tls == "" {
			tls = winLabTLS
		}
		out = append(out, labSpec{Name: "win", Server: addr, ServerName: tls, BindName: winLabBind,
			Password: secret.FromBytes([]byte(getenv("WIN_LAB_SVC_PASSWORD"))), CAPath: getenv("WIN_LAB_CA")})
	}
	if port := getenv("LAB_LDAPS_PORT"); port != "" {
		if getenv("LAB_SVC_PASSWORD") == "" {
			return nil, errLabConfig("samba", "LAB_SVC_PASSWORD")
		}
		if getenv("LAB_CA") == "" {
			return nil, errLabConfig("samba", "LAB_CA")
		}
		out = append(out, labSpec{Name: "samba", Server: "localhost:" + port, BindName: sambaLabBind,
			Password: secret.FromBytes([]byte(getenv("LAB_SVC_PASSWORD"))), CAPath: getenv("LAB_CA")})
	}
	return out, nil
}

// labPinStore is the in-memory write.PinStore of a lab connector.
type labPinStore struct {
	mu sync.Mutex
	g  []guid.GUID
}

func (m *labPinStore) PinnedC13(context.Context) ([]guid.GUID, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]guid.GUID(nil), m.g...), nil
}

func (m *labPinStore) PinC13(_ context.Context, gs []guid.GUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.g = append(m.g, gs...)
	return nil
}

// labSource resolves the seeded lab connections to their in-process connector and everything else to
// next (the fleet tunnel source).
type labSource struct {
	mu   sync.RWMutex
	by   map[string]connectorv1.ConnectorClient
	next client.ConnectorSource
}

var _ client.ConnectorSource = (*labSource)(nil)

// Connector implements client.ConnectorSource.
func (s *labSource) Connector(ctx context.Context, connectionID string) (connectorv1.ConnectorClient, error) {
	s.mu.RLock()
	c, ok := s.by[connectionID]
	s.mu.RUnlock()
	if ok {
		return c, nil
	}
	if s.next == nil {
		return nil, errors.New("server: no connector for connection")
	}
	return s.next.Connector(ctx, connectionID)
}

func (s *labSource) add(id string, c connectorv1.ConnectorClient) {
	s.mu.Lock()
	s.by[id] = c
	s.mu.Unlock()
}

// labBootstrap seeds the configured labs and returns the source that serves them (over next), and a
// closer for the sessions. With no lab configured it returns next unchanged and seeds nothing.
func labBootstrap(ctx context.Context, db *store.DB, conns *connection.Registry, getenv func(string) string, next client.ConnectorSource) (client.ConnectorSource, func(), error) {
	specs, err := labSpecs(getenv)
	if err != nil {
		return nil, nil, err
	}
	if len(specs) == 0 {
		return next, func() {}, nil
	}
	res, err := provision.FirstRun(ctx, db, "lab")
	if err != nil {
		return nil, nil, fmt.Errorf("server: lab bootstrap: tenant: %w", err)
	}
	src := &labSource{by: map[string]connectorv1.ConnectorClient{}, next: next}
	var closers []func()
	closeAll := func() {
		for i := len(closers) - 1; i >= 0; i-- {
			closers[i]()
		}
	}
	for _, sp := range specs {
		id, cl, closeFn, err := openLab(ctx, db, conns, res.Tenant, sp)
		if err != nil {
			closeAll()
			return nil, nil, fmt.Errorf("server: lab bootstrap (%s): %w", sp.Name, err)
		}
		closers = append(closers, closeFn)
		src.add(id, cl)
		slog.Info("server: lab connection active (in-process connector)", "lab", sp.Name, "connection_id", id, "tenant_id", res.Tenant.String())
	}
	return src, closeAll, nil
}

// labDisplayName is the stable name by which a re-boot finds its connection again.
func labDisplayName(sp labSpec) string { return "lab: " + sp.Name }

// openLab opens the lab session, ensures the active connection and serves it in process.
func openLab(ctx context.Context, db *store.DB, conns *connection.Registry, tid tenant.ID, sp labSpec) (string, connectorv1.ConnectorClient, func(), error) {
	pem, err := os.ReadFile(sp.CAPath)
	if err != nil {
		return "", nil, nil, errors.New("CA file unreadable")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return "", nil, nil, errors.New("CA file is not valid PEM")
	}
	sess, err := ad.Open(ctx, ad.Config{Servers: []string{sp.Server}, ServerName: sp.ServerName, RootCAs: pool, PageSize: 500,
		Credential: ad.Credential{BindName: sp.BindName, Password: sp.Password}})
	if err != nil {
		return "", nil, nil, fmt.Errorf("open directory session: code %s", ad.CodeOf(err))
	}
	ok := false
	defer func() {
		if !ok {
			sess.Close()
		}
	}()
	// The directory identity is the forest root NC head's objectGUID, read from the DC.
	rd, err := sess.RootDSE(ctx)
	if err != nil {
		return "", nil, nil, fmt.Errorf("rootDSE: code %s", ad.CodeOf(err))
	}
	ref, err := dn.ParseObjectRef(rd.RootDomainNamingContext)
	if err != nil {
		return "", nil, nil, errors.New("root naming context is not a DN")
	}
	head, err := sess.Read(ctx, ref, []string{"objectGUID"}, ad.ReadOptions{})
	if err != nil {
		return "", nil, nil, fmt.Errorf("read forest root: code %s", ad.CodeOf(err))
	}
	g, err := head.GUID()
	if err != nil {
		return "", nil, nil, errors.New("forest root has no objectGUID")
	}
	wire := write.GUIDToWire(g)
	ident := &connectorv1.DirectoryIdentity{Identity: &connectorv1.DirectoryIdentity_AdForest{AdForest: &connectorv1.AdForestIdentity{ForestRootNcGuid: wire}}}
	v := wire.GetValue()
	identText := fmt.Sprintf("%x-%x-%x-%x-%x", v[0:4], v[4:6], v[6:8], v[8:10], v[10:16])

	cid, err := ensureActive(ctx, conns, tid, labDisplayName(sp), connection.DirectoryIdentity(identText))
	if err != nil {
		return "", nil, nil, err
	}

	prov := write.NewADProvider(sess, nil, ident, &labPinStore{})
	src, err := read.NewADSource(sess, prov)
	if err != nil {
		return "", nil, nil, errors.New("read source")
	}
	h, err := read.New(src)
	if err != nil {
		return "", nil, nil, errors.New("read handler")
	}
	cl, stop, err := inProcessConnector(h)
	if err != nil {
		return "", nil, nil, err
	}
	ok = true
	return cid, cl, func() { stop(); sess.Close() }, nil
}

// ensureActive returns the active connection named name, creating it (draft → verifying → active) when
// the tenant has none. A connection that exists in another state is an error: the lab seed does not
// reshape a connection an operator has touched.
func ensureActive(ctx context.Context, conns *connection.Registry, tid tenant.ID, name string, identity connection.DirectoryIdentity) (string, error) {
	all, err := conns.List(ctx, tid, false)
	if err != nil {
		return "", errors.New("list connections")
	}
	for _, c := range all {
		if c.DisplayName != name {
			continue
		}
		if c.State != connection.StateActive || c.DirectoryIdentity != identity {
			return "", fmt.Errorf("connection %q exists in state %s or with another identity", name, c.State)
		}
		return string(c.ID), nil
	}
	cred, err := newUUID()
	if err != nil {
		return "", err
	}
	c, err := conns.Create(ctx, tid, connection.New{Kind: connection.KindADForest, DisplayName: name,
		CredentialID: connection.CredentialID(cred), Transport: connection.TransportLDAPS})
	if err != nil {
		return "", errors.New("create connection")
	}
	if _, err := conns.Transition(ctx, tid, c.ID, connection.StateDraft, connection.StateVerifying); err != nil {
		return "", errors.New("connection to verifying")
	}
	if _, err := conns.SetDirectoryIdentity(ctx, tid, c.ID, identity); err != nil {
		return "", errors.New("connection identity")
	}
	if _, err := conns.Transition(ctx, tid, c.ID, connection.StateVerifying, connection.StateActive); err != nil {
		return "", errors.New("connection to active")
	}
	return string(c.ID), nil
}

func newUUID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:]), nil
}

// inProcessConnector serves the read handler on an in-memory gRPC pipe and returns its client. The
// hop is real gRPC (marshalling, status errors, streaming) but never leaves the process.
func inProcessConnector(h *read.Handler) (connectorv1.ConnectorClient, func(), error) {
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	read.Register(srv, h)
	go func() { _ = srv.Serve(lis) }()
	cc, err := grpc.NewClient("passthrough:///lab-connector",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		srv.Stop()
		return nil, nil, errors.New("in-process connector dial")
	}
	return connectorv1.NewConnectorClient(cc), func() { _ = cc.Close(); srv.Stop() }, nil
}
