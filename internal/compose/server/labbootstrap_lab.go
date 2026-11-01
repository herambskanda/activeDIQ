//go:build lab

package server

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"google.golang.org/grpc"

	"github.com/skenzeriq/activediq/internal/connector/ad"
	"github.com/skenzeriq/activediq/internal/connector/read"
	"github.com/skenzeriq/activediq/internal/connector/rights"
	"github.com/skenzeriq/activediq/internal/connector/write"
	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
	"github.com/skenzeriq/activediq/internal/directory/client"
	"github.com/skenzeriq/activediq/internal/directory/connection"
	"github.com/skenzeriq/activediq/internal/directory/dn"
	"github.com/skenzeriq/activediq/internal/directory/ldapfilter"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/secret"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
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

// labSeeder seeds the opened labs' connections once the tenant and the connection service exist.
type labSeeder func(ctx context.Context, conns *connection.Registry, svc *connection.Service, tid tenant.ID) error

// openedLab is one lab session with its in-process connector, ready to be bound to a connection.
type openedLab struct {
	spec labSpec
	cl   client.LabConnector
	stop func()
}

// labBootstrap opens the configured labs' directory sessions and in-process connectors (no database
// yet) and returns the source that serves them over next, the seeder that creates and activates each
// lab's connection, and a closer for the sessions. With no lab configured it returns next unchanged
// and a no-op seeder.
func labBootstrap(ctx context.Context, getenv func(string) string, next client.ConnectorSource) (client.ConnectorSource, labSeeder, func(), error) {
	specs, err := labSpecs(getenv)
	if err != nil {
		return nil, nil, nil, err
	}
	if len(specs) == 0 {
		return next, func(context.Context, *connection.Registry, *connection.Service, tenant.ID) error { return nil }, func() {}, nil
	}
	src := client.NewLabSource(next)
	var opened []openedLab
	closeAll := func() {
		for i := len(opened) - 1; i >= 0; i-- {
			opened[i].stop()
		}
	}
	for _, sp := range specs {
		cl, stop, err := openLab(ctx, sp)
		if err != nil {
			closeAll()
			return nil, nil, nil, fmt.Errorf("server: lab bootstrap (%s): %w", sp.Name, err)
		}
		opened = append(opened, openedLab{spec: sp, cl: cl, stop: stop})
	}
	seed := func(ctx context.Context, conns *connection.Registry, svc *connection.Service, tid tenant.ID) error {
		for _, o := range opened {
			id, err := ensureActive(ctx, conns, svc, src, tid, labDisplayName(o.spec), o.cl)
			if err != nil {
				return fmt.Errorf("server: lab bootstrap (%s): %w", o.spec.Name, err)
			}
			slog.Info("server: lab connection active (in-process connector)", "lab", o.spec.Name, "connection_id", id, "tenant_id", tid.String())
		}
		return nil
	}
	return src, seed, closeAll, nil
}

// labDisplayName is the stable name by which a re-boot finds its connection again.
func labDisplayName(sp labSpec) string { return "lab: " + sp.Name }

// openLab opens the lab session and serves it, verification and reads, from an in-process connector.
func openLab(ctx context.Context, sp labSpec) (client.LabConnector, func(), error) {
	srv, closeSrv, err := openLabServer(ctx, sp)
	if err != nil {
		return client.LabConnector{}, nil, err
	}
	cl, stop, err := client.DialInProcess(srv)
	if err != nil {
		closeSrv()
		return client.LabConnector{}, nil, err
	}
	return cl, func() { stop(); closeSrv() }, nil
}

// openLabServer opens the lab session and builds the connector's served side over it: the real rights
// check and the real read handler. openLab dials it in process; the tunnel e2e serves it over a fleet tunnel.
func openLabServer(ctx context.Context, sp labSpec) (*labServer, func(), error) {
	pem, err := os.ReadFile(sp.CAPath)
	if err != nil {
		return nil, nil, errors.New("CA file unreadable")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, nil, errors.New("CA file is not valid PEM")
	}
	sess, err := ad.Open(ctx, ad.Config{Servers: []string{sp.Server}, ServerName: sp.ServerName, RootCAs: pool, PageSize: 500,
		Credential: ad.Credential{BindName: sp.BindName, Password: sp.Password}})
	if err != nil {
		return nil, nil, fmt.Errorf("open directory session: code %s", ad.CodeOf(err))
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
		return nil, nil, fmt.Errorf("rootDSE: code %s", ad.CodeOf(err))
	}
	ref, err := dn.ParseObjectRef(rd.RootDomainNamingContext)
	if err != nil {
		return nil, nil, errors.New("root naming context is not a DN")
	}
	head, err := sess.Read(ctx, ref, []string{"objectGUID"}, ad.ReadOptions{})
	if err != nil {
		return nil, nil, fmt.Errorf("read forest root: code %s", ad.CodeOf(err))
	}
	g, err := head.GUID()
	if err != nil {
		return nil, nil, errors.New("forest root has no objectGUID")
	}
	ident := &connectorv1.DirectoryIdentity{Identity: &connectorv1.DirectoryIdentity_AdForest{AdForest: &connectorv1.AdForestIdentity{ForestRootNcGuid: write.GUIDToWire(g)}}}

	self, err := selfRef(ctx, sess, ref, sp.BindName)
	if err != nil {
		return nil, nil, err
	}
	prov := write.NewADProvider(sess, nil, ident, &labPinStore{})
	src, err := read.NewADSource(sess, prov)
	if err != nil {
		return nil, nil, errors.New("read source")
	}
	h, err := read.New(src)
	if err != nil {
		return nil, nil, errors.New("read handler")
	}
	// The verification handler: the real rights check over this session. Its epoch baseline and records
	// live in a private directory that goes with the process (a lab connector has no host to keep them).
	dir, err := os.MkdirTemp("", "activediq-lab-connector-")
	if err != nil {
		return nil, nil, errors.New("lab connector state directory")
	}
	gate, err := write.NewGateBook(labBaseline{}, nil)
	if err != nil {
		_ = os.RemoveAll(dir)
		return nil, nil, errors.New("lab write gate")
	}
	epoch := rights.NewEpochState(rights.FileBaselineStore{Path: filepath.Join(dir, "baseline.json")},
		rights.FileRecordSink{Path: filepath.Join(dir, "records.log")}, nil)
	vh, err := rights.NewVerifyHandler(rights.VerifyConfig{Dir: rights.NewSessionDirectory(sess), Epoch: epoch, Identity: self,
		Directory: ident, Gate: gate, OnLocalRecordFailed: gate.CloseLocalRecordFailed})
	if err != nil {
		_ = os.RemoveAll(dir)
		return nil, nil, errors.New("verify handler")
	}
	ok = true
	return &labServer{verify: rights.NewServer(vh), read: read.NewServer(h)}, func() { sess.Close(); _ = os.RemoveAll(dir) }, nil
}

// labBaseline is the in-memory write.Baseline of a lab connector: the ratchet needs no durability
// across a process that holds its own temp state.
type labBaseline struct{}

func (labBaseline) Append(string, []write.Mark) error { return nil }

// selfRef resolves the service account the session is bound as (its objectGUID) by its UPN.
func selfRef(ctx context.Context, sess *ad.Session, root dn.ObjectRef, bindName string) (dn.ObjectRef, error) {
	sc := ad.DefaultSchema()
	an, err := ldapfilter.ParseAttrName("userPrincipalName", sc)
	if err != nil {
		return dn.ObjectRef{}, errors.New("identity filter")
	}
	var found *guid.GUID
	err = sess.Search(ctx, ad.SearchRequest{Base: root, Scope: ad.ScopeSubtree,
		Filter: ldapfilter.Eq(an, ldapfilter.String(bindName)), Attributes: []string{"objectGUID"}}, func(e *ad.Entry) error {
		g, gerr := e.GUID()
		if gerr != nil {
			return gerr
		}
		if found == nil {
			found = &g
		}
		return nil
	})
	if err != nil {
		return dn.ObjectRef{}, fmt.Errorf("resolve service account: code %s", ad.CodeOf(err))
	}
	if found == nil {
		return dn.ObjectRef{}, errors.New("service account not found by its user principal name")
	}
	return dn.GUIDRef(*found), nil
}

// ensureActive returns the active connection named name, creating it and running the product's real
// activation (a VerifyConnection against the lab DC through the in-process connector) when the tenant
// has none or it is still a draft. Any other state is an error: the lab seed does not reshape a
// connection an operator has touched. The activation's verdict is the evidence; nothing is fabricated.
func ensureActive(ctx context.Context, conns *connection.Registry, svc *connection.Service, src *client.LabSource, tid tenant.ID, name string, cl client.LabConnector) (string, error) {
	all, err := conns.List(ctx, tid, false)
	if err != nil {
		return "", errors.New("list connections")
	}
	var id connection.ID
	for _, c := range all {
		if c.DisplayName != name {
			continue
		}
		switch c.State {
		case connection.StateActive:
			src.Bind(string(c.ID), cl)
			return string(c.ID), nil
		case connection.StateDraft:
			id = c.ID
		default:
			return "", fmt.Errorf("connection %q exists in state %s", name, c.State)
		}
	}
	if id == "" {
		cred, err := newUUID()
		if err != nil {
			return "", err
		}
		c, err := conns.Create(ctx, tid, connection.New{Kind: connection.KindADForest, DisplayName: name,
			CredentialID: connection.CredentialID(cred), Transport: connection.TransportLDAPS})
		if err != nil {
			return "", errors.New("create connection")
		}
		id = c.ID
	}
	src.Bind(string(id), cl)
	actor := authority.Chain{Requester: authority.Principal{ID: "lab-bootstrap", Kind: authority.System}}
	out, err := svc.Activate(ctx, tid, id, actor)
	if err != nil {
		// Check names and outcomes only: no finding text, which can carry directory names.
		var bad []string
		for c, o := range out.Verification.Outcomes {
			if o != connection.OutcomePass {
				bad = append(bad, fmt.Sprintf("%s=%s", c, o))
			}
		}
		sort.Strings(bad)
		return "", fmt.Errorf("activation refused (verdict %s; %s): %w", out.Verification.Verdict, strings.Join(bad, ","), err)
	}
	if out.Connection.State != connection.StateActive {
		return "", fmt.Errorf("connection is %s after activation", out.Connection.State)
	}
	return string(id), nil
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

// labServer routes each served RPC to its group's server, as the tunnel binding does.
type labServer struct {
	connectorv1.UnimplementedConnectorServer
	verify *rights.Server
	read   *read.Server
}

func (s *labServer) VerifyConnection(req *connectorv1.VerifyConnectionRequest, st grpc.ServerStreamingServer[connectorv1.VerifyConnectionResponse]) error {
	return s.verify.VerifyConnection(req, st)
}

func (s *labServer) Read(req *connectorv1.ReadRequest, st grpc.ServerStreamingServer[connectorv1.ReadResponse]) error {
	return s.read.Read(req, st)
}

func (s *labServer) ScopedSearch(req *connectorv1.ScopedSearchRequest, st grpc.ServerStreamingServer[connectorv1.ScopedSearchResponse]) error {
	return s.read.ScopedSearch(req, st)
}
