//go:build lab

package server

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"math/big"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/skenzeriq/activediq/internal/compose/config"
	"github.com/skenzeriq/activediq/internal/compose/tunnelbind"
	"github.com/skenzeriq/activediq/internal/connector/labadmin"
	"github.com/skenzeriq/activediq/internal/connector/write"
	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
	"github.com/skenzeriq/activediq/internal/directory/client"
	"github.com/skenzeriq/activediq/internal/directory/connection"
	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/fleet"
	"github.com/skenzeriq/activediq/internal/platform/fleet/fleetsql"
	"github.com/skenzeriq/activediq/internal/platform/fleet/gateway"
	"github.com/skenzeriq/activediq/internal/platform/jobs"
	"github.com/skenzeriq/activediq/internal/platform/keys"
	"github.com/skenzeriq/activediq/internal/platform/secret"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
	"github.com/skenzeriq/activediq/internal/platform/tenant/tenanttest"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
	fleetv1 "github.com/skenzeriq/activediq/internal/proto/activediq/fleet/v1"
	"github.com/skenzeriq/activediq/internal/testlab"
)

// T-1119: the directory read path of the running server, end to end against the Samba lab, over a real
// fleet tunnel. The pieces are the ones Run composes: one gateway.Hub shared by the tunnel dependencies
// (buildTunnelDeps -> NewFleetService -> ServeTunnel) and by the connector source (client.NewTunnelSource
// inside directoryReads), the connection registry's Bindings scan over a real database, and the
// connector's own Read and Verify handlers over a real LDAPS session to the lab DC. The gateway is the
// real one with mutual TLS; the component is the Mux a connector runs, dialled with a tenant-signed
// certificate. Nothing is stubbed between the facts reader and the DC.

// countedConnector counts the Read RPCs that reach the connector, so a refusal can be proved to have
// read nothing.
type countedConnector struct {
	*labServer
	reads atomic.Int32
}

func (c *countedConnector) Read(req *connectorv1.ReadRequest, st grpc.ServerStreamingServer[connectorv1.ReadResponse]) error {
	c.reads.Add(1)
	return c.labServer.Read(req, st)
}

// tunnelPKI is a minimal fleet PKI: a tenant client CA and an installation server CA.
type tunnelPKI struct {
	clientCA, serverCA *x509.Certificate
	clientKey, srvKey  *ecdsa.PrivateKey
}

func newTunnelPKI(t *testing.T) tunnelPKI {
	t.Helper()
	mk := func(cn string) (*x509.Certificate, *ecdsa.PrivateKey) {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		tpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
			KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true, MaxPathLen: 0, MaxPathLenZero: true}
		tpl.Subject.CommonName = cn
		der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
		if err != nil {
			t.Fatal(err)
		}
		c, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return c, k
	}
	var p tunnelPKI
	p.clientCA, p.clientKey = mk("tenant client CA")
	p.serverCA, p.srvKey = mk("installation server CA")
	return p
}

func (p tunnelPKI) leaf(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, tpl *x509.Certificate) tls.Certificate {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl.SerialNumber = big.NewInt(time.Now().UnixNano())
	tpl.NotBefore, tpl.NotAfter = time.Now().Add(-time.Hour), time.Now().Add(time.Hour)
	tpl.KeyUsage = x509.KeyUsageDigitalSignature
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca, k.Public(), caKey)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}
}

type tunnelCAs map[tenant.ID][]*x509.Certificate

func (c tunnelCAs) TenantCAs(_ context.Context, tid tenant.ID) ([]*x509.Certificate, error) {
	return c[tid], nil
}

type allUsable struct{}

func (allUsable) Usable(context.Context, fleet.Identity) (bool, error)  { return true, nil }
func (allUsable) Current(context.Context, fleet.Identity) (bool, error) { return true, nil }

const (
	labConnector = "7f1e0c52-3a9d-4b6e-8c41-2d5a9b0e6f13"
	nsHost       = "localhost"
)

func TestLabDirectoryReadsOverTheSharedFleetHub(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		le := testlab.Load(t)
		d := s.NewDatabase(t)
		d.Migrate(t)
		db, err := store.Open(context.Background(), store.Config{DSN: d.AppDSN()})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(db.Close)
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		t.Cleanup(cancel)

		// The connector's served side: real verification and read over a real LDAPS session to the lab.
		env := envOf(map[string]string{"LAB_LDAPS_PORT": le.Port, "LAB_SVC_PASSWORD": le.Values["LAB_SVC_PASSWORD"], "LAB_CA": le.CAPath})
		specs, err := labSpecs(env)
		if err != nil || len(specs) != 1 {
			t.Fatalf("lab specs = %d, %v", len(specs), err)
		}
		lab, closeLab, err := openLabServer(ctx, specs[0])
		if err != nil {
			t.Fatalf("open lab connector: %v", err)
		}
		t.Cleanup(closeLab)
		conn := &countedConnector{labServer: lab}

		// The tenant of the install (audit genesis and data key) and a second tenant.
		kek, err := keys.NewLocalProvider("test-kek", secret.FromBytes(bytes.Repeat([]byte{7}, 32)))
		if err != nil {
			t.Fatal(err)
		}
		ch := audit.NewChainer(db)
		tidA, err := bootstrapTenant(ctx, config.Config{InstanceID: "node-1"}, db, ch, kek, jobs.NewRegistry())
		if err != nil {
			t.Fatal(err)
		}
		tidB := tenanttest.Seed(t, d.ExecOwner, "B")

		// The composition Run performs: one hub, the tunnel deps around it, the source over it.
		conns := connection.NewRegistry(db)
		hub := gateway.NewHub()
		src, err := client.NewTunnelSource(conns, conns, hub)
		if err != nil {
			t.Fatal(err)
		}
		deps, err := buildTunnelDeps(hub, db, ch)
		if err != nil {
			t.Fatal(err)
		}
		if deps.Hub != hub {
			t.Fatal("the tunnel deps are not on the shared hub")
		}
		svc, err := NewFleetService(&fleetsql.Enroller{}, deps)
		if err != nil {
			t.Fatal(err)
		}

		// The real gateway with mutual TLS in front of it.
		pki := newTunnelPKI(t)
		gw, err := gateway.NewGateway(gateway.Config{
			Methods: map[string]gateway.AuthClass{gateway.EnrollMethod: gateway.ClassPublic, "/activediq.fleet.v1.Fleet/Tunnel": gateway.ClassClientCert},
			CAs:     tunnelCAs{tidA: {pki.clientCA}, tidB: {pki.clientCA}}, Components: allUsable{}, Recheck: time.Second})
		if err != nil {
			t.Fatal(err)
		}
		srvLeaf := pki.leaf(t, pki.serverCA, pki.srvKey, &x509.Certificate{DNSNames: []string{nsHost}, IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
		srvLeaf.Certificate = append(srvLeaf.Certificate, pki.serverCA.Raw)
		pool := gateway.NewCAIndex([]*x509.Certificate{pki.clientCA})
		gs, err := gw.NewServer(srvLeaf, func() *gateway.CAIndex { return pool }, func(r grpc.ServiceRegistrar) { fleetv1.RegisterFleetServer(r, svc) })
		if err != nil {
			t.Fatal(err)
		}
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		go func() { _ = gs.Serve(l) }()
		t.Cleanup(gs.Stop)

		// The connector component of tenant A dials in and serves the Connector contract on its tunnel.
		binding := connectorTunnelBinding(t, conn)
		dialComponent(ctx, t, l.Addr().String(), pki, tidA, labConnector, binding)
		waitAttached(ctx, t, hub, tidA, labConnector)

		// Tenant A's connection, bound to that component; activation verifies it THROUGH the tunnel.
		connA := newConnection(ctx, t, conns, tidA, "tenant A forest")
		seedComponent(ctx, t, db, tidA, labConnector, connA)
		reads, err := directoryReads(conns, src)
		if err != nil {
			t.Fatal(err)
		}
		vopts, err := verifyOptions(src)
		if err != nil {
			t.Fatal(err)
		}
		csvc, err := connection.NewService(conns, client.New(vopts...), ch)
		if err != nil {
			t.Fatal(err)
		}
		actor := authority.Chain{Requester: authority.Principal{ID: "lab-test", Kind: authority.System}}
		if _, err := csvc.Activate(authority.WithTenant(ctx, tidA.String()), tidA, connA, actor); err != nil {
			t.Fatalf("activation over the tunnel: %v", err)
		}
		if conn.reads.Load() != 0 {
			t.Fatalf("activation read objects: %d", conn.reads.Load())
		}

		admin := labadmin.Dial(t, le.Port, le.Pool, "Administrator@lab.activediq.test", le.Values["LAB_ADMIN_PASSWORD"])
		udn := admin.CreateUser("t1119-lab-user-01", "CN=Users,"+labDom)
		ug, err := guid.FromBytes(admin.ObjectGUID(udn))
		if err != nil {
			t.Fatal(err)
		}
		userGUID := uuidText(write.GUIDToWire(ug).GetValue())
		ctxA := authority.WithTenant(ctx, tidA.String())

		t.Run("AC1 facts come from the connector, not ErrNoReads", func(t *testing.T) {
			facts := directoryFacts(reads)
			got, err := facts.Facts(ctxA, nil, authority.FactsQuery{
				Target: authority.TargetRef{Connection: string(connA), GUID: userGUID, Class: "user"}, Tier0: true, Ancestry: true})
			if errors.Is(err, client.ErrNoReads) {
				t.Fatal("ErrNoReads: the directory target was not read")
			}
			if err != nil {
				t.Fatalf("facts: %v", err)
			}
			if !got.Exists || got.Tier0 || len(got.Ancestors) == 0 || !got.AncestorsComplete {
				t.Fatalf("facts = %+v, want an existing non-Tier-0 user with its complete ancestry from the DC", got)
			}
			if conn.reads.Load() == 0 {
				t.Fatal("no Read reached the connector")
			}
			// An object the directory does not have must never be reported as existing. Over the tunnel the
			// typed OBJECT_NOT_FOUND detail is dropped (T-1141), so today this is an error (fail closed)
			// rather than Exists=false; either is safe, only Exists=true or ErrNoReads would be wrong.
			none, err := facts.Facts(ctxA, nil, authority.FactsQuery{
				Target: authority.TargetRef{Connection: string(connA), GUID: "00000000-0000-4000-8000-00000000d00d", Class: "user"}, Tier0: true})
			if errors.Is(err, client.ErrNoReads) || none.Exists {
				t.Fatalf("absent object facts = %+v, %v", none, err)
			}
		})

		t.Run("AC2 a ComponentID bound to another tenant is refused and nothing is read", func(t *testing.T) {
			before := conn.reads.Load()
			// Tenant B has its own component row with the SAME id as tenant A's connector, bound to B's
			// connection. B has no tunnel: the hub is keyed by tenant and component, so the id alone reaches nothing.
			connB := newConnection(ctx, t, conns, tidB, "tenant B forest")
			seedComponent(ctx, t, db, tidB, labConnector, connB)
			bs, err := conns.Bindings(ctx, tidB, connB)
			if err != nil || len(bs) != 1 || bs[0].ComponentID != labConnector || bs[0].Target != connection.TargetComponent {
				t.Fatalf("bindings scan for B = %+v, %v (want the one component binding with its ComponentID)", bs, err)
			}
			ctxB := authority.WithTenant(ctx, tidB.String())
			cl, err := src.Connector(ctxB, string(connB))
			if err != nil {
				t.Fatalf("connector for B: %v", err)
			}
			rs, err := cl.Read(ctxB, &connectorv1.ReadRequest{})
			if err == nil {
				_, err = rs.Recv()
			}
			if status.Code(err) != codes.Unavailable {
				t.Fatalf("read for B over A's component id = %v, want UNAVAILABLE", err)
			}
			// A's context cannot name B's connection, nor B's context A's.
			if _, err := src.Connector(ctxA, string(connB)); !errors.Is(err, client.ErrReadConnection) {
				t.Fatalf("A naming B's connection = %v, want ErrReadConnection", err)
			}
			if _, err := src.Connector(ctxB, string(connA)); !errors.Is(err, client.ErrReadConnection) {
				t.Fatalf("B naming A's connection = %v, want ErrReadConnection", err)
			}
			_, err = reads.Object(ctxB, nil, authority.TargetRef{Connection: string(connA), GUID: userGUID, Class: "user"}, userGUID, true)
			if err == nil {
				t.Fatal("B read A's object")
			}
			if conn.reads.Load() != before {
				t.Fatalf("connector served %d Read(s) during the cross-tenant attempts, want 0", conn.reads.Load()-before)
			}
			if msg := err.Error(); strings.Contains(msg, userGUID) || strings.Contains(msg, labConnector) {
				t.Errorf("refusal leaks an identifier: %q", msg)
			}
		})

		t.Run("a connection with no component binding fails closed", func(t *testing.T) {
			before := conn.reads.Load()
			lone := newConnection(ctx, t, conns, tidA, "tenant A, no binding")
			_, err := src.Connector(ctxA, string(lone))
			if !errors.Is(err, client.ErrNoEndpoint) {
				t.Fatalf("err = %v, want ErrNoEndpoint", err)
			}
			if conn.reads.Load() != before {
				t.Fatal("a Read was served")
			}
		})
	})
}

// connectorTunnelBinding is the connector's side of the "connector" contract, serving srv.
func connectorTunnelBinding(t *testing.T, srv connectorv1.ConnectorServer) fleet.Binding {
	t.Helper()
	sd := connectorv1.File_activediq_connector_v1_connector_proto.Services().ByName("Connector")
	c, err := fleet.NewContract("connector", []protoreflect.ServiceDescriptor{sd}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return fleet.Binding{Contract: c, Register: func(id fleet.Identity, reg grpc.ServiceRegistrar) {
		if id.Kind == fleet.KindConnector && !id.Tenant.IsZero() && id.ComponentID != "" {
			connectorv1.RegisterConnectorServer(reg, srv)
		}
	}}
}

// dialComponent connects as the connector component (tid, comp) with a certificate the tenant CA signed,
// verifies the server by the installation CA, opens Fleet.Tunnel and runs the component's Mux on it.
func dialComponent(ctx context.Context, t *testing.T, addr string, pki tunnelPKI, tid tenant.ID, comp string, b fleet.Binding) {
	t.Helper()
	cert := pki.leaf(t, pki.clientCA, pki.clientKey, &x509.Certificate{URIs: fleet.URIs(tid, "connector", comp), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	roots := x509.NewCertPool()
	roots.AddCert(pki.serverCA)
	cc, err := grpc.NewClient(addr, grpc.WithTransportCredentials(credentials.NewTLS(
		&tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: nsHost, Certificates: []tls.Certificate{cert}})))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cc.Close() })
	rctx, stop := context.WithCancel(ctx)
	st, err := tunnelbind.Open(rctx, cc)
	if err != nil {
		stop()
		t.Fatalf("open tunnel: %v", err)
	}
	m, err := fleet.NewMux(fleet.MuxConfig{Role: fleet.RoleComponent, Identity: fleet.Identity{Tenant: tid, Kind: fleet.KindConnector, ComponentID: comp}, Binding: b, Transport: st})
	if err != nil {
		stop()
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { defer close(done); _ = m.Run(rctx) }()
	t.Cleanup(func() { stop(); m.Close(); <-done })
}

// waitAttached waits until the server's hub holds the component's tunnel: a call on it is no longer UNAVAILABLE.
func waitAttached(ctx context.Context, t *testing.T, hub *gateway.Hub, tid tenant.ID, comp string) {
	t.Helper()
	for end := time.Now().Add(10 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		// Describe is not served by the lab connector (UNIMPLEMENTED), and it is not a Read.
		_, err := connectorv1.NewConnectorClient(hub.Conn(tid, comp)).Describe(ctx, &connectorv1.DescribeRequest{})
		if status.Code(err) != codes.Unavailable {
			return
		}
		if time.Now().After(end) {
			t.Fatal("the component's tunnel never attached to the shared hub")
		}
	}
}

func newConnection(ctx context.Context, t *testing.T, conns *connection.Registry, tid tenant.ID, name string) connection.ID {
	t.Helper()
	cred, err := newUUID()
	if err != nil {
		t.Fatal(err)
	}
	c, err := conns.Create(ctx, tid, connection.New{Kind: connection.KindADForest, DisplayName: name,
		CredentialID: connection.CredentialID(cred), Transport: connection.TransportLDAPS})
	if err != nil {
		t.Fatalf("create connection: %v", err)
	}
	return c.ID
}

// seedComponent is the fixture for what no product code writes yet (remote enrolment, T-0167): a
// connector component row, created pending and enrolled with a certificate serial (DM-12), and an
// active component binding of the connection to it. It runs as the application role under the
// tenant's row-level security, as the product would.
func seedComponent(ctx context.Context, t *testing.T, db *store.DB, tid tenant.ID, comp string, conn connection.ID) {
	t.Helper()
	err := db.WithTenant(ctx, tid, func(ctx context.Context, tx store.Tx) error {
		for _, q := range []struct {
			sql  string
			args []any
		}{
			{`INSERT INTO public.components (tenant_id, id, kind, name) VALUES ($1::uuid, $2::uuid, 'connector', 'lab connector')`, []any{tid.String(), comp}},
			{`UPDATE public.components SET state = 'enrolled', cert_serial = 'ab12' WHERE tenant_id = $1::uuid AND id = $2::uuid`, []any{tid.String(), comp}},
			{`INSERT INTO public.connector_bindings (tenant_id, connection_id, target, component_id) VALUES ($1::uuid, $2::uuid, 'component', $3::uuid)`, []any{tid.String(), string(conn), comp}},
		} {
			if _, err := tx.Exec(ctx, q.sql, q.args...); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("seed component: %v", err)
	}
}
