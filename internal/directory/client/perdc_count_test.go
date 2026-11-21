package client_test

import (
	"context"
	"errors"
	"net"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	"github.com/skenzeriq/activediq/internal/directory/client"
	"github.com/skenzeriq/activediq/internal/platform/report"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// descServer answers Describe with a fixed DC list and records the requests.
type descServer struct {
	connectorv1.UnimplementedConnectorServer
	resp *connectorv1.DescribeResponse
	reqs []*connectorv1.DescribeRequest
}

func (s *descServer) Describe(_ context.Context, r *connectorv1.DescribeRequest) (*connectorv1.DescribeResponse, error) {
	s.reqs = append(s.reqs, r)
	return s.resp, nil
}

func countReader(t *testing.T, srv *descServer, withSource bool) *client.ConnectorPerDC {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	gs := grpc.NewServer()
	connectorv1.RegisterConnectorServer(gs, srv)
	go func() { _ = gs.Serve(lis) }()
	cc, err := grpc.NewClient("passthrough:///count", grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cc.Close(); gs.Stop() })
	src := pdSource{connectorv1.NewConnectorClient(cc)}
	cfg := client.PerDCConfig{}
	if withSource {
		cfg.Describe = src
	}
	tr, err := client.NewGRPCPerDCTransport(src)
	if err != nil {
		t.Fatal(err)
	}
	r, err := client.NewConnectorPerDC(conns{}, tr, cfg)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func dcInfoOf(host string, nc []byte, rodc connectorv1.TriState, reachable bool) *connectorv1.DomainControllerInfo {
	return &connectorv1.DomainControllerInfo{
		Identity: &connectorv1.DcIdentity{DnsHostname: host}, DomainNcGuid: &connectorv1.Guid{Value: nc},
		IsRodc: rodc, Reachable: reachable,
	}
}

// T-1499 AC-1: a connection with three DCs, one of them down, counts three for scope all; RODCs count for
// all and not for writable, an unknown role counts for writable, another domain's DC never counts.
func TestDCsInScope(t *testing.T) {
	nc, other := wireOf(t, gH), wireOf(t, "99999999-0000-4000-8000-000000000009")
	f, tr, u := connectorv1.TriState_TRI_STATE_FALSE, connectorv1.TriState_TRI_STATE_TRUE, connectorv1.TriState_TRI_STATE_UNKNOWN
	info := func(kind connectorv1.NamingContextKind, dcs ...*connectorv1.DomainControllerInfo) *descServer {
		return &descServer{resp: &connectorv1.DescribeResponse{
			NamingContexts:    []*connectorv1.NamingContextInfo{{NcGuid: &connectorv1.Guid{Value: nc}, Kind: kind}},
			DomainControllers: dcs,
		}}
	}
	dom := connectorv1.NamingContextKind_NAMING_CONTEXT_KIND_DOMAIN
	srv := info(dom,
		dcInfoOf("dc1", nc, f, true), dcInfoOf("dc2", nc, f, true), dcInfoOf("down", nc, f, false),
		dcInfoOf("rodc", nc, tr, true), dcInfoOf("unk", nc, u, true), dcInfoOf("elsewhere", other, f, true))
	r := countReader(t, srv, true)
	for scope, want := range map[report.PerDCScope]int{report.ScopeAll: 5, report.ScopeWritable: 4} {
		n, err := r.DCsInScope(pdCtx(pdTenant), oid(t, connUUID), oid(t, gH), scope)
		if err != nil || n != want {
			t.Errorf("scope %v: got %d, %v; want %d", scope, n, err, want)
		}
	}
	if len(srv.reqs) != 2 || !srv.reqs[0].GetRefresh() || srv.reqs[0].GetConnection().GetConnectionId() != connUUID {
		t.Errorf("describe requests = %+v", srv.reqs)
	}

	three := countReader(t, info(dom, dcInfoOf("a", nc, f, true), dcInfoOf("b", nc, f, true), dcInfoOf("c", nc, f, false)), true)
	if n, err := three.DCsInScope(pdCtx(pdTenant), oid(t, connUUID), oid(t, gH), report.ScopeAll); err != nil || n != 3 {
		t.Fatalf("three DCs with one down: %d, %v", n, err)
	}
}

func TestDCsInScopeRefusals(t *testing.T) {
	srv := &descServer{resp: &connectorv1.DescribeResponse{}}
	r := countReader(t, srv, true)
	if _, err := r.DCsInScope(pdCtx(pdTenant), oid(t, connUUID), oid(t, gH), report.ScopeAll); !errors.Is(err, client.ErrDCNC) {
		t.Errorf("unknown NC: %v", err)
	}
	if _, err := r.DCsInScope(pdCtx(pdTenant), oid(t, connUUID), oid(t, gH), report.PerDCScope(99)); !errors.Is(err, client.ErrPerDCScope) {
		t.Errorf("bad scope: %v", err)
	}
	if _, err := r.DCsInScope(context.Background(), oid(t, connUUID), oid(t, gH), report.ScopeAll); err == nil {
		t.Error("no tenant must fail")
	}
	if len(srv.reqs) != 1 {
		t.Errorf("only the unknown-NC call may reach the connector: %d", len(srv.reqs))
	}
	noSrc := countReader(t, srv, false)
	if _, err := noSrc.DCsInScope(pdCtx(pdTenant), oid(t, connUUID), oid(t, gH), report.ScopeAll); !errors.Is(err, client.ErrNoDescribe) {
		t.Errorf("no describe source: %v", err)
	}
}
