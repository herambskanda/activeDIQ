package client

import (
	"context"
	"errors"
	"net"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	"github.com/skenzeriq/activediq/internal/directory/connection"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

const (
	tNC     = "11111111-1111-1111-1111-111111111111"
	tDSA    = "22222222-2222-2222-2222-222222222222"
	tHead   = "aaaaaaaa-0000-0000-0000-000000000001"
	tOU     = "aaaaaaaa-0000-0000-0000-000000000002"
	tUser   = "aaaaaaaa-0000-0000-0000-000000000003"
	tTenant = "33333333-3333-3333-3333-333333333333"
	tOther  = "44444444-4444-4444-4444-444444444444"
)

type fakeConnector struct {
	connectorv1.UnimplementedConnectorServer
	parents  map[string]string // object -> parent; absent = not found
	got      []*connectorv1.ReadRequest
	mutate   func(guid string) []*connectorv1.ReadResponse // overrides the stream
	tier0    map[string]bool                               // verdict served when the request asks for one
	noT0     bool                                          // leave the verdict out although asked
	servedBy []byte                                        // DSA of the DC the header names; default: the pin
}

func guidOf(s string) *connectorv1.Guid { b, _ := parseUUID(s); return &connectorv1.Guid{Value: b} }

func (f *fakeConnector) Read(req *connectorv1.ReadRequest, s grpc.ServerStreamingServer[connectorv1.ReadResponse]) error {
	f.got = append(f.got, req)
	// Like read.Handler: a read without the served directory's identity is refused.
	if want := guidOf(tNC).GetValue(); string(req.GetConnection().GetDirectoryIdentity().GetAdForest().GetForestRootNcGuid().GetValue()) != string(want) {
		return status.Error(3, "directory identity")
	}
	g := formatUUID(req.GetGuid().GetValue())
	if f.mutate != nil {
		for _, m := range f.mutate(g) {
			if err := s.Send(m); err != nil {
				return err
			}
		}
		return nil
	}
	p, ok := f.parents[g]
	if !ok {
		d, _ := status.New(5, "x").WithDetails(&connectorv1.ConnectorError{Code: connectorv1.ErrorCode_ERROR_CODE_OBJECT_NOT_FOUND})
		return d.Err()
	}
	e := &connectorv1.DirectoryEntry{ObjectGuid: req.GetGuid()}
	if p != "" {
		e.ParentGuid = guidOf(p)
	}
	h := &connectorv1.ReadHeader{Entry: e}
	dsa := f.servedBy
	if dsa == nil {
		dsa = req.GetDc().GetPinnedDsaGuid().GetValue()
	}
	if dsa != nil {
		h.Observed = &connectorv1.Observation{Dc: &connectorv1.DcIdentity{DsaGuid: &connectorv1.Guid{Value: dsa}}}
	}
	if req.GetIncludeTier0() && !f.noT0 {
		h.Tier0 = &connectorv1.Tier0Verdict{Tier0: f.tier0[g]}
	}
	for _, m := range []*connectorv1.ReadResponse{
		{Event: &connectorv1.ReadResponse_Header{Header: h}},
		{Event: &connectorv1.ReadResponse_Completed{Completed: &connectorv1.ReadCompleted{}}},
	} {
		if err := s.Send(m); err != nil {
			return err
		}
	}
	return nil
}

type connSrc struct{ cc connectorv1.ConnectorClient }

func (c connSrc) Connector(context.Context, string) (connectorv1.ConnectorClient, error) {
	return c.cc, nil
}

type conns map[string]connection.Connection // key tenant|id

func (c conns) Get(_ context.Context, tid tenant.ID, id connection.ID) (connection.Connection, error) {
	if v, ok := c[tid.String()+"|"+string(id)]; ok {
		return v, nil
	}
	return connection.Connection{}, errors.New("not found")
}

func setup(t *testing.T, f *fakeConnector) *ConnectorReads {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	connectorv1.RegisterConnectorServer(srv, f)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	cc, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cc.Close() })
	tr, _ := NewGRPCReadTransport(connSrc{connectorv1.NewConnectorClient(cc)})
	tid, _ := tenant.Parse(tTenant)
	cs := conns{tid.String() + "|c1": {ID: "c1", Kind: connection.KindADForest, DirectoryIdentity: tNC}, tid.String() + "|unv": {ID: "unv", Kind: connection.KindADForest}}
	r, err := NewConnectorReads(cs, tr)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func ctxFor(tenantID string, dsa authority.DSAPins) context.Context {
	return authority.WithDSAPins(authority.WithTenant(context.Background(), tenantID), dsa)
}

var tgt = authority.TargetRef{Connection: "c1", GUID: tUser, Class: "user", NC: tNC}

func TestFactsThroughRealGRPCOnPinnedDC(t *testing.T) {
	f := &fakeConnector{parents: map[string]string{tUser: tOU, tOU: tHead, tHead: ""}, tier0: map[string]bool{tUser: true}}
	cf := NewConnectorFacts(setup(t, f))
	got, err := cf.Facts(ctxFor(tTenant, authority.DSAPins{tNC: tDSA}), authority.Pins{tNC: "dc1"},
		authority.FactsQuery{Target: tgt, Tier0: true, Ancestry: true})
	if err != nil {
		t.Fatal(err)
	}
	if !got.Exists || !got.Tier0 || !got.AncestorsComplete || len(got.Ancestors) != 2 || got.Ancestors[0] != tOU || got.Ancestors[1] != tHead {
		t.Fatalf("facts %+v", got)
	}
	want, _ := parseUUID(tDSA)
	for i, r := range f.got {
		if string(r.GetDc().GetPinnedDsaGuid().GetValue()) != string(want) {
			t.Errorf("read %d not pinned to the DSA: %v", i, r.GetDc())
		}
		if len(r.GetNcGuid().GetValue()) != 16 {
			t.Errorf("read %d has no nc_guid", i)
		}
	}
	if len(f.got) != 3 {
		t.Fatalf("reads %d", len(f.got))
	}
	if !f.got[0].GetIncludeTier0() {
		t.Error("the target read did not ask for the verdict")
	}
}

func TestMissingObjectIsNotExists(t *testing.T) {
	cf := NewConnectorFacts(setup(t, &fakeConnector{parents: map[string]string{}}))
	got, err := cf.Facts(ctxFor(tTenant, authority.DSAPins{tNC: tDSA}), authority.Pins{tNC: "dc1"}, authority.FactsQuery{Target: tgt})
	if err != nil || got.Exists {
		t.Fatalf("%+v, %v", got, err)
	}
}

func TestPinnedReadWithoutDSAFailsClosed(t *testing.T) {
	f := &fakeConnector{parents: map[string]string{tUser: ""}}
	r := setup(t, f)
	for name, c := range map[string]context.Context{"no dsa pins": ctxFor(tTenant, nil), "other nc": ctxFor(tTenant, authority.DSAPins{"x": tDSA}),
		"nil dsa": ctxFor(tTenant, authority.DSAPins{tNC: "00000000-0000-0000-0000-000000000000"})} {
		if _, err := r.Object(c, authority.Pins{tNC: "dc1"}, tgt, tUser, true); !errors.Is(err, ErrReadPin) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := r.Object(ctxFor(tTenant, nil), authority.Pins{"other": "dc1"}, tgt, tUser, true); !errors.Is(err, ErrReadPin) {
		t.Errorf("pin for a different NC: %v", err)
	}
	if len(f.got) != 0 {
		t.Fatal("an unpinned read reached the connector")
	}
}

// nil pins (scope-root ancestry): one unpinned read per call, no DcSelection, and errors still refuse.
func TestNilPinsLeavesDCToConnector(t *testing.T) {
	f := &fakeConnector{parents: map[string]string{tOU: tHead, tHead: ""}}
	cf := NewConnectorFacts(setup(t, f))
	root := authority.TargetRef{Connection: "c1", GUID: tOU, Class: "organizationalUnit"}
	got, err := cf.Facts(ctxFor(tTenant, nil), nil, authority.FactsQuery{Target: root, Ancestry: true})
	if err != nil || !got.AncestorsComplete || len(got.Ancestors) != 1 {
		t.Fatalf("%+v, %v", got, err)
	}
	for _, r := range f.got {
		if r.GetDc() != nil {
			t.Fatalf("DcSelection set on an unpinned read: %v", r.GetDc())
		}
	}
}

func TestConnectionOfAnotherTenantIsRefused(t *testing.T) {
	f := &fakeConnector{parents: map[string]string{tUser: ""}}
	r := setup(t, f)
	if _, err := r.Object(ctxFor(tOther, nil), nil, tgt, tUser, true); !errors.Is(err, ErrReadConnection) {
		t.Fatalf("err %v", err)
	}
	if _, err := r.Object(context.Background(), nil, tgt, tUser, true); !errors.Is(err, ErrReadTenant) {
		t.Fatalf("no tenant: %v", err)
	}
	if len(f.got) != 0 {
		t.Fatal("connector reached")
	}
}

func TestVerdictErrorAndStreamViolationsFailClosed(t *testing.T) {
	ok := func(g string, parent string) []*connectorv1.ReadResponse {
		e := &connectorv1.DirectoryEntry{ObjectGuid: guidOf(g)}
		if parent != "" {
			e.ParentGuid = guidOf(parent)
		}
		return []*connectorv1.ReadResponse{{Event: &connectorv1.ReadResponse_Header{Header: &connectorv1.ReadHeader{Entry: e}}}}
	}
	done := &connectorv1.ReadResponse{Event: &connectorv1.ReadResponse_Completed{Completed: &connectorv1.ReadCompleted{}}}
	cases := map[string]struct {
		mutate func(string) []*connectorv1.ReadResponse
		want   error
	}{
		"no completed":    {func(g string) []*connectorv1.ReadResponse { return ok(g, "") }, ErrReadProtocol},
		"empty stream":    {func(string) []*connectorv1.ReadResponse { return nil }, ErrReadProtocol},
		"two headers":     {func(g string) []*connectorv1.ReadResponse { return append(append(ok(g, ""), ok(g, "")...), done) }, ErrReadProtocol},
		"other object":    {func(string) []*connectorv1.ReadResponse { return append(ok(tOU, ""), done) }, ErrReadIdentity},
		"verdict missing": {func(g string) []*connectorv1.ReadResponse { return append(ok(g, ""), done) }, ErrNoTier0Verdict},
	}
	for name, c := range cases {
		r := setup(t, &fakeConnector{mutate: c.mutate})
		_, err := r.Object(ctxFor(tTenant, nil), nil, tgt, tUser, name == "verdict missing")
		if err == nil || (c.want != nil && !errors.Is(err, c.want)) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestNewConnectorReadsRequiresEveryPort(t *testing.T) {
	if _, err := NewConnectorReads(conns{}, nil); !errors.Is(err, ErrNoReadTransport) {
		t.Error(err)
	}
}

// Acceptance (T-0433): a pinned read answered by another DC fails, and a verdict that was asked for
// but not delivered is an error, never false.
func TestPinnedReadServedByAnotherDCFails(t *testing.T) {
	other, _ := parseUUID(tOther)
	r := setup(t, &fakeConnector{parents: map[string]string{tUser: ""}, servedBy: other})
	if _, err := r.Object(ctxFor(tTenant, authority.DSAPins{tNC: tDSA}), authority.Pins{tNC: "dc1"}, tgt, tUser, false); !errors.Is(err, ErrReadPin) {
		t.Fatalf("err %v", err)
	}
}

func TestAskedVerdictMissingIsAnError(t *testing.T) {
	r := setup(t, &fakeConnector{parents: map[string]string{tUser: ""}, noT0: true})
	if _, err := r.Object(ctxFor(tTenant, authority.DSAPins{tNC: tDSA}), authority.Pins{tNC: "dc1"}, tgt, tUser, true); !errors.Is(err, ErrNoTier0Verdict) {
		t.Fatalf("err %v", err)
	}
}

func TestUnverifiedConnectionReadIsRefusedBeforeTheConnector(t *testing.T) {
	f := &fakeConnector{parents: map[string]string{tUser: ""}}
	r := setup(t, f)
	u := authority.TargetRef{Connection: "unv", GUID: tUser, Class: "user"}
	if _, err := r.Object(ctxFor(tTenant, nil), nil, u, tUser, false); !errors.Is(err, ErrReadDirectory) {
		t.Fatalf("err %v", err)
	}
	if len(f.got) != 0 {
		t.Fatal("connector reached")
	}
}
