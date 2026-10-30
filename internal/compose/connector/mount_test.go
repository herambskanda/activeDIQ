package connector_test

import (
	"context"
	"errors"
	"go/parser"
	"go/token"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/skenzeriq/activediq/internal/compose/connector"
	"github.com/skenzeriq/activediq/internal/connector/ad"
	"github.com/skenzeriq/activediq/internal/connector/read"
	"github.com/skenzeriq/activediq/internal/connector/rights"
	"github.com/skenzeriq/activediq/internal/connector/write"
	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
	"github.com/skenzeriq/activediq/internal/directory/ldapfilter"
	"github.com/skenzeriq/activediq/internal/platform/fleet"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
	v1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

type nopBase struct{}

func (nopBase) Append(string, []write.Mark) error { return nil }

type stubDir struct{ rights.ADDirectory }

type wire struct {
	in   <-chan fleet.Frame
	out  chan<- fleet.Frame
	done chan struct{}
	once *sync.Once
}

func (w *wire) Send(f fleet.Frame) error {
	select {
	case w.out <- f:
		return nil
	case <-w.done:
		return io.ErrClosedPipe
	}
}

func (w *wire) Recv() (fleet.Frame, error) {
	select {
	case f := <-w.in:
		return f, nil
	case <-w.done:
		return fleet.Frame{}, io.EOF
	}
}

func newWires() (a, b *wire) {
	ab, ba, done, once := make(chan fleet.Frame, 128), make(chan fleet.Frame, 128), make(chan struct{}), new(sync.Once)
	return &wire{in: ba, out: ab, done: done, once: once}, &wire{in: ab, out: ba, done: done, once: once}
}

type rep struct{}

func (rep) ProtocolError(context.Context, fleet.Identity, fleet.Violation) error { return nil }

func handler(t *testing.T) *rights.VerifyHandler {
	t.Helper()
	gate, _ := write.NewGateBook(nopBase{}, nil)
	h, err := rights.NewVerifyHandler(rights.VerifyConfig{Dir: stubDir{}, Epoch: rights.NewEpochState(nil, nil, nil),
		Directory: &v1.DirectoryIdentity{}, Gate: gate, OnLocalRecordFailed: gate.CloseLocalRecordFailed})
	if err != nil {
		t.Fatal(err)
	}
	return h
}

var (
	dirIdent = &v1.DirectoryIdentity{Identity: &v1.DirectoryIdentity_AdForest{AdForest: &v1.AdForestIdentity{
		ForestRootNcGuid: &v1.Guid{Value: []byte("0123456789abcdef")}}}}
	rootGUID = guid.GUID{0xaa, 1}
	objGUID  = guid.GUID{0xaa, 2}
	dsa      = guid.GUID{0x22, 3}
)

// fakeSrc is a directory source whose answers are fixed, so the tunnel and the in-process handler
// can be compared byte for byte. It stands for the directory only; the transport under test is real.
type fakeSrc struct{}

func (fakeSrc) Identity() *v1.DirectoryIdentity { return dirIdent }
func (fakeSrc) BoundDC(context.Context) (*v1.DcIdentity, error) {
	return &v1.DcIdentity{DsaGuid: write.GUIDToWire(dsa), DnsHostname: "dc1"}, nil
}
func (fakeSrc) entry() *ad.Entry {
	return ad.NewEntry("CN=Smith\\, Ann,OU=Ü,DC=lab,DC=test", map[string][][]byte{
		"objectGUID": {objGUID.Bytes()}, "cn": {[]byte("Smith, Ann")}, "instanceType": {[]byte("4")}})
}
func (f fakeSrc) Read(context.Context, guid.GUID, []string, int) (*ad.Entry, error) {
	return f.entry(), nil
}
func (fakeSrc) Parent(context.Context, *ad.Entry) (guid.GUID, bool, error) {
	return rootGUID, true, nil
}
func (fakeSrc) Syntax(n string) (ldapfilter.Syntax, bool) {
	if n == "instancetype" {
		return ldapfilter.SynInt32, true
	}
	return ldapfilter.SynString, true
}
func (fakeSrc) CanonicalAttr(n string) (string, error) { return n, nil }
func (fakeSrc) Classify(context.Context, guid.GUID) (write.Verdict, error) {
	return write.Verdict{}, nil
}
func (fakeSrc) ParseFilter(f *v1.Filter) (ldapfilter.Filter, error) {
	return ldapfilter.ParseFilterAST(f, ldapfilter.NewSchema(ldapfilter.AttrInfo{Name: "cn", Syntax: ldapfilter.SynString}), nil, ldapfilter.Limits{})
}
func (f fakeSrc) ScopedSearch(_ context.Context, _ ad.ScopedRequest, fn func(*ad.Entry) error) (ad.ScopedResult, error) {
	return ad.ScopedResult{Returned: 1}, fn(f.entry().WithParent(rootGUID, true)) // ResolveParents: the real source resolves the parent (T-0694)
}

func readHandler(t *testing.T) *read.Handler {
	t.Helper()
	h, err := read.New(fakeSrc{})
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// fakeProv is the write handler's provider; the tunnel tests never reach a write.
type fakeProv struct{}

func (fakeProv) Kind() v1.ProviderKind           { return v1.ProviderKind_PROVIDER_KIND_AD }
func (fakeProv) Identity() *v1.DirectoryIdentity { return dirIdent }
func (fakeProv) Classify(context.Context, guid.GUID, []guid.GUID) (write.Verdict, error) {
	return write.Verdict{}, nil
}
func (fakeProv) Anchors(context.Context, guid.GUID) (write.Anchors, error) {
	return write.Anchors{}, nil
}
func (fakeProv) PropertyGuard(context.Context) (write.PropertyGuard, error) {
	return nil, errors.New("none")
}

func writeHandler(t *testing.T) *write.Handler {
	t.Helper()
	gate, _ := write.NewGateBook(nopBase{}, nil)
	h, err := write.New(fakeProv{}, gate)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

type tunnel struct {
	srv *fleet.Mux
	bd  fleet.Binding
}

// newTunnel runs a RoleServer mux against a RoleComponent mux that carries the connector's binding.
func newTunnel(t *testing.T) (tunnel, context.Context) {
	t.Helper()
	bd, err := connector.TunnelBinding(handler(t), readHandler(t), writeHandler(t))
	if err != nil {
		t.Fatal(err)
	}
	return tunnelFor(t, bd, 20*time.Second)
}

// tunnelFor runs a RoleServer mux against a RoleComponent mux that carries bd.
func tunnelFor(t *testing.T, bd fleet.Binding, timeout time.Duration) (tunnel, context.Context) {
	t.Helper()
	a, b := newWires()
	id := fleet.Identity{Tenant: tenant.New(), Kind: fleet.KindConnector, ComponentID: "11111111-1111-4111-8111-111111111111"}
	srv, err := fleet.NewMux(fleet.MuxConfig{Role: fleet.RoleServer, Identity: id, Transport: a, Reporter: rep{},
		Binding: fleet.Binding{Contract: bd.Contract}})
	if err != nil {
		t.Fatal(err)
	}
	comp, err := fleet.NewMux(fleet.MuxConfig{Role: fleet.RoleComponent, Identity: id, Transport: b, Binding: bd})
	if err != nil {
		t.Fatalf("component mux with the connector binding: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	var wg sync.WaitGroup
	for _, m := range []*fleet.Mux{srv, comp} {
		wg.Add(1)
		go func() { defer wg.Done(); _ = m.Run(ctx) }()
	}
	t.Cleanup(func() { cancel(); a.once.Do(func() { close(a.done) }); wg.Wait() })
	return tunnel{srv: srv, bd: bd}, ctx
}

// The server (RoleServer) opens VerifyConnection over a tunnel whose component side is the
// connector's TunnelBinding; a method outside the contract is refused at registration.
func TestTunnelBindingServesVerifyOverTunnel(t *testing.T) {
	if _, err := connector.TunnelBinding(nil, readHandler(t), writeHandler(t)); err == nil {
		t.Fatal("nil verify handler accepted")
	}
	if _, err := connector.TunnelBinding(handler(t), nil, writeHandler(t)); err == nil {
		t.Fatal("nil read handler accepted")
	}
	if _, err := connector.TunnelBinding(handler(t), readHandler(t), nil); err == nil {
		t.Fatal("nil write handler accepted")
	}
	tn, ctx := newTunnel(t)
	st, err := v1.NewConnectorClient(tn.srv.Conn()).VerifyConnection(ctx, &v1.VerifyConnectionRequest{})
	if err == nil {
		_, err = st.Recv()
	}
	// The handler was reached: an empty request is its fixed INVALID_ARGUMENT, not UNIMPLEMENTED/UNAVAILABLE.
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("VerifyConnection over tunnel = %v, want InvalidArgument", err)
	}
	// A method the contract does not carry is not served by the component.
	err = tn.srv.Conn().Invoke(ctx, "/grpc.health.v1.Health/Check", &v1.VerifyConnectionRequest{}, &v1.VerifyConnectionRequest{})
	if status.Code(err) == codes.OK || status.Code(err) == codes.InvalidArgument {
		t.Fatalf("method outside the contract was served: %v", err)
	}
}

// The write group is served over the same tunnel by the same composite server: Plan reaches the
// write guard (an empty request is refused INVALID_ARGUMENT by it), not UNIMPLEMENTED.
func TestPlanOverTunnelReachesTheWriteGuard(t *testing.T) {
	tn, ctx := newTunnel(t)
	_, err := v1.NewConnectorClient(tn.srv.Conn()).Plan(ctx, &v1.PlanRequest{})
	if err == nil || status.Code(err) == codes.Unimplemented || status.Code(err) == codes.Unavailable {
		t.Fatalf("Plan over tunnel = %v, want the guard's refusal", err)
	}
}

func scopedReq() *v1.ScopedSearchRequest {
	return &v1.ScopedSearchRequest{
		Connection: &v1.ConnectionRef{ConnectionId: "c1", DirectoryIdentity: dirIdent},
		Roots:      []*v1.SearchRoot{{Guid: write.GUIDToWire(rootGUID)}},
		Depth:      v1.SearchDepth_SEARCH_DEPTH_SUBTREE,
		Filter: &v1.Filter{Node: &v1.Filter_Equal{Equal: &v1.Comparison{Attribute: "cn",
			Value: &v1.FilterValue{Value: &v1.FilterValue_Text{Text: "Smith, Ann"}}}}},
		Attributes: []string{"cn"},
	}
}

func readReq() *v1.ReadRequest {
	return &v1.ReadRequest{Connection: &v1.ConnectionRef{ConnectionId: "c1", DirectoryIdentity: dirIdent},
		Guid: write.GUIDToWire(objGUID), Attributes: []string{"cn"}}
}

// recvAll drains a server stream, returning the messages and the terminal error (nil on EOF).
func recvAll[T any](st interface{ Recv() (*T, error) }) ([]*T, error) {
	var out []*T
	for {
		m, err := st.Recv()
		if errors.Is(err, io.EOF) {
			return out, nil
		}
		if err != nil {
			return out, err
		}
		out = append(out, m)
	}
}

// AC1: entries return through the tunnel for a base root and filter.
func TestScopedSearchOverTunnelReturnsEntries(t *testing.T) {
	tn, ctx := newTunnel(t)
	st, err := v1.NewConnectorClient(tn.srv.Conn()).ScopedSearch(ctx, scopedReq())
	if err != nil {
		t.Fatal(err)
	}
	ms, err := recvAll(st)
	if err != nil || len(ms) != 2 {
		t.Fatalf("msgs=%d err=%v", len(ms), err)
	}
	es := ms[0].GetBatch().GetEntries()
	if len(es) != 1 || es[0].GetDn().GetDisplayDn() != fakeSrc.entry(fakeSrc{}).DN ||
		es[0].GetAttributes()[0].GetValues()[0].GetText() != "Smith, Ann" || ms[1].GetCompleted() == nil {
		t.Fatalf("unexpected search result: %v", ms)
	}
}

// AC2: a pinned Read crossing the tunnel equals the in-process handler's answer (only the
// connector's receive clock differs).
func TestReadOverTunnelMatchesInProcessHandler(t *testing.T) {
	tn, ctx := newTunnel(t)
	r := readReq()
	r.Dc = &v1.DcSelection{PinnedDsaGuid: write.GUIDToWire(dsa)}
	st, err := v1.NewConnectorClient(tn.srv.Conn()).Read(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	over, err := recvAll(st)
	if err != nil {
		t.Fatal(err)
	}
	var local []*v1.ReadResponse
	if err := readHandler(t).Read(ctx, r, sink{&local}); err != nil {
		t.Fatal(err)
	}
	if len(over) != len(local) || len(over) < 2 {
		t.Fatalf("tunnel %d messages, in-process %d", len(over), len(local))
	}
	for i := range over {
		if h := over[i].GetHeader(); h != nil {
			h.Observed.ReceivedAt = nil
			local[i].GetHeader().Observed.ReceivedAt = nil
		}
		if !proto.Equal(over[i], local[i]) {
			t.Fatalf("message %d differs:\n tunnel %v\n local  %v", i, over[i], local[i])
		}
	}
}

type sink struct{ out *[]*v1.ReadResponse }

func (s sink) Send(m *v1.ReadResponse) error { *s.out = append(*s.out, m); return nil }

// AC3: a caller without a connection reference, or naming another directory (another tenant's),
// is refused on both groups, and nothing is read.
func TestReadAndScopedSearchOverTunnelRefuseUnauthenticatedAndWrongTenant(t *testing.T) {
	tn, ctx := newTunnel(t)
	c := v1.NewConnectorClient(tn.srv.Conn())
	other := &v1.DirectoryIdentity{Identity: &v1.DirectoryIdentity_AdForest{AdForest: &v1.AdForestIdentity{
		ForestRootNcGuid: &v1.Guid{Value: []byte("fedcba9876543210")}}}}
	for name, mod := range map[string]func(*v1.ConnectionRef) *v1.ConnectionRef{
		"unauthenticated (no connection)": func(*v1.ConnectionRef) *v1.ConnectionRef { return nil },
		"unauthenticated (no identity)":   func(c *v1.ConnectionRef) *v1.ConnectionRef { c.DirectoryIdentity = nil; return c },
		"wrong tenant (other directory)":  func(c *v1.ConnectionRef) *v1.ConnectionRef { c.DirectoryIdentity = other; return c },
	} {
		sr := scopedReq()
		sr.Connection = mod(sr.Connection)
		st, err := c.ScopedSearch(ctx, sr)
		var ms []*v1.ScopedSearchResponse
		if err == nil {
			ms, err = recvAll(st)
		}
		if err == nil || len(ms) != 0 {
			t.Errorf("ScopedSearch %s: served (%d msgs, err %v)", name, len(ms), err)
		}
		rr := readReq()
		rr.Connection = mod(rr.Connection)
		rt, err := c.Read(ctx, rr)
		var rm []*v1.ReadResponse
		if err == nil {
			rm, err = recvAll(rt)
		}
		if err == nil || len(rm) != 0 {
			t.Errorf("Read %s: served (%d msgs, err %v)", name, len(rm), err)
		}
	}
}

type regCount struct{ n int }

func (r *regCount) RegisterService(*grpc.ServiceDesc, any) { r.n++ }

// AC3: a tunnel whose identity is not a tenant's connector gets no handlers at all.
func TestBindingServesNothingForAnIdentityThatIsNotATenantConnector(t *testing.T) {
	bd, err := connector.TunnelBinding(handler(t), readHandler(t), writeHandler(t))
	if err != nil {
		t.Fatal(err)
	}
	good := fleet.Identity{Tenant: tenant.New(), Kind: fleet.KindConnector, ComponentID: "11111111-1111-4111-8111-111111111111"}
	for name, c := range map[string]struct {
		id   fleet.Identity
		want int
	}{
		"connector of a tenant": {good, 1},
		"zero tenant":           {fleet.Identity{Kind: fleet.KindConnector, ComponentID: good.ComponentID}, 0},
		"other kind":            {fleet.Identity{Tenant: good.Tenant, Kind: fleet.KindADDC, ComponentID: good.ComponentID}, 0},
		"no component":          {fleet.Identity{Tenant: good.Tenant, Kind: fleet.KindConnector}, 0},
	} {
		var r regCount
		bd.Register(c.id, &r)
		if r.n != c.want {
			t.Errorf("%s: %d registrations, want %d", name, r.n, c.want)
		}
	}
}

// AC4: the golden list of Connector RPCs the tunnel serves. Adding a group to the mount means
// adding it here; every other method stays Unimplemented over the tunnel.
func TestTunnelServedRPCsAreTheGoldenList(t *testing.T) {
	golden := map[string]bool{"VerifyConnection": true, "Read": true, "ScopedSearch": true, "Plan": true, "Apply": true}
	tn, ctx := newTunnel(t)
	svc := v1.File_activediq_connector_v1_connector_proto.Services().ByName("Connector")
	for i := 0; i < svc.Methods().Len(); i++ {
		m := svc.Methods().Get(i)
		name := string(m.Name())
		full := "/" + string(svc.FullName()) + "/" + name
		var err error
		if m.IsStreamingServer() {
			var cs grpc.ClientStream
			cs, err = tn.srv.Conn().NewStream(ctx, &grpc.StreamDesc{ServerStreams: true}, full)
			if err == nil {
				err = cs.SendMsg(&v1.VerifyConnectionRequest{}) // an empty message of any type
			}
			if err == nil {
				err = cs.CloseSend()
			}
			if err == nil {
				err = cs.RecvMsg(&v1.VerifyConnectionResponse{})
			}
		} else {
			err = tn.srv.Conn().Invoke(ctx, full, &v1.VerifyConnectionRequest{}, &v1.VerifyConnectionResponse{})
		}
		served := status.Code(err) != codes.Unimplemented
		if served != golden[name] {
			t.Errorf("%s: served=%v (err %v), golden=%v", name, served, err, golden[name])
		}
	}
	if len(golden) != 5 {
		t.Fatal("golden list changed without this test")
	}
}

// Guard (TM-TB6-T10, TM-F-PORTS): the connector composition root has no listener or process gRPC
// server of its own.
func TestNoListenerInConnectorComposition(t *testing.T) {
	banned := []string{"grpc.NewServer", "net.Listen", "credentials.NewTLS", "tls.Listen", "http.ListenAndServe", "ListenAndServe"}
	files, _ := filepath.Glob("*.go")
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := parser.ParseFile(token.NewFileSet(), f, src, parser.ParseComments); err != nil {
			t.Fatal(err)
		}
		for _, b := range banned {
			if strings.Contains(string(src), b) {
				t.Errorf("%s uses %s: the connector dials out only", f, b)
			}
		}
	}
}
