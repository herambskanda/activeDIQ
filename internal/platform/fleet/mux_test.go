package fleet_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/skenzeriq/activediq/internal/platform/fleet"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

const (
	mPing   = "/t.v1.Down/Ping"   // server to component, unary
	mWatch  = "/t.v1.Down/Watch"  // server to component, server-streaming
	mReport = "/t.v1.Up/Report"   // component to server, unary
	mOther  = "/t.v1.Other/Thing" // another contract's method
)

// ---- harness ----

func svcDesc(t *testing.T, name string, methods ...string) protoreflect.ServiceDescriptor {
	t.Helper()
	sv := &descriptorpb.ServiceDescriptorProto{Name: proto.String(name)}
	for _, m := range methods {
		md := &descriptorpb.MethodDescriptorProto{
			Name: proto.String(m), InputType: proto.String(".google.protobuf.StringValue"), OutputType: proto.String(".google.protobuf.StringValue"),
		}
		if m == "Watch" {
			md.ServerStreaming = proto.Bool(true)
		}
		sv.Method = append(sv.Method, md)
	}
	fd, err := protodesc.NewFile(&descriptorpb.FileDescriptorProto{
		Name: proto.String(strings.ToLower(name) + ".proto"), Package: proto.String("t.v1"), Syntax: proto.String("proto3"),
		Dependency: []string{"google/protobuf/wrappers.proto"}, Service: []*descriptorpb.ServiceDescriptorProto{sv},
	}, protoregistry.GlobalFiles)
	if err != nil {
		t.Fatal(err)
	}
	return fd.Services().Get(0)
}

func testContract(t *testing.T) fleet.Contract {
	t.Helper()
	c, err := fleet.NewContract("t", []protoreflect.ServiceDescriptor{svcDesc(t, "Down", "Ping", "Watch")}, []protoreflect.ServiceDescriptor{svcDesc(t, "Up", "Report")})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

type counters struct{ ran atomic.Int32 }

// serverHandlers registers t.v1.Up/Report on the per-tunnel registrar.
func serverHandlers(cnt *counters) func(fleet.Identity, grpc.ServiceRegistrar) {
	return func(_ fleet.Identity, reg grpc.ServiceRegistrar) {
		reg.RegisterService(&grpc.ServiceDesc{ServiceName: "t.v1.Up", HandlerType: (*any)(nil), Methods: []grpc.MethodDesc{{
			MethodName: "Report",
			Handler: func(_ any, _ context.Context, dec func(any) error, _ grpc.UnaryServerInterceptor) (any, error) {
				cnt.ran.Add(1)
				in := new(wrapperspb.StringValue)
				if err := dec(in); err != nil {
					return nil, err
				}
				return wrapperspb.String("ok:" + in.Value), nil
			},
		}}}, struct{}{})
	}
}

// componentHandlers registers t.v1.Down on the component's registrar. Watch streams n replies until
// cancelled; Ping blocks on "hang" until its context ends.
func componentHandlers(cancelled chan<- struct{}) func(fleet.Identity, grpc.ServiceRegistrar) {
	return func(_ fleet.Identity, reg grpc.ServiceRegistrar) {
		reg.RegisterService(&grpc.ServiceDesc{ServiceName: "t.v1.Down", HandlerType: (*any)(nil),
			Methods: []grpc.MethodDesc{{MethodName: "Ping", Handler: func(_ any, ctx context.Context, dec func(any) error, _ grpc.UnaryServerInterceptor) (any, error) {
				in := new(wrapperspb.StringValue)
				if err := dec(in); err != nil {
					return nil, err
				}
				if in.Value == "hang" {
					<-ctx.Done()
					if cancelled != nil {
						cancelled <- struct{}{}
					}
					return nil, ctx.Err()
				}
				if in.Value == "fail" {
					return nil, status.Error(codes.NotFound, "secret internal detail /etc/passwd")
				}
				return wrapperspb.String("pong:" + in.Value), nil
			}}},
			Streams: []grpc.StreamDesc{{StreamName: "Watch", ServerStreams: true, Handler: func(_ any, ss grpc.ServerStream) error {
				in := new(wrapperspb.StringValue)
				if err := ss.RecvMsg(in); err != nil {
					return err
				}
				for i := 0; i < 3; i++ {
					if err := ss.SendMsg(wrapperspb.String(in.Value)); err != nil {
						return err
					}
				}
				return nil
			}}}}, struct{}{})
	}
}

type wire struct {
	in, out chan fleet.Frame
	done    chan struct{}
	once    *sync.Once
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

func (w *wire) drop() { w.once.Do(func() { close(w.done) }) }

func newWires() (a, b *wire) {
	ab, ba, done, once := make(chan fleet.Frame, 128), make(chan fleet.Frame, 128), make(chan struct{}), new(sync.Once)
	return &wire{in: ba, out: ab, done: done, once: once}, &wire{in: ab, out: ba, done: done, once: once}
}

type recorder struct {
	mu  sync.Mutex
	vs  []fleet.Violation
	ids []fleet.Identity
}

func (r *recorder) ProtocolError(_ context.Context, id fleet.Identity, v fleet.Violation) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.vs = append(r.vs, v)
	r.ids = append(r.ids, id)
	return nil
}

func (r *recorder) got() []fleet.Violation {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]fleet.Violation(nil), r.vs...)
}

func ident(kind string) fleet.Identity {
	return fleet.Identity{Tenant: tenant.New(), Kind: kind, ComponentID: compID}
}

type tunRig struct {
	m      *fleet.Mux
	peer   *wire
	rep    *recorder
	cnt    *counters
	runErr chan error
	cancel context.CancelFunc
	logs   *bytes.Buffer
}

// newRig runs a server Mux whose peer is driven frame by frame by the test.
func newRig(t *testing.T, mut func(*fleet.MuxConfig)) *tunRig {
	t.Helper()
	srvW, peer := newWires()
	r := &tunRig{peer: peer, rep: &recorder{}, cnt: &counters{}, runErr: make(chan error, 1), logs: &bytes.Buffer{}}
	cfg := fleet.MuxConfig{
		Role: fleet.RoleServer, Identity: ident("connector"), Transport: srvW, Reporter: r.rep,
		Binding: fleet.Binding{Contract: testContract(t), Serve: serverHandlers(r.cnt)},
		Logger:  slog.New(slog.NewJSONHandler(&syncBuf{b: r.logs}, nil)),
	}
	if mut != nil {
		mut(&cfg)
	}
	m, err := fleet.NewMux(cfg)
	if err != nil {
		t.Fatal(err)
	}
	r.m = m
	ctx, cancel := context.WithCancel(context.Background())
	r.cancel = cancel
	go func() { r.runErr <- m.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		peer.drop()
		select {
		case <-r.runErr:
		case <-time.After(5 * time.Second):
			t.Error("Run did not return")
		}
	})
	return r
}

type syncBuf struct {
	mu sync.Mutex
	b  *bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }

func (r *tunRig) next(t *testing.T) fleet.Frame {
	t.Helper()
	select {
	case f := <-r.peer.in:
		return f
	case <-time.After(3 * time.Second):
		t.Fatal("no frame from the server")
		return fleet.Frame{}
	}
}

func (r *tunRig) send(f fleet.Frame) { r.peer.out <- f }

func (r *tunRig) closed(t *testing.T) error {
	t.Helper()
	select {
	case <-r.m.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("tunnel did not close")
	}
	select {
	case err := <-r.runErr:
		r.runErr <- err
		return err
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not return")
		return nil
	}
}

func (r *tunRig) open(t *testing.T) {
	t.Helper()
	select {
	case <-r.m.Done():
		t.Fatal("tunnel closed")
	default:
	}
}

func str(s string) []byte { b, _ := proto.Marshal(wrapperspb.String(s)); return b }

// healthy proves the tunnel still serves: a valid component call on a fresh id works.
func (r *tunRig) healthy(t *testing.T, id uint64) {
	t.Helper()
	r.send(fleet.Frame{CallID: id, Body: fleet.BodyOpen, Method: mReport})
	r.send(fleet.Frame{CallID: id, Body: fleet.BodyData, Payload: str("x")})
	r.send(fleet.Frame{CallID: id, Body: fleet.BodyHalfClose})
	for {
		f := r.next(t)
		if f.CallID == id && f.Body == fleet.BodyClose {
			if f.Code != 0 {
				t.Fatalf("healthy call closed with code %d", f.Code)
			}
			return
		}
	}
}

// ---- A: dispatch ----

func TestMethodCorpusIsOnePermissionDenied(t *testing.T) {
	corpus := []string{
		mOther, // another contract's method
		mPing,  // server-only method, opened by the component
		mWatch,
		"/grpc.health.v1.Health/Check", // health
		"/grpc.health.v1.Health/Watch",
		"/grpc.reflection.v1.ServerReflection/ServerReflectionInfo",
		"/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo",
		"/grpc.channelz.v1.Channelz/GetChannel",
		"/t.v1.up/Report", // case
		"/t.v1.Up/report",
		"t.v1.Up/Report", // slash variants
		"//t.v1.Up/Report",
		"/t.v1.Up/Report/",
		"/t.v1.Up//Report",
		"/t.v1.Up/Report ", // suffix
		"/t.v1.Up/ReportX",
		"/t.v1.Up/Report\x00",
		"/t.v1.Up",
		"/activediq.fleet.v1.Fleet/Enroll",
		"/activediq.fleet.v1.Fleet/Tunnel",
		"/activediq.connector.v1.Connector/Describe",
		"",
		"/",
	}
	r := newRig(t, nil)
	var first fleet.Frame
	for i, m := range corpus {
		id := uint64(2 * (i + 1))
		r.send(fleet.Frame{CallID: id, Body: fleet.BodyOpen, Method: m})
		f := r.next(t)
		if f.CallID != id || f.Body != fleet.BodyClose || f.Code != int32(codes.PermissionDenied) {
			t.Fatalf("%q: got %+v", m, f)
		}
		if i == 0 {
			first = f
		} else if f.Message != first.Message {
			t.Fatalf("%q: refusal text differs: %q vs %q", m, f.Message, first.Message)
		}
		r.open(t)
	}
	if r.cnt.ran.Load() != 0 {
		t.Fatal("a handler ran for a refused method")
	}
	r.healthy(t, uint64(2*(len(corpus)+1)))
	if r.cnt.ran.Load() != 1 {
		t.Fatal("the allowed method did not run exactly once")
	}
}

func TestInvalidMethodNamesCloseTheTunnelWithoutRunningAHandler(t *testing.T) {
	for name, m := range map[string]string{"too long": "/t.v1.Up/" + strings.Repeat("a", 300), "not utf-8": "/t.v1.Up/\xff\xfe"} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t, nil)
			r.send(fleet.Frame{CallID: 2, Body: fleet.BodyOpen, Method: m})
			var pe *fleet.ProtocolError
			if err := r.closed(t); !errors.As(err, &pe) || pe.Violation != fleet.ViolationBadMethod {
				t.Fatalf("got %v", err)
			}
			if r.cnt.ran.Load() != 0 {
				t.Fatal("handler ran")
			}
		})
	}
}

func TestServerCannotCallComponentToServerMethods(t *testing.T) {
	r := newRig(t, nil)
	for _, m := range []string{mReport, mOther, "/grpc.health.v1.Health/Check", "/t.v1.down/Ping"} {
		err := r.m.Conn().Invoke(context.Background(), m, wrapperspb.String("x"), new(wrapperspb.StringValue))
		if status.Code(err) != codes.PermissionDenied || status.Convert(err).Message() != fleet.FixedText(codes.PermissionDenied) {
			t.Fatalf("%q: %v", m, err)
		}
	}
	select {
	case f := <-r.peer.in:
		t.Fatalf("a refused call put %+v on the wire", f)
	case <-time.After(50 * time.Millisecond):
	}
}

func TestRegistrarRefusesServicesOutsideTheContract(t *testing.T) {
	for _, svc := range []string{"grpc.health.v1.Health", "grpc.reflection.v1.ServerReflection", "grpc.channelz.v1.Channelz", "t.v1.Other"} {
		_, err := fleet.NewMux(fleet.MuxConfig{
			Role: fleet.RoleServer, Identity: ident("connector"), Transport: &wire{}, Reporter: &recorder{},
			Binding: fleet.Binding{Contract: testContract(t), Serve: func(_ fleet.Identity, reg grpc.ServiceRegistrar) {
				reg.RegisterService(&grpc.ServiceDesc{ServiceName: svc, Methods: []grpc.MethodDesc{{MethodName: "Check"}}}, struct{}{})
			}},
		})
		if !errors.Is(err, fleet.ErrForeignImpl) {
			t.Fatalf("%s: got %v", svc, err)
		}
	}
}

func TestBindingComesFromKind(t *testing.T) {
	b := fleet.Bindings{"connector": {Contract: testContract(t)}}
	if _, err := b.For(ident("connector")); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{fleet.KindADDC, fleet.KindFileServer, "agent"} {
		if _, err := b.For(ident(k)); !errors.Is(err, fleet.ErrNoBinding) {
			t.Fatalf("%s must not get the connector's contract: %v", k, err)
		}
	}
}

// TM-D24 A1 / TM-TB12-T16: one contract per module kind. A tunnel opened by each kind's identity runs
// its own contract's method and refuses the methods of either other kind with PERMISSION_DENIED.
func TestCrossKindContractsAreIsolated(t *testing.T) {
	svcOf := map[string]string{fleet.KindConnector: "UpConnector", fleet.KindADDC: "UpAddc", fleet.KindFileServer: "UpFileserver"}
	b := fleet.Bindings{}
	for k, svc := range svcOf {
		svc := svc
		c, err := fleet.NewContract("t"+svc, []protoreflect.ServiceDescriptor{svcDesc(t, "Down"+svc, "Ping")}, []protoreflect.ServiceDescriptor{svcDesc(t, svc, "Report")})
		if err != nil {
			t.Fatal(err)
		}
		b[k] = fleet.Binding{Contract: c, Serve: func(_ fleet.Identity, reg grpc.ServiceRegistrar) {
			reg.RegisterService(&grpc.ServiceDesc{ServiceName: "t.v1." + svc, HandlerType: (*any)(nil), Methods: []grpc.MethodDesc{{
				MethodName: "Report",
				Handler: func(_ any, _ context.Context, dec func(any) error, _ grpc.UnaryServerInterceptor) (any, error) {
					in := new(wrapperspb.StringValue)
					if err := dec(in); err != nil {
						return nil, err
					}
					return wrapperspb.String("ok"), nil
				},
			}}}, struct{}{})
		}}
	}
	for k := range svcOf {
		bd, err := b.For(ident(k))
		if err != nil {
			t.Fatal(err)
		}
		r := newRig(t, func(c *fleet.MuxConfig) { c.Identity, c.Binding = ident(k), bd })
		id := uint64(2)
		for other, svc := range svcOf {
			m := "/t.v1." + svc + "/Report"
			r.send(fleet.Frame{CallID: id, Body: fleet.BodyOpen, Method: m})
			if other == k {
				r.send(fleet.Frame{CallID: id, Body: fleet.BodyData, Payload: str("x")})
				r.send(fleet.Frame{CallID: id, Body: fleet.BodyHalfClose})
			}
			var f fleet.Frame
			for {
				f = r.next(t)
				if f.CallID == id && f.Body == fleet.BodyClose {
					break
				}
			}
			want := int32(codes.PermissionDenied)
			if other == k {
				want = 0
			}
			if f.Code != want {
				t.Errorf("%s opening %s's method: code %d, want %d", k, other, f.Code, want)
			}
			id += 2
		}
	}
}

// ---- B: call identity ----

func TestProtocolViolationsCloseTheTunnelAndAreAudited(t *testing.T) {
	// The server opens call 1 (streaming) before each case where the case needs a live server call.
	cases := []struct {
		name  string
		setup func(r *tunRig) // runs first
		frame fleet.Frame
		want  fleet.Violation
	}{
		{"empty body", nil, fleet.Frame{CallID: 2}, fleet.ViolationEmptyBody},
		{"open with the server's parity", nil, fleet.Frame{CallID: 3, Body: fleet.BodyOpen, Method: mReport}, fleet.ViolationWrongParity},
		{"open on call 0", nil, fleet.Frame{CallID: 0, Body: fleet.BodyOpen, Method: mReport}, fleet.ViolationCallZero},
		{"data on call 0", nil, fleet.Frame{CallID: 0, Body: fleet.BodyData, Payload: []byte("x")}, fleet.ViolationCallZero},
		{"close on call 0", nil, fleet.Frame{CallID: 0, Body: fleet.BodyClose}, fleet.ViolationCallZero},
		{"cancel on call 0", nil, fleet.Frame{CallID: 0, Body: fleet.BodyCancel}, fleet.ViolationCallZero},
		{"half-close on call 0", nil, fleet.Frame{CallID: 0, Body: fleet.BodyHalfClose}, fleet.ViolationCallZero},
		{"data on a never-opened id", nil, fleet.Frame{CallID: 8, Body: fleet.BodyData}, fleet.ViolationUnknownCall},
		{"cancel on a never-opened id", nil, fleet.Frame{CallID: 4, Body: fleet.BodyCancel}, fleet.ViolationUnknownCall},
		{"data on the server's never-opened id", nil, fleet.Frame{CallID: 1, Body: fleet.BodyData}, fleet.ViolationUnknownCall},
		{"oversize payload", nil, fleet.Frame{CallID: 2, Body: fleet.BodyData, Payload: make([]byte, 5<<20)}, fleet.ViolationOversize},
		{"reused id", func(r *tunRig) { r.healthy(t, 2) }, fleet.Frame{CallID: 2, Body: fleet.BodyOpen, Method: mReport}, fleet.ViolationNonIncreasing},
		{"lower id", func(r *tunRig) { r.healthy(t, 6) }, fleet.Frame{CallID: 4, Body: fleet.BodyOpen, Method: mReport}, fleet.ViolationNonIncreasing},
		{"open on a refused id again", func(r *tunRig) {
			r.send(fleet.Frame{CallID: 2, Body: fleet.BodyOpen, Method: mOther})
			r.next(t)
		}, fleet.Frame{CallID: 2, Body: fleet.BodyOpen, Method: mReport}, fleet.ViolationNonIncreasing},
		{"data after the peer's half-close", func(r *tunRig) {
			r.send(fleet.Frame{CallID: 2, Body: fleet.BodyOpen, Method: mReport})
			r.send(fleet.Frame{CallID: 2, Body: fleet.BodyHalfClose})
		}, fleet.Frame{CallID: 2, Body: fleet.BodyData}, fleet.ViolationForbidden},
		{"second half-close", func(r *tunRig) {
			r.send(fleet.Frame{CallID: 2, Body: fleet.BodyOpen, Method: mReport})
			r.send(fleet.Frame{CallID: 2, Body: fleet.BodyHalfClose})
		}, fleet.Frame{CallID: 2, Body: fleet.BodyHalfClose}, fleet.ViolationForbidden},
		{"close by the opener", func(r *tunRig) {
			r.send(fleet.Frame{CallID: 2, Body: fleet.BodyOpen, Method: mReport})
		}, fleet.Frame{CallID: 2, Body: fleet.BodyClose}, fleet.ViolationForbidden},
		{"frame after the peer's cancel", func(r *tunRig) {
			r.send(fleet.Frame{CallID: 2, Body: fleet.BodyOpen, Method: mReport})
			r.send(fleet.Frame{CallID: 2, Body: fleet.BodyCancel})
		}, fleet.Frame{CallID: 2, Body: fleet.BodyData}, fleet.ViolationForbidden},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newRig(t, nil)
			if tc.setup != nil {
				tc.setup(r)
			}
			r.send(tc.frame)
			var pe *fleet.ProtocolError
			if err := r.closed(t); !errors.As(err, &pe) || pe.Violation != tc.want {
				t.Fatalf("got %v, want %s", err, tc.want)
			}
			if vs := r.rep.got(); len(vs) != 1 || vs[0] != tc.want || r.rep.ids[0].ComponentID != compID {
				t.Fatalf("audit: %v %+v", vs, r.rep.ids)
			}
		})
	}
}

// Frames the opened-by-server call forbids to the component.
func TestRoleViolationsOnAServerOpenedCall(t *testing.T) {
	for name, body := range map[string]fleet.Frame{
		"half-close by the callee": {Body: fleet.BodyHalfClose},
		"cancel by the callee":     {Body: fleet.BodyCancel},
		"open on a live id":        {Body: fleet.BodyOpen, Method: mPing},
		"data after close":         {Body: fleet.BodyData},
	} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t, nil)
			go func() {
				_ = r.m.Conn().Invoke(context.Background(), mPing, wrapperspb.String("x"), new(wrapperspb.StringValue))
			}()
			open := r.next(t)
			if open.Body != fleet.BodyOpen || open.CallID != 1 {
				t.Fatalf("got %+v", open)
			}
			f := body
			f.CallID = 1
			if name == "data after close" {
				r.send(fleet.Frame{CallID: 1, Body: fleet.BodyClose})
			}
			if name == "open on a live id" {
				f.CallID = 3 // wrong parity for a component open
			}
			r.send(f)
			var pe *fleet.ProtocolError
			if err := r.closed(t); !errors.As(err, &pe) {
				t.Fatalf("got %v", err)
			}
		})
	}
}

func TestInFlightFramesAfterOwnEndAreDropped(t *testing.T) {
	t.Run("after this side cancels", func(t *testing.T) {
		r := newRig(t, nil)
		ctx, cancel := context.WithCancel(context.Background())
		errc := make(chan error, 1)
		go func() { errc <- r.m.Conn().Invoke(ctx, mPing, wrapperspb.String("x"), new(wrapperspb.StringValue)) }()
		if r.next(t).Body != fleet.BodyOpen {
			t.Fatal("no open")
		}
		_ = r.next(t) // data
		_ = r.next(t) // half-close
		cancel()
		if f := r.next(t); f.Body != fleet.BodyCancel || f.CallID != 1 {
			t.Fatalf("got %+v", f)
		}
		if status.Code(<-errc) != codes.Canceled {
			t.Fatal("want Canceled")
		}
		// The component had already sent these.
		r.send(fleet.Frame{CallID: 1, Body: fleet.BodyData, Payload: str("late")})
		r.send(fleet.Frame{CallID: 1, Body: fleet.BodyClose})
		r.send(fleet.Frame{CallID: 1, Body: fleet.BodyCredit, Messages: 1})
		r.healthy(t, 2)
		r.open(t)
	})
	t.Run("after this side closes", func(t *testing.T) {
		r := newRig(t, nil)
		r.healthy(t, 2)
		r.send(fleet.Frame{CallID: 2, Body: fleet.BodyData, Payload: str("late")})
		r.send(fleet.Frame{CallID: 2, Body: fleet.BodyCancel})
		r.send(fleet.Frame{CallID: 2, Body: fleet.BodyHalfClose})
		r.healthy(t, 4)
		r.open(t)
	})
	t.Run("after this side refuses", func(t *testing.T) {
		r := newRig(t, nil)
		r.send(fleet.Frame{CallID: 2, Body: fleet.BodyOpen, Method: mOther})
		r.next(t)
		r.send(fleet.Frame{CallID: 2, Body: fleet.BodyData, Payload: str("x")})
		r.send(fleet.Frame{CallID: 2, Body: fleet.BodyHalfClose})
		r.healthy(t, 4)
		r.open(t)
	})
}

func TestCreditOnCallZeroIsAllowed(t *testing.T) {
	r := newRig(t, nil)
	r.send(fleet.Frame{CallID: 0, Body: fleet.BodyCredit, Messages: 10})
	r.healthy(t, 2)
}

func TestPendingCallsFailUnavailableOutcomeUnknownAndAreNeverRebound(t *testing.T) {
	hub := fleet.NewHub()
	id := ident("connector")
	r1 := newRig(t, func(c *fleet.MuxConfig) { c.Identity = id })
	detach := hub.Attach(r1.m)
	defer detach()

	errc := make(chan error, 1)
	go func() {
		errc <- hub.Conn(id.Tenant, id.ComponentID).Invoke(context.Background(), mPing, wrapperspb.String("x"), new(wrapperspb.StringValue))
	}()
	if f := r1.next(t); f.Body != fleet.BodyOpen {
		t.Fatalf("got %+v", f)
	}
	r1.peer.drop() // the tunnel drops with the call pending

	err := <-errc
	if status.Code(err) != codes.Unavailable || !fleet.OutcomeUnknown(err) {
		t.Fatalf("pending call: %v (unknown=%v)", err, fleet.OutcomeUnknown(err))
	}

	// A second tunnel for the same component opens.
	r2 := newRig(t, func(c *fleet.MuxConfig) { c.Identity = id })
	hub.Attach(r2.m)
	select {
	case f := <-r2.peer.in:
		t.Fatalf("the pending call was rebound to the new tunnel: %+v", f)
	case <-time.After(100 * time.Millisecond):
	}
	// A frame for the old call id on the new tunnel is a violation there, not a delivery.
	r2.send(fleet.Frame{CallID: 1, Body: fleet.BodyClose})
	var pe *fleet.ProtocolError
	if e := r2.closed(t); !errors.As(e, &pe) || pe.Violation != fleet.ViolationUnknownCall {
		t.Fatalf("got %v", e)
	}
}

func TestNewTunnelDisplacesTheOldAndFailsItsPendingCalls(t *testing.T) {
	hub := fleet.NewHub()
	id := ident("connector")
	r1 := newRig(t, func(c *fleet.MuxConfig) { c.Identity = id })
	hub.Attach(r1.m)
	errc := make(chan error, 1)
	go func() {
		errc <- hub.Conn(id.Tenant, id.ComponentID).Invoke(context.Background(), mPing, wrapperspb.String("x"), new(wrapperspb.StringValue))
	}()
	r1.next(t)
	r2 := newRig(t, func(c *fleet.MuxConfig) { c.Identity = id })
	hub.Attach(r2.m)
	err := <-errc
	if status.Code(err) != codes.Unavailable || !fleet.OutcomeUnknown(err) {
		t.Fatalf("got %v", err)
	}
	select {
	case f := <-r2.peer.in:
		t.Fatalf("rebound: %+v", f)
	case <-time.After(100 * time.Millisecond):
	}
}

func TestHubWithoutTunnelIsUnavailable(t *testing.T) {
	err := fleet.NewHub().Conn(tenant.New(), compID).Invoke(context.Background(), mPing, wrapperspb.String("x"), new(wrapperspb.StringValue))
	if status.Code(err) != codes.Unavailable || fleet.OutcomeUnknown(err) {
		t.Fatalf("got %v", err)
	}
}

func TestConcurrentCallsAreBounded(t *testing.T) {
	r := newRig(t, func(c *fleet.MuxConfig) { c.MaxCalls = 2 })
	// Peer-opened: two stay open (no half-close), the third is refused, the tunnel lives.
	r.send(fleet.Frame{CallID: 2, Body: fleet.BodyOpen, Method: mReport})
	r.send(fleet.Frame{CallID: 4, Body: fleet.BodyOpen, Method: mReport})
	r.send(fleet.Frame{CallID: 6, Body: fleet.BodyOpen, Method: mReport})
	if f := r.next(t); f.CallID != 6 || f.Code != int32(codes.ResourceExhausted) {
		t.Fatalf("got %+v", f)
	}
	r.open(t)
	// Server-opened.
	for i := 0; i < 2; i++ {
		go func() {
			_ = r.m.Conn().Invoke(context.Background(), mPing, wrapperspb.String("hang"), new(wrapperspb.StringValue))
		}()
		for r.next(t).Body != fleet.BodyHalfClose {
		}
	}
	err := r.m.Conn().Invoke(context.Background(), mPing, wrapperspb.String("x"), new(wrapperspb.StringValue))
	if status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("got %v", err)
	}
}

// ---- C: untrusted CallClose text ----

func TestSanitizeStatusText(t *testing.T) {
	hostile := map[string]string{
		"crlf":    "line1\r\nFORGED 2026-01-01 level=info msg=admin logged in",
		"ansi":    "\x1b[31mred\x1b[0m\x1b]0;title\a",
		"bidi":    "abc\u202edef\u2066x\u2069\u200f\u061c",
		"c1":      "a\u0085b\u009bc",
		"html":    `<script>alert(1)</script><img src=x onerror="a()">&amp;`,
		"invalid": "ok\xff\xfe\xc3\x28end",
		"nul":     "a\x00b\x7f",
		"sep":     "a\u2028b\u2029c",
		"huge":    strings.Repeat("A", 1<<20),
		"hugeesc": strings.Repeat("\x1b", 1<<20),
		"hugemb":  strings.Repeat("\u00e9", 1<<19),
	}
	for name, in := range hostile {
		out := fleet.SanitizeStatusText(in)
		if len(out) > fleet.MaxStatusMessage {
			t.Errorf("%s: %d bytes", name, len(out))
		}
		if !isCleanUTF8(out) {
			t.Errorf("%s: output is not clean: %q", name, out)
		}
	}
	if got := fleet.SanitizeStatusText("a\r\nb"); got != `a\u000d\u000ab` {
		t.Errorf("got %q", got)
	}
	if got := fleet.SanitizeStatusText("x\u202ey"); got != `x\u202ey` {
		t.Errorf("got %q", got)
	}
	if got := fleet.SanitizeStatusText("plain text, 42 items"); got != "plain text, 42 items" {
		t.Errorf("plain text changed: %q", got)
	}
	// The cut falls on an escape or rune boundary, never inside one.
	if out := fleet.SanitizeStatusText(strings.Repeat("\u00e9", 2000)); len(out) != 1024 || strings.Contains(out, "\ufffd") {
		t.Errorf("rune cut: %d", len(out))
	}
	if out := fleet.SanitizeStatusText(strings.Repeat("\n", 2000)); strings.HasSuffix(out, `\u00`) || len(out)%6 != 0 {
		t.Errorf("escape cut: %q", out[len(out)-8:])
	}
}

func isCleanUTF8(s string) bool {
	for _, r := range s {
		switch {
		case r == 0xFFFD && false:
		case r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f), r == '<', r == '>', r == '&':
			return false
		case r >= 0x202a && r <= 0x202e, r >= 0x2066 && r <= 0x2069, r == 0x2028, r == 0x2029:
			return false
		}
	}
	return true
}

func TestNormalizeCode(t *testing.T) {
	for in, want := range map[int32]codes.Code{0: codes.OK, 5: codes.NotFound, 16: codes.Unauthenticated, 17: codes.Unknown, -1: codes.Unknown, 1 << 30: codes.Unknown, -1 << 31: codes.Unknown} {
		if got := fleet.NormalizeCode(in); got != want {
			t.Errorf("%d: got %v want %v", in, got, want)
		}
	}
}

func TestComponentCloseTextIsBoundedEscapedAndKeptApart(t *testing.T) {
	for _, tc := range []struct {
		name string
		code int32
		msg  string
		want codes.Code
	}{
		{"crlf", 13, "boom\r\n2026-01-01 level=ERROR forged", codes.Internal},
		{"ansi", 5, "\x1b[2J\x1b[31m", codes.NotFound},
		{"bidi", 9, "\u202eevil", codes.FailedPrecondition},
		{"invalid utf-8", 3, "\xff\xfe", codes.InvalidArgument},
		{"html", 2, "<b>hi</b>", codes.Unknown},
		{"1 MiB", 13, strings.Repeat("x", 1<<20), codes.Internal},
		{"code 17", 17, "x", codes.Unknown},
		{"code 99999", 99999, "x", codes.Unknown},
		{"code -5", -5, "x", codes.Unknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newRig(t, func(c *fleet.MuxConfig) { c.MaxPayload = 2 << 20 })
			errc := make(chan error, 1)
			go func() {
				errc <- r.m.Conn().Invoke(context.Background(), mPing, wrapperspb.String("x"), new(wrapperspb.StringValue))
			}()
			for r.next(t).Body != fleet.BodyHalfClose {
			}
			r.send(fleet.Frame{CallID: 1, Body: fleet.BodyClose, Code: tc.code, Message: tc.msg})
			err := <-errc
			if status.Code(err) != tc.want {
				t.Fatalf("code %v want %v", status.Code(err), tc.want)
			}
			if got := status.Convert(err).Message(); got != fleet.FixedText(tc.want) {
				t.Fatalf("the API-facing text is %q, not the fixed text", got)
			}
			rep, ok := fleet.ComponentReported(err)
			if !ok || len(rep) > fleet.MaxStatusMessage || !isCleanUTF8(rep) {
				t.Fatalf("component_reported: ok=%v len=%d %q", ok, len(rep), rep)
			}
			if strings.ContainsAny(err.Error(), "\r\n\x1b<") || strings.Contains(err.Error(), "forged") {
				t.Fatalf("the error string carries component text: %q", err.Error())
			}
			logs := r.logs.String()
			if strings.Count(logs, "\n") > 1 || strings.ContainsAny(strings.TrimSuffix(logs, "\n"), "\r\x1b") || strings.Contains(logs, "\u202e") {
				t.Fatalf("log line forged or unescaped: %q", logs)
			}
			if len(logs) > 4096 {
				t.Fatalf("log line is %d bytes", len(logs))
			}
			if got := r.rep.got(); len(got) != 0 {
				t.Fatalf("a hostile close text is not a protocol error: %v", got)
			}
		})
	}
}

func TestServerTextIsFixedPerCode(t *testing.T) {
	srv, comp := e2e(t, nil)
	_ = srv
	err := comp.Conn().Invoke(context.Background(), mReport, wrapperspb.String("x"), new(wrapperspb.StringValue))
	if err != nil {
		t.Fatal(err)
	}
	// The component's handler fails with an internal detail; the server's side of the wire is fixed text.
	err = srv.Conn().Invoke(context.Background(), mPing, wrapperspb.String("fail"), new(wrapperspb.StringValue))
	if status.Code(err) != codes.NotFound || strings.Contains(err.Error(), "passwd") {
		t.Fatalf("got %v", err)
	}
	if rep, ok := fleet.ComponentReported(err); !ok || rep != "not found" {
		// A conforming component also sends fixed text; the server still treats it as untrusted.
		t.Fatalf("reported %q %v", rep, ok)
	}
}

// ---- end to end ----

// e2e connects a server Mux and a component Mux over a pipe.
func e2e(t *testing.T, cancelled chan<- struct{}) (srv, comp *fleet.Mux) {
	t.Helper()
	a, b := newWires()
	ct := testContract(t)
	cnt := &counters{}
	id := ident("connector")
	var err error
	srv, err = fleet.NewMux(fleet.MuxConfig{Role: fleet.RoleServer, Identity: id, Transport: a, Reporter: &recorder{}, Binding: fleet.Binding{Contract: ct, Serve: serverHandlers(cnt)}})
	if err != nil {
		t.Fatal(err)
	}
	comp, err = fleet.NewMux(fleet.MuxConfig{Role: fleet.RoleComponent, Identity: id, Transport: b, Binding: fleet.Binding{Contract: ct, Serve: componentHandlers(cancelled)}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	for _, m := range []*fleet.Mux{srv, comp} {
		wg.Add(1)
		go func() { defer wg.Done(); _ = m.Run(ctx) }()
	}
	t.Cleanup(func() { cancel(); a.drop(); wg.Wait() })
	return srv, comp
}

func TestEndToEnd(t *testing.T) {
	cancelled := make(chan struct{}, 1)
	srv, comp := e2e(t, cancelled)

	out := new(wrapperspb.StringValue)
	if err := srv.Conn().Invoke(context.Background(), mPing, wrapperspb.String("a"), out); err != nil || out.Value != "pong:a" {
		t.Fatalf("server to component: %v %q", err, out.Value)
	}
	if err := comp.Conn().Invoke(context.Background(), mReport, wrapperspb.String("b"), out); err != nil || out.Value != "ok:b" {
		t.Fatalf("component to server: %v %q", err, out.Value)
	}
	// The component cannot call the server-only method on the server, nor the server a component-only one.
	if err := comp.Conn().Invoke(context.Background(), mPing, wrapperspb.String("b"), out); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("got %v", err)
	}

	st, err := srv.Conn().NewStream(context.Background(), &grpc.StreamDesc{ServerStreams: true}, mWatch)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SendMsg(wrapperspb.String("w")); err != nil {
		t.Fatal(err)
	}
	_ = st.CloseSend()
	n := 0
	for {
		m := new(wrapperspb.StringValue)
		if err := st.RecvMsg(m); err != nil {
			if !errors.Is(err, io.EOF) {
				t.Fatal(err)
			}
			break
		}
		n++
	}
	if n != 3 {
		t.Fatalf("got %d stream messages", n)
	}

	// Cancelling the caller reaches the handler's context.
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { errc <- srv.Conn().Invoke(ctx, mPing, wrapperspb.String("hang"), out) }()
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case <-cancelled:
	case <-time.After(3 * time.Second):
		t.Fatal("the cancel did not reach the handler")
	}
	if status.Code(<-errc) != codes.Canceled {
		t.Fatal("want Canceled")
	}

	// A deadline travels as timeout_ms and ends the handler.
	dctx, dcancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer dcancel()
	if err := srv.Conn().Invoke(dctx, mPing, wrapperspb.String("hang"), out); status.Code(err) != codes.DeadlineExceeded {
		t.Fatalf("got %v", err)
	}
	select {
	case <-cancelled:
	case <-time.After(3 * time.Second):
		t.Fatal("the deadline did not reach the handler")
	}
}

func TestManyConcurrentCallsKeepIdsInOrder(t *testing.T) {
	srv, _ := e2e(t, nil)
	var wg sync.WaitGroup
	var bad atomic.Int32
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			out := new(wrapperspb.StringValue)
			if err := srv.Conn().Invoke(context.Background(), mPing, wrapperspb.String("n"), out); err != nil || out.Value != "pong:n" {
				bad.Add(1)
			}
		}()
	}
	wg.Wait()
	select {
	case <-srv.Done():
		t.Fatal("tunnel closed under concurrent calls")
	default:
	}
	if bad.Load() != 0 {
		t.Fatalf("%d calls failed", bad.Load())
	}
}

// unaryServe registers t.v1.Up/Report with a handler h that the test controls.
func unaryServe(h func(ctx context.Context, dec func(any) error) (any, error)) func(fleet.Identity, grpc.ServiceRegistrar) {
	return func(_ fleet.Identity, reg grpc.ServiceRegistrar) {
		reg.RegisterService(&grpc.ServiceDesc{ServiceName: "t.v1.Up", HandlerType: (*any)(nil), Methods: []grpc.MethodDesc{{
			MethodName: "Report",
			Handler: func(_ any, ctx context.Context, dec func(any) error, _ grpc.UnaryServerInterceptor) (any, error) {
				return h(ctx, dec)
			},
		}}}, struct{}{})
	}
}

// A second CallData on a unary component-opened call is a violation and never reaches the handler.
func TestSecondDataOnAUnaryCallClosesTheTunnel(t *testing.T) {
	release := make(chan struct{})
	started := make(chan struct{})
	var reads atomic.Int32
	r := newRig(t, func(c *fleet.MuxConfig) {
		c.Binding.Serve = unaryServe(func(_ context.Context, dec func(any) error) (any, error) {
			close(started)
			<-release
			for {
				if err := dec(new(wrapperspb.StringValue)); err != nil {
					return nil, err
				}
				reads.Add(1)
			}
		})
	})
	r.send(fleet.Frame{CallID: 2, Body: fleet.BodyOpen, Method: mReport})
	r.send(fleet.Frame{CallID: 2, Body: fleet.BodyData, Payload: str("one")})
	<-started
	r.send(fleet.Frame{CallID: 2, Body: fleet.BodyData, Payload: str("two")})
	select {
	case <-r.m.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("tunnel did not close")
	}
	close(release) // Run waits for the handler
	var pe *fleet.ProtocolError
	if err := r.closed(t); !errors.As(err, &pe) || pe.Violation != fleet.ViolationForbidden {
		t.Fatalf("got %v", err)
	}
	if vs := r.rep.got(); len(vs) != 1 || r.rep.ids[0].ComponentID != compID {
		t.Fatalf("audit: %v", vs)
	}
	if reads.Load() > 1 {
		t.Fatalf("handler read %d messages", reads.Load())
	}
}

// Calls that end while the component has over-sent data must not leave the payload retained.
func TestRetiredCallsRetainNoPayload(t *testing.T) {
	r := newRig(t, func(c *fleet.MuxConfig) {
		c.Binding.Serve = unaryServe(func(context.Context, func(any) error) (any, error) {
			return wrapperspb.String("ok"), nil // replies without reading the request
		})
	})
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	const calls, size = 300, 1 << 20
	big := make([]byte, size)
	for i := 0; i < calls; i++ {
		id := uint64(2 + 2*i)
		r.send(fleet.Frame{CallID: id, Body: fleet.BodyOpen, Method: mReport})
		r.send(fleet.Frame{CallID: id, Body: fleet.BodyData, Payload: append([]byte(nil), big...)})
		for {
			f := r.next(t)
			if f.CallID == id && f.Body == fleet.BodyClose {
				break
			}
		}
	}
	r.open(t)
	runtime.GC()
	runtime.GC()
	runtime.ReadMemStats(&after)
	if grew := int64(after.HeapInuse) - int64(before.HeapInuse); grew > 64<<20 {
		t.Fatalf("heap grew by %d MiB after %d finished calls", grew>>20, calls)
	}
}

// Regression (T-0287): a tunnel that ends while the caller is still sending must end the pending call
// as UNAVAILABLE with an unknown outcome — never a raw transport error, never a known-outcome
// UNAVAILABLE that a retry loop would take for "not sent".
func TestCallPendingWhenTunnelEndsAlwaysEndsOutcomeUnknown(t *testing.T) {
	for i := 0; i < 300; i++ {
		r := newRig(t, nil)
		errc := make(chan error, 1)
		go func() {
			errc <- r.m.Conn().Invoke(context.Background(), mPing, wrapperspb.String("x"), new(wrapperspb.StringValue))
		}()
		if f := r.next(t); f.Body != fleet.BodyOpen {
			t.Fatalf("got %+v", f)
		}
		r.m.Close()
		err := <-errc
		if status.Code(err) != codes.Unavailable || !fleet.OutcomeUnknown(err) {
			t.Fatalf("iteration %d: %v (unknown=%v)", i, err, fleet.OutcomeUnknown(err))
		}
	}
}
