package fleetproof

import (
	"context"
	"crypto/x509"
	"net"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/fleet/fleetsql"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
	"github.com/skenzeriq/activediq/internal/platform/tenant/tenanttest"

	tunnelserver "github.com/skenzeriq/activediq/internal/compose/server"
	"github.com/skenzeriq/activediq/internal/platform/fleet"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
	fleetv1 "github.com/skenzeriq/activediq/internal/proto/activediq/fleet/v1"
)

const sibID = "66666666-7777-4888-8999-aaaaaaaaaaaa"

// recSink records the audit events the real fleetsql.TunnelReporter appends.
type recSink struct {
	mu  sync.Mutex
	evs []audit.Event
}

func (s *recSink) Append(_ context.Context, _ store.Tx, ev audit.Event) error {
	if err := ev.Validate(); err != nil {
		return err
	}
	s.mu.Lock()
	s.evs = append(s.evs, ev)
	s.mu.Unlock()
	return nil
}

func (s *recSink) got() []audit.Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]audit.Event(nil), s.evs...)
}

// startTunnel serves the real compose Fleet service (NewFleetService) under the real gateway, with
// the real TunnelReporter over a seeded tenant database.
func startTunnel(t *testing.T, srv *storetest.Server) (*rig, *fleet.Hub, *recSink) {
	t.Helper()
	d := srv.NewDatabase(t)
	d.Migrate(t)
	tid := tenanttest.Seed(t, d.ExecOwner, "A")
	db, err := store.Open(context.Background(), store.Config{DSN: d.AppDSN()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	ca := newAuthority(t, "installation CA")
	cm := &comps{}
	gw, err := fleet.NewGateway(fleet.Config{Methods: classes(), CAs: cas{tid: {ca.cert}}, Components: cm, Recheck: 50 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	b, err := tunnelserver.FleetBindings()
	if err != nil {
		t.Fatal(err)
	}
	hub, sink := fleet.NewHub(), &recSink{}
	svc, err := tunnelserver.NewFleetService(&fleetsql.Enroller{},
		tunnelserver.TunnelDeps{Hub: hub, Bindings: b, Reporter: &fleetsql.TunnelReporter{DB: db, Audit: sink}})
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)
	gs, err := gw.NewServer(ca.serverCert(t), func() *x509.CertPool { return pool }, func(r grpc.ServiceRegistrar) {
		fleetv1.RegisterFleetServer(r, svc)
	})
	if err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = gs.Serve(l) }()
	t.Cleanup(gs.Stop)
	return &rig{addr: l.Addr().String(), comps: cm, gw: gw, ca: ca, tid: tid, grpc: gs}, hub, sink
}

// openTunnel dials as comp and returns the stream and a channel of the frames the server sends.
func openTunnel(t *testing.T, r *rig, comp string) (grpc.BidiStreamingClient[fleetv1.TunnelFrame, fleetv1.TunnelFrame], <-chan *fleetv1.TunnelFrame) {
	t.Helper()
	c := r.ca.clientCert(t, r.tid, comp)
	s, err := fleetv1.NewFleetClient(r.conn(t, &c)).Tunnel(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	in := make(chan *fleetv1.TunnelFrame, 16)
	go func() {
		defer close(in)
		for {
			f, err := s.Recv()
			if err != nil {
				return
			}
			in <- f
		}
	}()
	return s, in
}

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for end := time.Now().Add(5 * time.Second); !ok(); time.Sleep(10 * time.Millisecond) {
		if time.Now().After(end) {
			t.Fatal("timed out: " + what)
		}
	}
}

const describe = "/activediq.connector.v1.Connector/Describe"

func invoke(hub *fleet.Hub, tid tenant.ID, comp string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return hub.Conn(tid, comp).Invoke(ctx, describe, &connectorv1.DescribeRequest{}, new(connectorv1.DescribeResponse))
}

func TestRevokedComponentsMuxFailsAndHubRefusesButSiblingWorks(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) { revokedProof(t, s) })
}

func revokedProof(t *testing.T, srv *storetest.Server) {
	r, hub, _ := startTunnel(t, srv)
	_, inA := openTunnel(t, r, compID)
	sibS, sibIn := openTunnel(t, r, sibID)

	// A server-opened call to the victim stays pending: the component never answers. It is retried
	// only while the victim's tunnel is not yet attached (UNAVAILABLE with a known outcome).
	pending := make(chan error, 1)
	go func() {
		for end := time.Now().Add(5 * time.Second); ; {
			err := invoke(hub, r.tid, compID)
			if status.Code(err) == codes.Unavailable && !fleet.OutcomeUnknown(err) && time.Now().Before(end) {
				time.Sleep(10 * time.Millisecond)
				continue
			}
			pending <- err
			return
		}
	}()
	f := <-inA
	if f == nil || f.GetOpen() == nil || f.GetOpen().GetMethod() != describe {
		t.Fatalf("the victim should have been sent an open: %v", f)
	}

	start := time.Now()
	if n := r.gw.CloseComponent(r.tid, compID); n != 1 {
		t.Fatalf("closed %d streams", n)
	}
	select {
	case err := <-pending:
		if status.Code(err) != codes.Unavailable || !fleet.OutcomeUnknown(err) {
			t.Fatalf("pending call: %v (unknown=%v)", err, fleet.OutcomeUnknown(err))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the pending call did not end")
	}
	waitFor(t, "hub refuses the victim", func() bool {
		err := invoke(hub, r.tid, compID)
		return status.Code(err) == codes.Unavailable && !fleet.OutcomeUnknown(err)
	})
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("took %v", d)
	}

	// The sibling's entry still works: answer its Describe with an empty response.
	done := make(chan error, 1)
	go func() {
		// The sibling's tunnel may not be attached yet: UNAVAILABLE with a known outcome means retry.
		for end := time.Now().Add(5 * time.Second); ; {
			err := invoke(hub, r.tid, sibID)
			if status.Code(err) == codes.Unavailable && !fleet.OutcomeUnknown(err) && time.Now().Before(end) {
				time.Sleep(10 * time.Millisecond)
				continue
			}
			done <- err
			return
		}
	}()
	var open *fleetv1.TunnelFrame
	select {
	case open = <-sibIn:
	case <-time.After(5 * time.Second):
		t.Fatal("sibling got no open")
	}
	id := open.GetCallId()
	for _, fr := range []*fleetv1.TunnelFrame{
		{CallId: id, Body: &fleetv1.TunnelFrame_Data{Data: &fleetv1.CallData{}}},
		{CallId: id, Body: &fleetv1.TunnelFrame_Close{Close: &fleetv1.CallClose{}}},
	} {
		if err := sibS.Send(fr); err != nil {
			t.Fatal(err)
		}
	}
	if err := <-done; err != nil {
		t.Fatalf("sibling call: %v", err)
	}
}

func TestProtocolErrorOnTunnelIsReportedAgainstTheComponent(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) { violationProof(t, s) })
}

func violationProof(t *testing.T, srv *storetest.Server) {
	r, _, rep := startTunnel(t, srv)
	s, in := openTunnel(t, r, compID)
	// A frame on a call id that was never opened (TM-D24 B5).
	if err := s.Send(&fleetv1.TunnelFrame{CallId: 2, Body: &fleetv1.TunnelFrame_HalfClose{HalfClose: &fleetv1.CallHalfClose{}}}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-in: // the stream closes
	case <-time.After(5 * time.Second):
		t.Fatal("tunnel stayed open")
	}
	waitFor(t, "audit", func() bool { return len(rep.got()) == 1 })
	ev := rep.got()[0]
	if ev.Kind != fleetsql.KindTunnelProtocolError || ev.Target.GUID != compID || ev.Outcome != audit.Denied ||
		ev.Reason != string(fleet.ViolationUnknownCall) {
		t.Fatalf("event: %+v", ev)
	}
}
