package agent

import (
	"context"
	"errors"
	"io"
	"os"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	kernel "github.com/skenzeriq/activediq/internal/platform/agent"
	"github.com/skenzeriq/activediq/internal/platform/fleet"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
	addcv1 "github.com/skenzeriq/activediq/internal/proto/activediq/addc/v1"
	agentv1 "github.com/skenzeriq/activediq/internal/proto/skenzeriq/agent/v1"
)

type pipeEnd struct {
	in  <-chan fleet.Frame
	out chan<- fleet.Frame
}

func (p pipeEnd) Send(f fleet.Frame) error { p.out <- f; return nil }
func (p pipeEnd) Recv() (fleet.Frame, error) {
	f, ok := <-p.in
	if !ok {
		return fleet.Frame{}, io.EOF
	}
	return f, nil
}

type noRep struct{}

func (noRep) ProtocolError(context.Context, fleet.Identity, fleet.Violation) error { return nil }

type ingest struct {
	agentv1.UnimplementedEventIngestServer
	mu  sync.Mutex
	got []uint64
}

func (i *ingest) SubmitEvents(_ context.Context, in *agentv1.SubmitEventsRequest) (*agentv1.SubmitEventsResponse, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	for _, e := range in.Events {
		i.got = append(i.got, e.AgentSeq)
	}
	return &agentv1.SubmitEventsResponse{Accepted: uint64(len(in.Events)), HighestStoredSeq: in.Events[len(in.Events)-1].AgentSeq}, nil
}

func TestContractOverTunnel(t *testing.T) {
	tid, _ := tenant.Parse("11111111-1111-4111-8111-111111111111")
	id := fleet.Identity{Tenant: tid, Kind: fleet.KindADDC, ComponentID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"}
	c, err := addcContract()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	_ = os.Chmod(dir, 0o700)
	mod, _ := buildModule(fleet.KindADDC, "dc")
	h, err := kernel.Open(kernel.Config{Identity: id, DataDir: dir, Version: "t", Module: mod,
		Ceilings: kernel.Ceilings{OutboxMaxBytes: 8 << 20, BatchMaxBytes: 64 << 10, MaxEventsPerSecond: 50}})
	if err != nil {
		t.Fatal(err)
	}
	a, b := make(chan fleet.Frame, 64), make(chan fleet.Frame, 64)
	ing := &ingest{}
	srv, err := fleet.NewMux(fleet.MuxConfig{Role: fleet.RoleServer, Identity: id, Reporter: noRep{}, Transport: pipeEnd{in: a, out: b},
		Binding: fleet.Binding{Contract: c, Register: func(_ fleet.Identity, reg grpc.ServiceRegistrar) { agentv1.RegisterEventIngestServer(reg, ing) }}})
	if err != nil {
		t.Fatal(err)
	}
	comp, err := fleet.NewMux(fleet.MuxConfig{Role: fleet.RoleComponent, Identity: id, Transport: pipeEnd{in: b, out: a},
		Binding: fleet.Binding{Contract: c, Register: func(_ fleet.Identity, reg grpc.ServiceRegistrar) { h.Register(reg) }}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	go func() { _ = srv.Run(ctx) }()
	go func() { _ = comp.Run(ctx) }()
	go func() { _ = h.Run(ctx) }()
	h.SetEventClient(agentv1.NewEventIngestClient(comp.Conn()))

	// Server -> agent: the closed Host surface works.
	st, err := agentv1.NewHostClient(srv.Conn()).GetStatus(ctx, &agentv1.GetStatusRequest{})
	if err != nil || st.Anchored {
		t.Fatalf("GetStatus %v %v", st, err)
	}
	// Server -> agent: the module's own service is part of the contract.
	if _, err := addcv1.NewAddcClient(srv.Conn()).GetCollectionState(ctx, &addcv1.GetCollectionStateRequest{}); err != nil {
		t.Fatalf("GetCollectionState %v", err)
	}
	// Agent -> server: events flow through the outbox and sender.
	for i := 0; i < 3; i++ {
		_, _ = h.Outbox().Append(&agentv1.AgentEvent{Kind: agentv1.EventKind_EVENT_KIND_EVENT, Channel: "security", EventRecordId: uint64(i + 1)})
	}
	for i := 0; i < 600; i++ {
		ing.mu.Lock()
		n := len(ing.got)
		ing.mu.Unlock()
		if n >= 3 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(ing.got) < 3 {
		t.Fatalf("server saw %v", ing.got)
	}
	// A method outside the contract is refused by the tunnel, not by the handler.
	err = srv.Conn().Invoke(ctx, "/skenzeriq.agent.v1.EventIngest/SubmitEvents", &agentv1.SubmitEventsRequest{}, &agentv1.SubmitEventsResponse{})
	if status.Code(err) == codes.OK {
		t.Fatal("server called an agent->server method on the agent")
	}
	cancel()
	if !errors.Is(ctx.Err(), context.Canceled) && ctx.Err() == nil {
		t.Fatal("ctx")
	}
}
