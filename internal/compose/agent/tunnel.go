package agent

import (
	"context"
	"log/slog"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/skenzeriq/activediq/internal/compose/tunnelbind"
	kernel "github.com/skenzeriq/activediq/internal/platform/agent"
	"github.com/skenzeriq/activediq/internal/platform/fleet"
	"github.com/skenzeriq/activediq/internal/platform/fleet/dial"
	"github.com/skenzeriq/activediq/internal/platform/fleet/tunnelclient"
	addcv1 "github.com/skenzeriq/activediq/internal/proto/activediq/addc/v1"
	agentv1 "github.com/skenzeriq/activediq/internal/proto/skenzeriq/agent/v1"
)

// addcContract is the one contract the DC agent speaks (agent-host-addc-contract §2): the server may
// call Host and Addc; the agent may call EventIngest. Nothing else is registered or callable.
func addcContract() (fleet.Contract, error) {
	host := agentv1.File_skenzeriq_agent_v1_agent_proto.Services().ByName("Host")
	ing := agentv1.File_skenzeriq_agent_v1_agent_proto.Services().ByName("EventIngest")
	addc := addcv1.File_activediq_addc_v1_addc_proto.Services().ByName("Addc")
	if host == nil || ing == nil || addc == nil {
		return fleet.Contract{}, fleet.ErrContract
	}
	return fleet.NewContract("addc", []protoreflect.ServiceDescriptor{host, addc}, []protoreflect.ServiceDescriptor{ing})
}

// tunnelLoop serves the contract over the shared tunnel client until ctx is done.
func tunnelLoop(ctx context.Context, st *dial.State, h *kernel.Host, id fleet.Identity, c fleet.Contract, log *slog.Logger) {
	tunnelclient.Run(ctx, tunnelclient.Config{State: st, Identity: id, Log: log, Open: tunnelbind.Open,
		Binding: fleet.Binding{Contract: c, Register: func(_ fleet.Identity, reg grpc.ServiceRegistrar) { h.Register(reg) }},
		OnConnect: func(conn grpc.ClientConnInterface) func() {
			h.SetEventClient(agentv1.NewEventIngestClient(conn))
			return func() { h.SetEventClient(nil) }
		}})
}
