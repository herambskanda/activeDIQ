// Package service is the one assembly of the connector (blueprint §4.3, §7.1): New builds the verify,
// read and write handlers over one provider.Provider and returns the one composite
// activediq.connector.v1 ConnectorServer. The remote role (compose/connector) mounts it on the fleet
// tunnel registrar; the embedded role (compose/server) hands it to directory/client in process.
// Neither composition root assembles handlers itself, so the two roles cannot drift.
//
// The service holds no policy and imports no provider variant: the caller picks the variant
// (provider/ad, provider/entra) and passes it in.
package service

import (
	"context"
	"errors"
	"log/slog"

	"google.golang.org/grpc"

	"github.com/skenzeriq/activediq/internal/connector/provider"
	"github.com/skenzeriq/activediq/internal/connector/read"
	"github.com/skenzeriq/activediq/internal/connector/rights"
	"github.com/skenzeriq/activediq/internal/connector/write"
	"github.com/skenzeriq/activediq/internal/directory/dn"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// ErrDeps is returned for an incomplete Deps or a nil provider; it carries no directory text.
var ErrDeps = errors.New("service: a provider, a write gate and a rights epoch are required")

// Deps is what the handlers need besides the provider.
type Deps struct {
	// Gate is the write gate book. The verify handler feeds it and the write handler reads it, so
	// there is exactly one per service.
	Gate *write.GateBook
	// Epoch is the rights check's baseline state.
	Epoch *rights.EpochState
	// Self is the service account the session is bound as (excluded from its own rights findings).
	Self dn.ObjectRef
	// ConnectionID is the connection this connector is bound to by its configuration; empty only for
	// in-process lab connectors (see rights.VerifyConfig).
	ConnectionID string
	// Log receives one line per failed verification run; nil means slog.Default.
	Log *slog.Logger
	// WriteOptions configure the write handler (recorder, clock).
	WriteOptions []write.Option
}

// Service is the assembled connector: the three handlers and the composite server over them.
type Service struct {
	p      provider.Provider
	verify *rights.VerifyHandler
	read   *read.Handler
	write  *write.Handler
	srv    *server
}

// New builds the handlers over p. Each handler asserts the facets it needs on p at construction; a
// group whose facet p lacks answers CAPABILITY_UNSUPPORTED.
func New(p provider.Provider, d Deps) (*Service, error) {
	if p == nil || d.Gate == nil || d.Epoch == nil {
		return nil, ErrDeps
	}
	vh, err := rights.NewVerifyHandler(p, rights.VerifyConfig{Epoch: d.Epoch, Identity: d.Self, Gate: d.Gate,
		OnLocalRecordFailed: d.Gate.CloseLocalRecordFailed, ConnectionID: d.ConnectionID, Log: d.Log})
	if err != nil {
		return nil, errors.New("service: verify handler")
	}
	var svc *Service
	rh, err := read.New(p, read.WithLog(d.Log), read.WithOperations(func() []*connectorv1.OperationSupport { return svc.Capabilities() }))
	if err != nil {
		return nil, errors.New("service: read handler")
	}
	wh, err := write.New(p, d.Gate, d.WriteOptions...)
	if err != nil {
		return nil, errors.New("service: write handler")
	}
	svc = &Service{p: p, verify: vh, read: rh, write: wh,
		srv: &server{verify: rights.NewServer(vh), read: read.NewServer(rh), write: write.NewServer(wh)}}
	return svc, nil
}

// Server is the one composite ConnectorServer. Each group's Register would register the whole
// Connector service, so a registrar gets this one server and never two.
func (s *Service) Server() connectorv1.ConnectorServer { return s.srv }

// Write is the in-process handle of the write group (Plan and Apply satisfy directory/client.Transport).
func (s *Service) Write() *write.Handler { return s.write }

// Read is the in-process handle of the read group.
func (s *Service) Read() *read.Handler { return s.read }

// Verify is the in-process handle of the VerifyConnection group.
func (s *Service) Verify() *rights.VerifyHandler { return s.verify }

// Capabilities is the Describe rows of the connector: the provider's, derived from its facets, and the
// write group's, derived from the operation table.
func (s *Service) Capabilities() []*connectorv1.OperationSupport {
	return append(provider.Supports(s.p), write.Capabilities()...)
}

// server routes each served RPC to its group's server (embedding the group servers would be
// ambiguous). Everything else is Unimplemented.
type server struct {
	connectorv1.UnimplementedConnectorServer
	verify *rights.Server
	read   *read.Server
	write  *write.Server
}

func (s *server) VerifyConnection(req *connectorv1.VerifyConnectionRequest, st grpc.ServerStreamingServer[connectorv1.VerifyConnectionResponse]) error {
	return s.verify.VerifyConnection(req, st)
}

func (s *server) Read(req *connectorv1.ReadRequest, st grpc.ServerStreamingServer[connectorv1.ReadResponse]) error {
	return s.read.Read(req, st)
}

func (s *server) ScopedSearch(req *connectorv1.ScopedSearchRequest, st grpc.ServerStreamingServer[connectorv1.ScopedSearchResponse]) error {
	return s.read.ScopedSearch(req, st)
}

func (s *server) ChangeFeed(req *connectorv1.ChangeFeedRequest, st grpc.ServerStreamingServer[connectorv1.ChangeFeedResponse]) error {
	return s.read.ChangeFeed(req, st)
}

func (s *server) Describe(ctx context.Context, req *connectorv1.DescribeRequest) (*connectorv1.DescribeResponse, error) {
	return s.read.Describe(ctx, req)
}

func (s *server) Plan(ctx context.Context, req *connectorv1.PlanRequest) (*connectorv1.PlanResponse, error) {
	return s.write.Plan(ctx, req)
}

func (s *server) Apply(ctx context.Context, req *connectorv1.ApplyRequest) (*connectorv1.ApplyResponse, error) {
	return s.write.Apply(ctx, req)
}
