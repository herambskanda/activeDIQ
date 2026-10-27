package server

import (
	"context"
	"crypto/x509"
	"errors"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/skenzeriq/activediq/internal/platform/fleet/fleetsql"
	fleetv1 "github.com/skenzeriq/activediq/internal/proto/activediq/fleet/v1"
)

// The Enroll RPC adapter (T-0155). The platform root never imports the generated protos (blueprint
// §2 rule 1), so compose carries the translation between fleetv1 and fleetsql.Enroller. The listener
// that mounts it, and the per-RPC client-certificate rule for Tunnel, are the gateway's (T-0156).

const (
	maxTokenBytes   = 256 // a real token is about 90
	maxVersionBytes = 128 // component_version is informational and never stored
)

// enrollBackend is what the adapter needs from fleetsql.Enroller.
type enrollBackend interface {
	Enroll(ctx context.Context, source, token string, csrDER []byte) (fleetsql.Enrolled, error)
	Rotate(ctx context.Context, leaf *x509.Certificate, csrDER []byte) (fleetsql.Enrolled, error)
}

// fleetEnrollService serves Fleet.Enroll. It embeds the unimplemented server, and Tunnel when
// tunnel dependencies are given; otherwise Tunnel answers UNIMPLEMENTED.
type fleetEnrollService struct {
	fleetv1.UnimplementedFleetServer
	backend enrollBackend
	tunnel  *TunnelDeps // nil: Tunnel answers UNIMPLEMENTED
}

// Tunnel serves Fleet.Tunnel through the multiplexer (T-0287).
func (s *fleetEnrollService) Tunnel(st grpc.BidiStreamingServer[fleetv1.TunnelFrame, fleetv1.TunnelFrame]) error {
	if s.tunnel == nil {
		return s.UnimplementedFleetServer.Tunnel(st)
	}
	return ServeTunnel(*s.tunnel, st)
}

// The fixed answers. Nothing here repeats the request, the token or an internal error.
var (
	errRefused  = status.Error(codes.Unauthenticated, "enrollment refused")
	errBadCSR   = status.Error(codes.InvalidArgument, "certificate request not acceptable")
	errTooMany  = status.Error(codes.ResourceExhausted, "too many attempts")
	errInternal = status.Error(codes.Internal, "enrollment unavailable")
)

// Enroll redeems the token, or, when no token is given and the caller presented a client certificate
// that the TLS layer verified, renews that certificate. The tenant and component are never read from
// the request. The source address is the transport peer; no header or message field can change it.
func (s *fleetEnrollService) Enroll(ctx context.Context, req *fleetv1.EnrollRequest) (*fleetv1.EnrollResponse, error) {
	if len(req.GetEnrollmentToken()) > maxTokenBytes || len(req.GetComponentVersion()) > maxVersionBytes {
		return nil, errRefused
	}
	p, ok := peer.FromContext(ctx)
	if !ok || p.Addr == nil {
		return nil, errInternal
	}
	var (
		out fleetsql.Enrolled
		err error
	)
	if req.GetEnrollmentToken() == "" {
		leaf := verifiedLeaf(p)
		if leaf == nil {
			return nil, errRefused
		}
		out, err = s.backend.Rotate(ctx, leaf, req.GetCsrDer())
	} else {
		out, err = s.backend.Enroll(ctx, p.Addr.String(), req.GetEnrollmentToken(), req.GetCsrDer())
	}
	if err != nil {
		return nil, mapEnrollErr(err)
	}
	resp := &fleetv1.EnrollResponse{LeafCertificateDer: out.LeafDER, CaBundlePem: out.CABundlePEM, LeafNotAfter: timestamppb.New(out.NotAfter)}
	for _, e := range out.Endpoints {
		resp.Endpoints = append(resp.Endpoints, &fleetv1.Endpoint{Host: e.Host, Port: uint32(e.Port)})
	}
	return resp, nil
}

// verifiedLeaf returns the leaf of a chain the TLS handshake verified, or nil. An unverified
// certificate (PeerCertificates alone) is never used.
func verifiedLeaf(p *peer.Peer) *x509.Certificate {
	ti, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok || len(ti.State.VerifiedChains) == 0 || len(ti.State.VerifiedChains[0]) == 0 {
		return nil
	}
	return ti.State.VerifiedChains[0][0]
}

func mapEnrollErr(err error) error {
	var rl *fleetsql.RateLimitedError
	switch {
	case errors.Is(err, fleetsql.ErrTokenInvalid), errors.Is(err, fleetsql.ErrRotateRefused):
		return errRefused
	case errors.Is(err, fleetsql.ErrCSR):
		return errBadCSR
	case errors.As(err, &rl):
		return errTooMany
	}
	return errInternal
}
