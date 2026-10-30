package client

import (
	"context"
	"errors"
	"net"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	"github.com/skenzeriq/activediq/internal/directory/connection"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

func withIdentity(m *connectorv1.VerifyConnectionResponse, d *connectorv1.DirectoryIdentity) *connectorv1.VerifyConnectionResponse {
	m.GetCompleted().DirectoryIdentity = d
	return m
}

func passRun(d *connectorv1.DirectoryIdentity, v connectorv1.VerificationVerdict) *fakeStream {
	return &fakeStream{msgs: []*connectorv1.VerifyConnectionResponse{header(),
		withIdentity(completed(v, 0, 0, chk(connectorv1.VerificationCheck_VERIFICATION_CHECK_V5_IDENTITY, connectorv1.CheckOutcome_CHECK_OUTCOME_PASS)), d)}}
}

func TestVerifyConnectionRejectsMissingOrWrongIdentityFailClosed(t *testing.T) {
	pass := connectorv1.VerificationVerdict_VERIFICATION_VERDICT_PASS
	entra := &connectorv1.DirectoryIdentity{Identity: &connectorv1.DirectoryIdentity_EntraTenantId{EntraTenantId: "11111111-2222-4333-8444-555555555555"}}
	badGUID := &connectorv1.DirectoryIdentity{Identity: &connectorv1.DirectoryIdentity_AdForest{AdForest: &connectorv1.AdForestIdentity{ForestRootNcGuid: &connectorv1.Guid{Value: []byte{1, 2}}}}}
	unsetKind := &connectorv1.DirectoryIdentity{}
	for _, tc := range []struct {
		name string
		id   *connectorv1.DirectoryIdentity
		want error
	}{
		{"nil", nil, ErrIdentityMissing},
		{"empty oneof", unsetKind, ErrIdentityMissing},
		{"entra tenant on an AD forest", entra, ErrIdentityMismatch},
		{"malformed forest guid", badGUID, ErrIdentityMismatch},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cl, _ := newVerifyClient(passRun(tc.id, pass), fixedScope{})
			res, err := cl.VerifyConnection(context.Background(), vreq())
			if !errors.Is(err, tc.want) || res.Verdict != "" || res.DirectoryIdentity != "" {
				t.Fatalf("err=%v res=%+v", err, res)
			}
		})
	}
}

func TestVerifyConnectionEntraIdentityOnEntraConnection(t *testing.T) {
	const tenantID = "11111111-2222-4333-8444-555555555555"
	st := passRun(&connectorv1.DirectoryIdentity{Identity: &connectorv1.DirectoryIdentity_EntraTenantId{EntraTenantId: tenantID}}, connectorv1.VerificationVerdict_VERIFICATION_VERDICT_PASS)
	cl, _ := newVerifyClient(st, fixedScope{})
	r := vreq()
	r.Connection.Kind = connection.KindEntraTenant
	res, err := cl.VerifyConnection(context.Background(), r)
	if err != nil || string(res.DirectoryIdentity) != tenantID {
		t.Fatalf("err=%v id=%q", err, res.DirectoryIdentity)
	}
	// and the AD identity is refused on it
	cl, _ = newVerifyClient(passRun(adIdentity(), connectorv1.VerificationVerdict_VERIFICATION_VERDICT_PASS), fixedScope{})
	if _, err := cl.VerifyConnection(context.Background(), r); !errors.Is(err, ErrIdentityMismatch) {
		t.Fatalf("err=%v", err)
	}
}

func TestVerifyConnectionFailedRunNeedsNoIdentity(t *testing.T) {
	for _, v := range []connectorv1.VerificationVerdict{connectorv1.VerificationVerdict_VERIFICATION_VERDICT_FAILED, connectorv1.VerificationVerdict_VERIFICATION_VERDICT_COULD_NOT_VERIFY} {
		cl, _ := newVerifyClient(passRun(nil, v), fixedScope{})
		res, err := cl.VerifyConnection(context.Background(), vreq())
		if err != nil || res.DirectoryIdentity != "" {
			t.Fatalf("%v: err=%v id=%q", v, err, res.DirectoryIdentity)
		}
	}
}

type verifyServer struct {
	connectorv1.UnimplementedConnectorServer
	msgs []*connectorv1.VerifyConnectionResponse
}

func (f verifyServer) VerifyConnection(_ *connectorv1.VerifyConnectionRequest, s grpc.ServerStreamingServer[connectorv1.VerifyConnectionResponse]) error {
	for _, m := range f.msgs {
		if err := s.Send(m); err != nil {
			return err
		}
	}
	return nil
}

// The identity the connector streams reaches the caller unchanged over a real gRPC stream.
func TestGRPCVerifyTransportRoundTripsDirectoryIdentity(t *testing.T) {
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	connectorv1.RegisterConnectorServer(srv, verifyServer{msgs: passRun(adIdentity(), connectorv1.VerificationVerdict_VERIFICATION_VERDICT_PASS).msgs})
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	cc, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cc.Close() })
	tr, err := NewGRPCVerifyTransport(connSrc{connectorv1.NewConnectorClient(cc)})
	if err != nil {
		t.Fatal(err)
	}
	cl := New(WithVerifyTransport(tr), WithVerifyScope(fixedScope{}))
	res, err := cl.VerifyConnection(context.Background(), vreq())
	if err != nil || res.DirectoryIdentity != vIdentity || res.Verdict != connection.VerdictPass {
		t.Fatalf("err=%v res=%+v", err, res)
	}
	if _, err := NewGRPCVerifyTransport(nil); err == nil {
		t.Fatal("a transport with no connector source must not build")
	}
}
