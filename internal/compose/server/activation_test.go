package server

import (
	"bytes"
	"context"
	"io"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	"github.com/skenzeriq/activediq/internal/compose/config"
	"github.com/skenzeriq/activediq/internal/directory/client"
	"github.com/skenzeriq/activediq/internal/directory/connection"
	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/jobs"
	"github.com/skenzeriq/activediq/internal/platform/keys"
	"github.com/skenzeriq/activediq/internal/platform/secret"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

func TestVerifyOptionsRefusesWithoutSource(t *testing.T) {
	if _, err := verifyOptions(nil); err != ErrNoVerifySource {
		t.Fatalf("err = %v; want ErrNoVerifySource", err)
	}
}

func TestRegistryScope(t *testing.T) {
	const nc = "dddddddd-dddd-4ddd-8ddd-ddddddddddd0"
	ctx := context.Background()
	got, err := (registryScope{}).VerifyScope(ctx, connection.Connection{Kind: connection.KindADForest})
	if err != nil || len(got.ManagedDomains) != 0 || len(got.EnabledFamilies) != 2 {
		t.Fatalf("draft AD scope = %+v, %v", got, err)
	}
	for _, f := range got.EnabledFamilies {
		if f > connectorv1.RightsFamily_RIGHTS_FAMILY_AD_R2_CHANGE_TRACKING {
			t.Fatalf("a write family %v is enabled without a registry record", f)
		}
	}
	got, err = (registryScope{}).VerifyScope(ctx, connection.Connection{Kind: connection.KindADForest, DirectoryIdentity: nc})
	if err != nil || len(got.ManagedDomains) != 1 || got.ManagedDomains[0] != nc {
		t.Fatalf("identified AD scope = %+v, %v", got, err)
	}
	if _, err := (registryScope{}).VerifyScope(ctx, connection.Connection{Kind: "other"}); err == nil {
		t.Fatal("unknown kind was given a scope")
	}
}

func TestBootstrapTenantEmptyDatabase(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		ctx := context.Background()
		d := s.NewDatabase(t)
		d.Migrate(t)
		db, err := store.Open(ctx, store.Config{DSN: d.AppDSN()})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(db.Close)
		kek, err := keys.NewLocalProvider("test-kek", secret.FromBytes(bytes.Repeat([]byte{7}, 32)))
		if err != nil {
			t.Fatal(err)
		}
		ch := audit.NewChainer(db)
		boot := func() (tenant.ID, *jobs.Registry) {
			jr := jobs.NewRegistry()
			id, err := bootstrapTenant(ctx, config.Config{InstanceID: "node-1"}, db, ch, kek, jr)
			if err != nil {
				t.Fatalf("bootstrapTenant: %v", err)
			}
			return id, jr
		}
		first, _ := boot()
		second, _ := boot() // idempotent: same tenant, nothing duplicated
		if first != second {
			t.Fatalf("second start made another tenant: %s vs %s", first, second)
		}
		count := func(sql string) int {
			var n int
			if err := db.WithTenant(ctx, first, func(ctx context.Context, tx store.Tx) error {
				return tx.QueryRow(ctx, sql, first.String()).Scan(&n)
			}); err != nil {
				t.Fatal(err)
			}
			return n
		}
		for _, q := range []struct{ name, sql string }{
			{"tenant key", `SELECT count(*) FROM public.tenant_keys WHERE tenant_id = $1::uuid`},
			{"audit head", `SELECT count(*) FROM audit_head WHERE tenant_id = $1::uuid`},
			{"checkpoint key", `SELECT count(*) FROM audit_checkpoint_key WHERE tenant_id = $1::uuid`},
		} {
			if n := count(q.sql); n != 1 {
				t.Errorf("%s rows = %d; want 1", q.name, n)
			}
		}
	})
}

// passingConnector is a ConnectorClient whose VerifyConnection answers a clean AD run: every check
// passes, the identity is the forest root. It stands in for the connector end of the tunnel only;
// the client, the service, the registry's activation guards and the audit chain are the real ones.
type passingConnector struct {
	connectorv1.ConnectorClient
	req *connectorv1.VerifyConnectionRequest
}

type passStream struct {
	msgs []*connectorv1.VerifyConnectionResponse
}

func (s *passStream) Recv() (*connectorv1.VerifyConnectionResponse, error) {
	if len(s.msgs) == 0 {
		return nil, io.EOF
	}
	m := s.msgs[0]
	s.msgs = s.msgs[1:]
	return m, nil
}

func (s *passStream) Header() (metadata.MD, error) { return nil, nil }
func (s *passStream) Trailer() metadata.MD         { return nil }
func (s *passStream) CloseSend() error             { return nil }
func (s *passStream) Context() context.Context     { return context.Background() }
func (s *passStream) SendMsg(any) error            { return nil }
func (s *passStream) RecvMsg(any) error            { return nil }

func (c *passingConnector) VerifyConnection(_ context.Context, req *connectorv1.VerifyConnectionRequest, _ ...grpc.CallOption) (grpc.ServerStreamingClient[connectorv1.VerifyConnectionResponse], error) {
	c.req = req
	pass := connectorv1.CheckOutcome_CHECK_OUTCOME_PASS
	var cs []*connectorv1.CheckResult
	for _, k := range []connectorv1.VerificationCheck{
		connectorv1.VerificationCheck_VERIFICATION_CHECK_V1_LOCATE, connectorv1.VerificationCheck_VERIFICATION_CHECK_V2_CLOCK,
		connectorv1.VerificationCheck_VERIFICATION_CHECK_V3_TRANSPORT, connectorv1.VerificationCheck_VERIFICATION_CHECK_V4_AUTHENTICATE,
		connectorv1.VerificationCheck_VERIFICATION_CHECK_V5_IDENTITY, connectorv1.VerificationCheck_VERIFICATION_CHECK_V6_TOPOLOGY,
		connectorv1.VerificationCheck_VERIFICATION_CHECK_V7_OVER_PRIVILEGE, connectorv1.VerificationCheck_VERIFICATION_CHECK_V8_READ_SUFFICIENCY,
		connectorv1.VerificationCheck_VERIFICATION_CHECK_V9_EXCESS_IN_MANAGED_OUS,
	} {
		cs = append(cs, &connectorv1.CheckResult{Check: k, Outcome: pass})
	}
	root := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	return &passStream{msgs: []*connectorv1.VerifyConnectionResponse{
		{Event: &connectorv1.VerifyConnectionResponse_Header{Header: &connectorv1.VerificationHeader{VerificationId: req.GetVerificationId(), CheckListVersion: "1"}}},
		{Event: &connectorv1.VerifyConnectionResponse_Completed{Completed: &connectorv1.VerificationCompleted{
			Verdict: connectorv1.VerificationVerdict_VERIFICATION_VERDICT_PASS, Checks: cs,
			DirectoryIdentity: &connectorv1.DirectoryIdentity{Identity: &connectorv1.DirectoryIdentity_AdForest{
				AdForest: &connectorv1.AdForestIdentity{ForestRootNcGuid: &connectorv1.Guid{Value: root}}}}}}},
	}}, nil
}

type fixedConnectorSource struct{ c connectorv1.ConnectorClient }

func (f fixedConnectorSource) Connector(context.Context, string) (connectorv1.ConnectorClient, error) {
	return f.c, nil
}

// TestActivateReachesActive is the activation path of a booted server: the verify transport and
// scope source that Run wires, the tenant that bootstrapTenant creates, and Service.Activate over a
// connector that serves VerifyConnection. The verification is recorded and the connection is active
// with an audit event.
func TestActivateReachesActive(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		ctx := context.Background()
		d := s.NewDatabase(t)
		d.Migrate(t)
		db, err := store.Open(ctx, store.Config{DSN: d.AppDSN()})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(db.Close)
		kek, err := keys.NewLocalProvider("test-kek", secret.FromBytes(bytes.Repeat([]byte{7}, 32)))
		if err != nil {
			t.Fatal(err)
		}
		ch := audit.NewChainer(db)
		ten, err := bootstrapTenant(ctx, config.Config{InstanceID: "node-1"}, db, ch, kek, jobs.NewRegistry())
		if err != nil {
			t.Fatal(err)
		}
		cc := &passingConnector{}
		vopts, err := verifyOptions(fixedConnectorSource{cc})
		if err != nil {
			t.Fatal(err)
		}
		reg := connection.NewRegistry(db)
		svc, err := connection.NewService(reg, client.New(vopts...), ch)
		if err != nil {
			t.Fatal(err)
		}
		c, err := reg.Create(ctx, ten, connection.New{Kind: connection.KindADForest, DisplayName: "lab", CredentialID: "11111111-1111-4111-8111-111111111111", Transport: connection.TransportLDAPS})
		if err != nil {
			t.Fatal(err)
		}
		actor := authority.Chain{Requester: authority.Principal{ID: "u1", Kind: authority.Human}}
		out, err := svc.Activate(ctx, ten, c.ID, actor)
		if err != nil {
			t.Fatalf("Activate: %v", err)
		}
		if out.Connection.State != connection.StateActive || out.Verification.ID == "" || out.Verification.Verdict != connection.VerdictPass {
			t.Fatalf("outcome = state %s, verification %+v", out.Connection.State, out.Verification)
		}
		if cc.req == nil || len(cc.req.GetEnabledFamilies()) != 2 {
			t.Fatalf("the connector was not told the registry scope: %+v", cc.req)
		}
		var n int
		if err := db.WithTenant(ctx, ten, func(ctx context.Context, tx store.Tx) error {
			return tx.QueryRow(ctx, `SELECT count(*) FROM audit_event WHERE tenant_id = $1::uuid AND kind = 'connection.activated'`, ten.String()).Scan(&n)
		}); err != nil {
			t.Fatal(err)
		}
		if n != 1 {
			t.Fatalf("connection.activated audit events = %d; want 1", n)
		}
	})
}
