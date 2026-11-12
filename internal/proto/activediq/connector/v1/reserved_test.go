package connectorv1_test

import (
	"context"
	"testing"

	"google.golang.org/protobuf/reflect/protoreflect"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// The names ReadSecret and VerifyUser are reserved in the Operation enum and have no RPC
// (connector.proto; fitness-proto rule P6). These checks fail the build, not just the test run,
// if one of them is implemented before its ticket specifies a shape. Apply was reserved in v1 and
// shaped in contract v1.1 (T-0091); its enum value keeps its number.

// Reserved and kept: the enum values must keep existing with their numbers. Removing or renumbering
// one is a breaking change to the contract.
var _ = [...]connectorv1.Operation{
	connectorv1.Operation_OPERATION_READ_SECRET,
	connectorv1.Operation_OPERATION_VERIFY_USER,
	connectorv1.Operation_OPERATION_APPLY,
	connectorv1.Operation_OPERATION_PLAN,
	connectorv1.Operation_OPERATION_VERIFY_CONNECTION,
}

func TestOperationNumbersAreStable(t *testing.T) {
	for op, want := range map[connectorv1.Operation]int32{
		connectorv1.Operation_OPERATION_PLAN:                    7,
		connectorv1.Operation_OPERATION_VERIFY_CONNECTION:       8,
		connectorv1.Operation_OPERATION_READ_REPLICATION_STATUS: 9,
		connectorv1.Operation_OPERATION_APPLY:                   100,
		connectorv1.Operation_OPERATION_READ_SECRET:             101,
		connectorv1.Operation_OPERATION_VERIFY_USER:             102,
	} {
		if int32(op) != want {
			t.Errorf("%s = %d, want %d", op, int32(op), want)
		}
	}
}

// Unimplemented: each marker declares one method at the same depth as ConnectorServer's. If the
// service ever gains ReadSecret or VerifyUser, the selector below becomes ambiguous and the package
// stops compiling. The same probe is built for the client interface.
type (
	readSecretMarker struct{}
	verifyUserMarker struct{}
)

func (readSecretMarker) ReadSecret() {}
func (verifyUserMarker) VerifyUser() {}

type serverProbe struct {
	connectorv1.ConnectorServer
	readSecretMarker
	verifyUserMarker
}

type clientProbe struct {
	connectorv1.ConnectorClient
	readSecretMarker
	verifyUserMarker
}

var (
	_ = serverProbe.ReadSecret
	_ = serverProbe.VerifyUser
	_ = clientProbe.ReadSecret
	_ = clientProbe.VerifyUser
)

// TestServiceRPCs pins the RPC list, so a new RPC is a visible change here as well as in
// connector.proto.
func TestServiceRPCs(t *testing.T) {
	var got []string
	for _, s := range connectorv1.Connector_ServiceDesc.Streams {
		got = append(got, s.StreamName)
	}
	for _, m := range connectorv1.Connector_ServiceDesc.Methods {
		got = append(got, m.MethodName)
	}
	want := map[string]bool{
		"Describe": true, "DescribeSchema": true, "ScopedSearch": true, "Read": true, "ReadPerDC": true, "ChangeFeed": true,
		"VerifyConnection": true, "Plan": true, "Apply": true, "ReadReplicationStatus": true,
	}
	if len(got) != len(want) {
		t.Fatalf("service has RPCs %v, want exactly %v", got, want)
	}
	for _, g := range got {
		if !want[g] {
			t.Errorf("unexpected RPC %s", g)
		}
	}
}

// readOnlyProvider stands for a provider with no write path: it embeds the generated
// UnimplementedConnectorServer, as every provider must (the generated interface requires it), and
// implements no write-group method.
type readOnlyProvider struct {
	connectorv1.UnimplementedConnectorServer
}

// TestNoWritePathMeansNoWrite: a provider that does not wire Plan, Apply or VerifyConnection
// cannot answer them with anything but UNIMPLEMENTED, which the transports map to
// ERROR_CODE_CAPABILITY_UNSUPPORTED (contract §7). Its Describe must report PLAN and APPLY
// UNSUPPORTED; conformance case CC-DESC-10 checks that against the running provider.
func TestNoWritePathMeansNoWrite(t *testing.T) {
	var p connectorv1.ConnectorServer = readOnlyProvider{}
	ctx := context.Background()
	if _, err := p.Plan(ctx, &connectorv1.PlanRequest{}); status.Code(err) != codes.Unimplemented {
		t.Errorf("Plan on a read-only provider: %v, want Unimplemented", err)
	}
	if _, err := p.Apply(ctx, &connectorv1.ApplyRequest{}); status.Code(err) != codes.Unimplemented {
		t.Errorf("Apply on a read-only provider: %v, want Unimplemented", err)
	}
	if err := p.VerifyConnection(&connectorv1.VerifyConnectionRequest{}, nil); status.Code(err) != codes.Unimplemented {
		t.Errorf("VerifyConnection on a read-only provider: %v, want Unimplemented", err)
	}
}

// TestWriteKindList pins the WriteKind list of contract v1.4 (connector-contract.md §8.10, T-1581):
// ten kinds, each with the WriteChange arm of the same number. Adding, removing or renumbering a
// kind needs a change to §8.10 (its digest key, reversibility class, touched-set rule and CC-WK
// cases) in the same commit; update this test with it.
func TestWriteKindList(t *testing.T) {
	want := map[connectorv1.WriteKind]string{
		connectorv1.WriteKind_WRITE_KIND_OBJECT_CREATE:       "object_create",
		connectorv1.WriteKind_WRITE_KIND_OBJECT_UPDATE:       "object_update",
		connectorv1.WriteKind_WRITE_KIND_OBJECT_DELETE:       "object_delete",
		connectorv1.WriteKind_WRITE_KIND_OBJECT_MOVE:         "object_move",
		connectorv1.WriteKind_WRITE_KIND_OBJECT_RENAME:       "object_rename",
		connectorv1.WriteKind_WRITE_KIND_OBJECT_RESTORE:      "object_restore",
		connectorv1.WriteKind_WRITE_KIND_USER_PASSWORD_RESET: "user_password_reset",
		connectorv1.WriteKind_WRITE_KIND_USER_UNLOCK:         "user_unlock",
		connectorv1.WriteKind_WRITE_KIND_ACCOUNT_ENABLE:      "account_enable",
		connectorv1.WriteKind_WRITE_KIND_ACCOUNT_DISABLE:     "account_disable",
	}
	if n := len(connectorv1.WriteKind_name); n != len(want)+1 {
		t.Fatalf("WriteKind has %d values, want %d plus UNSPECIFIED: update contract §8.10 and this test together", n, len(want))
	}
	oneof := (&connectorv1.WriteChange{}).ProtoReflect().Descriptor().Oneofs().ByName("change")
	if oneof == nil || oneof.Fields().Len() != len(want) {
		t.Fatalf("WriteChange.change must have exactly %d arms", len(want))
	}
	for k, arm := range want {
		f := oneof.Fields().ByName(protoreflectName(arm))
		if f == nil || int32(f.Number()) != int32(k) {
			t.Errorf("kind %s: WriteChange arm %q missing or its number differs from the kind's (%d)", k, arm, int32(k))
		}
	}
}

func protoreflectName(s string) protoreflect.Name { return protoreflect.Name(s) }
