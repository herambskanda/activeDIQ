package connectorv1_test

import (
	"testing"

	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// The names Apply, ReadSecret and VerifyUser are reserved in the Operation enum and have no RPC
// (connector.proto; fitness-proto rule P6). These checks fail the build, not just the test run,
// if one of them is implemented before its ticket specifies a shape.

// Reserved: the enum values must keep existing. Removing one is a breaking change to the contract.
var _ = [...]connectorv1.Operation{
	connectorv1.Operation_OPERATION_APPLY,
	connectorv1.Operation_OPERATION_READ_SECRET,
	connectorv1.Operation_OPERATION_VERIFY_USER,
}

// Unimplemented: each marker declares one method at the same depth as ConnectorServer's. If the
// service ever gains Apply, ReadSecret or VerifyUser, the selector below becomes ambiguous and
// the package stops compiling. The same probe is built for the client interface.
type (
	applyMarker      struct{}
	readSecretMarker struct{}
	verifyUserMarker struct{}
)

func (applyMarker) Apply()           {}
func (readSecretMarker) ReadSecret() {}
func (verifyUserMarker) VerifyUser() {}

type serverProbe struct {
	connectorv1.ConnectorServer
	applyMarker
	readSecretMarker
	verifyUserMarker
}

type clientProbe struct {
	connectorv1.ConnectorClient
	applyMarker
	readSecretMarker
	verifyUserMarker
}

var (
	_ = serverProbe.Apply
	_ = serverProbe.ReadSecret
	_ = serverProbe.VerifyUser
	_ = clientProbe.Apply
	_ = clientProbe.ReadSecret
	_ = clientProbe.VerifyUser
)

// TestServiceHasOnlyTheReadSide pins the RPC list, so a new RPC is a visible change here as well
// as in connector.proto.
func TestServiceHasOnlyTheReadSide(t *testing.T) {
	methods := connectorv1.Connector_ServiceDesc.Methods
	var got []string
	for _, s := range connectorv1.Connector_ServiceDesc.Streams {
		got = append(got, s.StreamName)
	}
	for _, m := range methods {
		got = append(got, m.MethodName)
	}
	want := map[string]bool{"Describe": true, "DescribeSchema": true, "ScopedSearch": true, "Read": true, "ReadPerDC": true, "ChangeFeed": true}
	if len(got) != len(want) {
		t.Fatalf("service has RPCs %v, want exactly %v", got, want)
	}
	for _, g := range got {
		if !want[g] {
			t.Errorf("unexpected RPC %s", g)
		}
	}
}
