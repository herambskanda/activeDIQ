package fleetv1

import (
	"testing"

	"google.golang.org/protobuf/reflect/protoreflect"
)

// TestServiceShape pins the generated descriptor: Enroll (unary) and Tunnel (bidirectional) and
// nothing else (TM-TB6-T8). fitness-proto F1 enforces the same on the .proto source.
func TestServiceShape(t *testing.T) {
	svc := File_activediq_fleet_v1_fleet_proto.Services()
	if svc.Len() != 1 {
		t.Fatalf("want one service, got %d", svc.Len())
	}
	ms := svc.Get(0).Methods()
	if ms.Len() != 2 {
		t.Fatalf("want exactly Enroll and Tunnel, got %d methods", ms.Len())
	}
	if m := ms.ByName("Enroll"); m == nil || m.IsStreamingClient() || m.IsStreamingServer() {
		t.Fatal("Enroll must be unary")
	}
	if m := ms.ByName("Tunnel"); m == nil || !m.IsStreamingClient() || !m.IsStreamingServer() {
		t.Fatal("Tunnel must be bidirectional")
	}
}

// TestEnrollResponseCarriesCABundleAndNoPrivateKey is acceptance criterion 3.
func TestEnrollResponseCarriesCABundleAndNoPrivateKey(t *testing.T) {
	fs := (&EnrollResponse{}).ProtoReflect().Descriptor().Fields()
	if fd := fs.ByName("ca_bundle_pem"); fd == nil || fd.Kind() != protoreflect.BytesKind {
		t.Fatal("EnrollResponse must carry ca_bundle_pem bytes")
	}
	for i := 0; i < fs.Len(); i++ {
		if n := string(fs.Get(i).Name()); n == "private_key" || n == "private_key_der" {
			t.Fatalf("EnrollResponse has a private key field %q", n)
		}
	}
}
