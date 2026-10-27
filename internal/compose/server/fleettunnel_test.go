package server

import (
	"testing"

	"github.com/skenzeriq/activediq/internal/platform/fleet"
	fleetv1 "github.com/skenzeriq/activediq/internal/proto/activediq/fleet/v1"
)

func TestFrameTranslationRoundTrips(t *testing.T) {
	for _, f := range []fleet.Frame{
		{CallID: 1, Body: fleet.BodyOpen, Method: "/a.B/C", TimeoutMS: 7},
		{CallID: 2, Body: fleet.BodyData, Payload: []byte("x")},
		{CallID: 3, Body: fleet.BodyHalfClose},
		{CallID: 4, Body: fleet.BodyClose, Code: 5, Message: "m"},
		{CallID: 5, Body: fleet.BodyCancel},
		{CallID: 0, Body: fleet.BodyCredit, Messages: 9},
	} {
		pf, ok := frameToProto(f)
		if !ok {
			t.Fatalf("%+v not translated", f)
		}
		back := frameFromProto(pf)
		if back.CallID != f.CallID || back.Body != f.Body || back.Method != f.Method || back.TimeoutMS != f.TimeoutMS ||
			string(back.Payload) != string(f.Payload) || back.Code != f.Code || back.Message != f.Message || back.Messages != f.Messages {
			t.Fatalf("%+v became %+v", f, back)
		}
	}
	if _, ok := frameToProto(fleet.Frame{CallID: 1}); ok {
		t.Fatal("a frame with no body must not be sent")
	}
	// An empty oneof from the peer is BodyNone, which the mux treats as a protocol error.
	if got := frameFromProto(&fleetv1.TunnelFrame{CallId: 3}); got.Body != fleet.BodyNone {
		t.Fatalf("got %+v", got)
	}
}

func TestOnlyTheConnectorKindHasAContract(t *testing.T) {
	b, err := FleetBindings()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := b[fleet.KindConnector]; !ok || len(b) != 1 {
		t.Fatalf("bindings: %v", b)
	}
	if _, err := b.For(fleet.Identity{Kind: fleet.KindADDC}); err == nil {
		t.Fatal("addc must have no tunnel yet")
	}
}
