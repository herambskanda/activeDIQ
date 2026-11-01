package tunnelbind

import (
	"testing"

	"github.com/skenzeriq/activediq/internal/platform/fleet"
	fleetv1 "github.com/skenzeriq/activediq/internal/proto/activediq/fleet/v1"
)

// Every frame body survives the proto round trip; this is the wire the tunnel speaks.
func TestFrameRoundTrip(t *testing.T) {
	for _, f := range []fleet.Frame{
		{CallID: 1, Body: fleet.BodyOpen, Method: "/m", TimeoutMS: 5},
		{CallID: 2, Body: fleet.BodyData, Payload: []byte{1, 2, 3}},
		{CallID: 3, Body: fleet.BodyHalfClose},
		{CallID: 4, Body: fleet.BodyClose, Code: 3, Message: "invalid request"},
		{CallID: 5, Body: fleet.BodyCancel},
		{CallID: 6, Body: fleet.BodyCredit, Messages: 7},
	} {
		p, ok := frameToProto(f)
		if !ok {
			t.Fatalf("body %v not encodable", f.Body)
		}
		got := frameFromProto(p)
		if got.CallID != f.CallID || got.Body != f.Body || got.Method != f.Method || got.TimeoutMS != f.TimeoutMS ||
			string(got.Payload) != string(f.Payload) || got.Code != f.Code || got.Message != f.Message ||
			got.Messages != f.Messages {
			t.Errorf("round trip: got %+v want %+v", got, f)
		}
	}
}

// A frame with no body is never put on the wire, and a wire frame with no body decodes to BodyNone.
func TestEmptyFrames(t *testing.T) {
	if _, ok := frameToProto(fleet.Frame{CallID: 1}); ok {
		t.Fatal("bodiless frame encoded")
	}
	if got := frameFromProto(&fleetv1.TunnelFrame{CallId: 3}); got.Body != fleet.BodyNone {
		t.Fatalf("got %+v", got)
	}
}
