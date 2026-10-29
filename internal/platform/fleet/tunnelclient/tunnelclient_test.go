package tunnelclient

import (
	"testing"

	"github.com/skenzeriq/activediq/internal/platform/fleet"
	"github.com/skenzeriq/activediq/internal/platform/fleet/dial"
)

// Every frame body survives the proto round trip; this is the wire the tunnel speaks.
func TestFrameRoundTrip(t *testing.T) {
	for _, f := range []fleet.Frame{
		{CallID: 1, Body: fleet.BodyOpen, Method: "/m", TimeoutMS: 5},
		{CallID: 2, Body: fleet.BodyData, Payload: []byte{1, 2, 3}},
		{CallID: 3, Body: fleet.BodyHalfClose},
		{CallID: 4, Body: fleet.BodyClose, Code: 3, Message: "invalid request"},
		{CallID: 5, Body: fleet.BodyCancel},
	} {
		p, ok := frameToProto(f)
		if !ok {
			t.Fatalf("body %v not encodable", f.Body)
		}
		got := frameFromProto(p)
		if got.CallID != f.CallID || got.Body != f.Body || got.Method != f.Method || got.TimeoutMS != f.TimeoutMS ||
			string(got.Payload) != string(f.Payload) || got.Code != f.Code || got.Message != f.Message {
			t.Errorf("round trip: got %+v want %+v", got, f)
		}
	}
}

func TestEndpointAddr(t *testing.T) {
	if got := endpointAddr(dial.Endpoint{Host: "fleet.example", Port: 8443}); got != "fleet.example:8443" {
		t.Fatal(got)
	}
	if got := endpointAddr(dial.Endpoint{Host: "::1", Port: 1}); got != "[::1]:1" {
		t.Fatal(got)
	}
}
