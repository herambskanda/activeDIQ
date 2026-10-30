package connections_test

// The HTTP flow over the composed Entra adapters moved to internal/compose/server/entra
// (attest_http_test.go): a module test must not import internal/compose (ADR-0002 rule 1; T-0943).
// What stays here needs no adapter.

import (
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/modules/connections"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

func TestWindowGate(t *testing.T) {
	now := time.Date(2026, 10, 27, 9, 0, 0, 0, time.UTC)
	g := &connections.WindowGate{PerSource: 1, PerTenant: 1, MaxKeys: 1, Now: func() time.Time { return now }}
	if !g.AllowSource("2001:db8::1") || g.AllowSource("2001:db8::ffff") {
		t.Fatal("IPv6 sources in one /64 share a bucket")
	}
	if g.AllowSource("198.51.100.1") && g.AllowSource("198.51.100.2") {
		t.Fatal("overflow keys must share one bucket")
	}
	now = now.Add(2 * time.Minute)
	if !g.AllowSource("2001:db8::1") {
		t.Fatal("a new window starts empty")
	}
}

func TestStateTenant(t *testing.T) {
	id, err := tenant.Parse(entraTenantID)
	if err != nil {
		t.Fatal(err)
	}
	for state, want := range map[string]bool{entraTenantID + ".abc": true, entraTenantID: false, ".abc": false,
		"zz.abc": false, "00000000-0000-0000-0000-000000000000.abc": false, "": false} {
		got, ok := connections.StateTenant(state)
		if ok != want || (ok && got != id) {
			t.Fatalf("%q: %v %v", state, got, ok)
		}
	}
}
