package fleetsql_test

import (
	"context"
	"errors"
	"testing"

	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/fleet"
	"github.com/skenzeriq/activediq/internal/platform/fleet/fleetsql"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
)

func TestTunnelReporterAuditsViolationAgainstTheComponent(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setupEnroll(t, s)
		id := e.enrolled(t, e.a, fleetsql.KindConnector)
		rep := &fleetsql.TunnelReporter{DB: e.db, Audit: e.sink}
		before := len(e.sink.evs)
		if err := rep.ProtocolError(context.Background(), id, fleet.ViolationUnknownCall); err != nil {
			t.Fatal(err)
		}
		if err := rep.ProtocolError(context.Background(), id, fleet.ViolationUnknownCall); err != nil {
			t.Fatal(err)
		}
		if len(e.sink.evs) != before+2 || e.sink.evs[before].ID == e.sink.evs[before+1].ID {
			t.Fatalf("each occurrence is its own event: %d", len(e.sink.evs)-before)
		}
		ev := e.sink.evs[before]
		if ev.Kind != fleetsql.KindTunnelProtocolError || ev.Target.GUID != id.ComponentID || ev.Outcome != audit.Denied ||
			ev.Reason != string(fleet.ViolationUnknownCall) {
			t.Fatalf("event: %+v", ev)
		}
		for i := 1; i < len(ev.Details); i++ {
			if ev.Details[i-1].Key >= ev.Details[i].Key {
				t.Fatal("details out of key order")
			}
		}
		if err := (&fleetsql.TunnelReporter{}).ProtocolError(context.Background(), id, fleet.ViolationEmptyBody); !errors.Is(err, fleetsql.ErrReporterNotConfigured) {
			t.Fatalf("unconfigured: %v", err)
		}
	})
}
