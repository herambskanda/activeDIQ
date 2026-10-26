package server

import (
	"testing"

	"github.com/skenzeriq/activediq/internal/directory/connection"
	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/jobs"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
)

// T-0245: the server composes connection.Service and registers the scheduled rights check in the job
// registry its worker runs; wiring the same registry twice is refused rather than shadowed.
func TestBuildConnectionsRegistersTheScheduledCheck(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		jreg, ch := jobs.NewRegistry(), audit.NewChainer(e.db) // the chainer installs its hook once per store
		k, err := buildConnections(e.db, ch, directoryFacts(nil), jreg)
		if err != nil || k.Service == nil || k.Jobs == nil {
			t.Fatalf("buildConnections: %+v %v", k, err)
		}
		if _, ok := jreg.Lookup(connection.JobScheduledCheck); !ok {
			t.Fatal("connection.scheduled_check is not registered")
		}
		if _, err := buildConnections(e.db, ch, directoryFacts(nil), jreg); err == nil {
			t.Fatal("a second registration must be refused")
		}
	})
}
