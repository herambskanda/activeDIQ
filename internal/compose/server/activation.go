package server

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/skenzeriq/activediq/internal/compose/config"
	"github.com/skenzeriq/activediq/internal/directory/client"
	"github.com/skenzeriq/activediq/internal/directory/connection"
	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/jobs"
	"github.com/skenzeriq/activediq/internal/platform/keys"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
	"github.com/skenzeriq/activediq/internal/platform/tenant/provision"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// firstRunTenantName names the single tenant of a self-hosted install when FirstRun creates it.
const firstRunTenantName = "activeDIQ"

// ErrNoVerifySource is returned at boot when the verify path would be half wired: a connection could
// then never leave draft, or worse be verified against nothing.
var ErrNoVerifySource = errors.New("server: no connector source for the VerifyConnection transport: refusing to start")

// registryScope is the client.VerifyScopeSource over the server's own registry (contract §8.4: "the
// server's registry is the only source"). The registry records no enabled write families yet, so a
// run is told only the two read families; a write right the identity holds is then reported
// excessive, never silently allowed. The managed domain is the connection's directory identity
// (V5, the forest root NC head), known once a run has recorded it; before that a run is told no
// domain and V8 has nothing to compare (follow-up: the connector defaults to its bound root).
type registryScope struct{}

func (registryScope) VerifyScope(_ context.Context, c connection.Connection) (client.VerifyScope, error) {
	sc := client.VerifyScope{}
	switch c.Kind {
	case connection.KindADForest:
		sc.EnabledFamilies = []connectorv1.RightsFamily{
			connectorv1.RightsFamily_RIGHTS_FAMILY_AD_R1_INVENTORY,
			connectorv1.RightsFamily_RIGHTS_FAMILY_AD_R2_CHANGE_TRACKING,
		}
		if c.DirectoryIdentity != "" {
			sc.ManagedDomains = []string{string(c.DirectoryIdentity)}
		}
	case connection.KindEntraTenant:
		sc.EnabledFamilies = []connectorv1.RightsFamily{
			connectorv1.RightsFamily_RIGHTS_FAMILY_ENTRA_TENANT_READ,
			connectorv1.RightsFamily_RIGHTS_FAMILY_ENTRA_SKU_READ,
		}
	default:
		return client.VerifyScope{}, fmt.Errorf("server: verify scope: unknown connection kind")
	}
	return sc, nil
}

// verifyOptions wires the VerifyConnection half of the directory client: the gRPC transport over the
// connector source (the same one reads use) and the registry scope. Without a source it refuses.
func verifyOptions(src client.ConnectorSource) ([]client.Option, error) {
	if src == nil {
		return nil, ErrNoVerifySource
	}
	vt, err := client.NewGRPCVerifyTransport(src)
	if err != nil {
		return nil, fmt.Errorf("server: verify transport: %w", err)
	}
	return []client.Option{client.WithVerifyTransport(vt), client.WithVerifyScope(registryScope{})}, nil
}

// bootstrapTenant makes sure the install has its tenant, that tenant's first data key and its audit
// genesis head and checkpoint key (ADR-0005 rule 11), and registers the audit jobs with the
// checkpoint cadence started by the initialiser. It runs on every start; every step is idempotent.
// Nothing here is fabricated: keys come from the unlocked KEK provider, and a failure stops boot.
func bootstrapTenant(ctx context.Context, cfg config.Config, db *store.DB, ch *audit.Chainer, kekp keys.Provider, jreg *jobs.Registry) (tenant.ID, error) {
	ks := keys.NewStore(kekp)
	cp := audit.NewCheckpointer(ch, ks.KeySource())
	holder := cfg.InstanceID
	if holder == "" {
		holder = "server"
	}
	aj, err := audit.RegisterJobs(audit.JobsConfig{DB: db, Checkpointer: cp, Registry: jreg, Holder: holder})
	if err != nil {
		return tenant.ID{}, fmt.Errorf("server: audit jobs: %w", err)
	}
	cp.StartCadenceOnInit(aj.ScheduleCheckpoint)
	ictx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	// The tenant data key first: the checkpoint key is sealed under it.
	res, err := provision.FirstRun(ictx, db, firstRunTenantName, ks.Provision, cp.InitTenant)
	if err != nil {
		return tenant.ID{}, fmt.Errorf("server: first-run tenant: %w", err)
	}
	return res.Tenant, nil
}
