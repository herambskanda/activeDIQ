package server

// T-1096 AC2: universal search in the composed server takes its scope from the one producer, rbac.ReadScopes.For
// through the txReadScopes adapter T-0987 composed — the same value buildDirectory hands the handlers' Scopes.
// Proved against the real producer, store and inventory: an account with the naming_context assignment finds an
// object of the connection, an account without one finds nothing, a dead owner is refused, and a missing
// producer fails the build of the service instead of searching unscoped.

import (
	"context"
	"encoding/base32"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/directory"
	"github.com/skenzeriq/activediq/internal/directory/connection"
	"github.com/skenzeriq/activediq/internal/directory/inventory"
	"github.com/skenzeriq/activediq/internal/modules/search"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/capability"
	"github.com/skenzeriq/activediq/internal/platform/secret"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/owners"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
)

// The adapter buildDirectory is given satisfies both ports: there is no second producer to write.
var _ search.ReadScopes = txReadScopes{}

func TestSearchTakesItsScopeFromTheComposedProducer(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		ctx := context.Background()
		db, ten, ks := hardeningDB(t, s, 0)
		deps := localAccountDeps{DB: db, Sink: nopSink{}, Keys: ks.KeySource()}
		mk := func(user string) string {
			la, err := createLocalAccount(ctx, deps, LocalAccountSpec{Username: user, Password: secret.FromBytes([]byte(signInPassword))})
			if err != nil {
				t.Fatal(err)
			}
			// The owner is dead for the producer until its TOTP is confirmed.
			var seedText string
			la.Seed.Expose(func(b []byte) { seedText = string(b) })
			seed, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(seedText))
			if err != nil {
				t.Fatal(err)
			}
			if err := confirmTOTP(ctx, deps, la, totpCode(seed, time.Now())); err != nil {
				t.Fatal(err)
			}
			return la.ID
		}
		// Created before any connection is active: no naming_context assignment to name.
		unassigned := mk("no.assignment")
		active := activeAD(t, connection.NewRegistry(db), ten)
		assigned := mk("console.reader")

		// One user in the connection's naming context.
		nc := inventory.GUID(string(active.DirectoryIdentity))
		const person = "cccccccc-0000-4000-8000-0000000000c1"
		yes := true
		var pop inventory.Populator
		err := db.WithTenant(ctx, ten, func(ctx context.Context, tx store.Tx) error {
			_, err := pop.Populate(ctx, tx, inventory.ConnectionID(active.ID), time.Now().Add(-time.Hour), []inventory.Observation{
				{Object: nc, NC: nc, Kind: inventory.KindOther, Class: "domainDNS", State: inventory.ObjLive},
				{Object: person, NC: nc, Kind: inventory.KindUser, Class: "user", State: inventory.ObjLive, Parent: nc, Ancestry: []inventory.GUID{nc},
					DN: "CN=Priya Raman,DC=corp,DC=example,DC=test", RDN: "CN=Priya Raman", DisplayName: "Priya Raman", SAMAccountName: "praman", Enabled: &yes},
			})
			return err
		})
		if err != nil {
			t.Fatal(err)
		}

		c, _, err := bootReport(ctx, capability.NewSet(capability.DirectoryAD, capability.DirectoryEntra, capability.TenantProvisioning), directory.Services{}, owners.Lookup)
		if err != nil {
			t.Fatal(err)
		}
		az, err := rbacAuthorizer(db, noFacts{})
		if err != nil {
			t.Fatal(err)
		}
		rs, err := buildReadScopes(az, c)
		if err != nil {
			t.Fatal(err)
		}
		svc, err := buildSearch(ctx, db, txReadScopes{db: db, rs: rs})
		if err != nil {
			t.Fatal(err)
		}
		ask := func(id string) (search.Result, error) {
			chain := authority.Chain{Requester: authority.Principal{ID: authority.PrincipalID(id), Kind: authority.Human}}
			return svc.Search(ctx, search.Call{Tenant: ten, Chain: chain, Text: "praman"})
		}
		hits := func(r search.Result) (n int) {
			for _, g := range r.Groups {
				n += len(g.Items)
			}
			return n
		}

		got, err := ask(assigned)
		if err != nil || hits(got) != 1 {
			t.Fatalf("assigned account: %d hits, %v", hits(got), err)
		}
		if !got.AsOf.IsZero() {
			t.Errorf("as-of = %v before any sync pass completed; want the zero time (asOf null)", got.AsOf)
		}
		if r, err := ask(unassigned); hits(r) != 0 || (err != nil && !errors.Is(err, search.ErrForbidden)) {
			t.Errorf("account without an assignment: %d hits, %v", hits(r), err)
		}
		if r, err := ask("b0000000-0000-4000-8000-0000000000ff"); !errors.Is(err, search.ErrForbidden) || hits(r) != 0 {
			t.Errorf("unknown owner: %d hits, %v; want ErrForbidden", hits(r), err)
		}

		// No producer: the service is not built (fail closed), and a service without one refuses.
		if _, err := buildSearch(ctx, db, nil); err == nil {
			t.Error("buildSearch accepted a nil producer")
		}
		noProducer := *svc
		noProducer.Scopes = nil
		if _, err := noProducer.Search(ctx, search.Call{Tenant: ten, Text: "praman"}); !errors.Is(err, search.ErrForbidden) {
			t.Errorf("service without a producer: %v; want ErrForbidden", err)
		}
	})
}
