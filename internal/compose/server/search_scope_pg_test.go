package server

// T-1096 AC2: universal search in the composed server takes its scope from the one producer, rbac.ReadScopes.For
// through the rbac.TxReadScopes the composition root binds after Boot — the same value the directory module
// holds as Deps.ReadScopes.
// Proved against the real producer, store and inventory: an account with the naming_context assignment finds an
// object of the connection, an account without one finds nothing, a dead owner is refused, and a service
// whose producer is not bound yet refuses (the module's own test proves a missing one fails the build).

import (
	"context"
	"encoding/base32"
	"encoding/json"
	"github.com/skenzeriq/activediq/internal/platform/apihost"
	"github.com/skenzeriq/activediq/internal/platform/apihost/apitest"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/directory/connection"
	"github.com/skenzeriq/activediq/internal/directory/inventory"
	"github.com/skenzeriq/activediq/internal/platform/secret"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
)

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

		az, err := rbacAuthorizer(db, noFacts{})
		if err != nil {
			t.Fatal(err)
		}
		tags := bootDirectoryRoutes(ctx, t, db, connection.NewRegistry(db), stubSource{}, stubReads{}, az)
		doc, err := apihost.LoadDocument()
		if err != nil {
			t.Fatal(err)
		}
		pol, err := apihost.LoadPolicy()
		if err != nil {
			t.Fatal(err)
		}
		who := &atomic.Pointer[string]{}
		lp := openPorts{tenant: ten.String(), account: who}
		srv, err := apihost.Build(doc, tags, pol, apitest.Catalogue(doc), apihost.Ports{Authn: lp, Authz: lp, Limits: lp, StepUp: lp})
		if err != nil {
			t.Fatal(err)
		}
		// ask is POST /directory/search as the given account: the hits over all groups, and the status.
		ask := func(id string) (int, int) {
			who.Store(&id)
			r := httptest.NewRequest(http.MethodPost, "/api/v1/directory/search", strings.NewReader(`{"q":"praman"}`))
			r.Header.Set("Content-Type", "application/json")
			r.RemoteAddr = "203.0.113.7:1"
			w := httptest.NewRecorder()
			srv.ServeHTTP(w, r)
			var body struct {
				AsOf   *string `json:"asOf"`
				Groups []struct {
					Items []json.RawMessage `json:"items"`
				} `json:"groups"`
			}
			if w.Code == http.StatusOK {
				if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
					t.Fatalf("answer: %v: %s", err, w.Body)
				}
				if body.AsOf != nil {
					t.Errorf("asOf = %q before any sync pass completed; want null", *body.AsOf)
				}
			}
			n := 0
			for _, g := range body.Groups {
				n += len(g.Items)
			}
			return w.Code, n
		}

		if code, n := ask(assigned); code != http.StatusOK || n != 1 {
			t.Fatalf("assigned account: status %d, %d hits; want 200 and 1", code, n)
		}
		if code, n := ask(unassigned); n != 0 || (code != http.StatusOK && code != http.StatusForbidden) {
			t.Errorf("account without an assignment: status %d, %d hits", code, n)
		}
		if code, n := ask("b0000000-0000-4000-8000-0000000000ff"); code != http.StatusForbidden || n != 0 {
			t.Errorf("unknown owner: status %d, %d hits; want 403", code, n)
		}
	})
}
