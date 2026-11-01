package inventory_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
	"github.com/skenzeriq/activediq/internal/directory/connection"
	"github.com/skenzeriq/activediq/internal/directory/inventory"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
)

// stubClassifier is the PairClassifier port: the tier0 classifiers are another ticket's. Directory
// behaviour (objects, links, edges, the gate) is the real database.
type stubClassifier struct {
	ad []inventory.Basis
	at time.Time
}

func (s stubClassifier) Classify(_ context.Context, _ store.Tx, _, _ inventory.Ref) (inventory.PairFacts, error) {
	return inventory.PairFacts{ADBases: s.ad, AsOf: s.at}, nil
}

const (
	enU1  = "eeeeeeee-0000-4000-8000-0000000000a1"
	enU2  = "eeeeeeee-0000-4000-8000-0000000000a2"
	enG   = "eeeeeeee-0000-4000-8000-0000000000b1"
	adU3  = "aaaaaaaa-0000-4000-8000-0000000000a3"
	admin = "99999999-9999-4999-8999-999999999999"
)

var userSID = []byte{1, 1, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 9, 0, 0, 0}

type ingestEnv struct {
	*env
	ing inventory.Ingester
	now time.Time
}

func newIngestEnv(t *testing.T, s *storetest.Server) *ingestEnv {
	e := setup(t, s)
	now := time.Now().UTC().Truncate(time.Second)
	return &ingestEnv{env: e, now: now, ing: inventory.Ingester{Classifier: stubClassifier{at: now.Add(-time.Minute)}}}
}

func (x *ingestEnv) link(t *testing.T, declare bool) {
	t.Helper()
	err := x.tx(t, x.a, func(ctx context.Context, tx store.Tx) error {
		n := connection.NewHybridLink{ADConnectionID: connection.ID(x.adA), NCGUID: nc1, EntraConnectionID: connection.ID(x.enA)}
		var err error
		if declare {
			_, err = connection.Store{}.DeclareHybridLink(ctx, tx, n)
		} else {
			_, err = connection.Store{}.DiscoverHybridLink(ctx, tx, n)
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}

func (x *ingestEnv) attest(t *testing.T, hard, soft bool) {
	t.Helper()
	err := x.tx(t, x.a, func(ctx context.Context, tx store.Tx) error {
		_, err := connection.Store{}.RecordAttestation(ctx, tx, connection.ID(x.enA),
			connection.Attestation{By: admin, BlockHardMatch: hard, BlockSoftMatch: soft}, x.now.Add(-time.Hour))
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}

func (x *ingestEnv) ingest(t *testing.T, c inventory.ConnectionID, at time.Time, obs ...inventory.Observation) (inventory.Ingested, error) {
	t.Helper()
	var out inventory.Ingested
	err := x.tx(t, x.a, func(ctx context.Context, tx store.Tx) (err error) {
		out, err = x.ing.Ingest(ctx, tx, inventory.Cycle{Connection: c, Observed: at, Observations: obs, Now: x.now})
		return
	})
	return out, err
}

func (x *ingestEnv) state(t *testing.T, enGUID string) (state, reason, class string) {
	t.Helper()
	err := x.tx(t, x.a, func(ctx context.Context, tx store.Tx) error {
		return tx.QueryRow(ctx, `SELECT state, candidate_reason, eligibility_class FROM public.correlations
			WHERE entra_object_guid = $1::uuid AND state <> 'removed'`, enGUID).Scan(&state, &reason, &class)
	})
	if err != nil {
		t.Fatalf("correlation of %s: %v", enGUID, err)
	}
	return
}

func wire(t *testing.T, g string) []byte {
	t.Helper()
	p, err := guid.Parse(g)
	if err != nil {
		t.Fatal(err)
	}
	return p.Bytes()
}

func adDomainHead() inventory.Observation {
	return inventory.Observation{Object: nc1, NC: nc1, Kind: inventory.KindContainer, Class: "domainDNS", DN: "DC=corp,DC=example", State: inventory.ObjLive}
}

func adUserCG(g string, cg []byte) inventory.Observation {
	o := adUser(g, nc1)
	o.SID, o.ConsistencyGUID = userSID, cg
	return o
}

func enUserFor(g string, anchorOf []byte, s []byte) inventory.Observation {
	o := enUser(g, &yes)
	o.OnPremisesSecurityIdentifier, o.OnPremisesImmutableID, o.OnPremisesDomainName = s, anchorOf, "corp.example"
	return o
}

func TestIngestFormsMatchedPairWithMembersInOneTransaction(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		x := newIngestEnv(t, s)
		x.link(t, true)
		x.attest(t, true, true)
		cg := wire(t, "12345678-1234-4234-8234-123456789abc")
		grp := inventory.Observation{Object: grp1, NC: nc1, Kind: inventory.KindGroup, Class: "group", State: inventory.ObjLive,
			SID: sid, Members: []inventory.GUID{usr1}, MembersComplete: true}
		if _, err := x.ingest(t, x.adA, x.now.Add(-20*time.Minute), adDomainHead(), adUserCG(usr1, cg), grp); err != nil {
			t.Fatal(err)
		}
		egrp := inventory.Observation{Object: enG, Kind: inventory.KindGroup, Class: "group", OnPremisesSyncEnabled: &yes, OnPremisesSyncEnabledRead: true,
			State: inventory.ObjActive, OnPremisesSecurityIdentifier: sid, OnPremisesDomainName: "corp.example"}
		res, err := x.ingest(t, x.enA, x.now.Add(-10*time.Minute), enUserFor(enU1, cg, userSID), egrp)
		if err != nil || res.Pairs != 2 || res.Created != 2 || res.Matched != 2 {
			t.Fatalf("entra cycle: %+v %v", res, err)
		}
		if st, _, class := x.state(t, enU1); st != "matched" || class != "install_time" && class != "attested" {
			t.Fatalf("user: %s %s", st, class)
		}
		// DM-17: the member edge from the AD cycle is in the same inventory, and the evaluation as-of is the oldest input.
		if n := x.count(t, `SELECT count(*) FROM public.links WHERE link_attr = 'member' AND state = 'active'`); n != 1 {
			t.Fatalf("member edges: %d", n)
		}
		c, err := x.r.CorrelationsFor(context.Background(), x.a, inventory.Ref{Connection: x.enA, Object: enU1})
		if err != nil || len(c.Links) != 1 || !c.EvaluatedAt.Equal(x.now.Add(-20*time.Minute)) {
			t.Fatalf("as-of: %+v %v", c, err)
		}
	})
}

func TestIngestGateReasonsFromStoredState(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		x := newIngestEnv(t, s)
		cg := wire(t, "12345678-1234-4234-8234-123456789abc")
		at := x.now.Add(-20 * time.Minute)
		if _, err := x.ingest(t, x.adA, at, adDomainHead(), adUserCG(usr1, cg)); err != nil {
			t.Fatal(err)
		}
		// Proposed link and never attested: the first failing check is the link.
		x.link(t, false)
		if _, err := x.ingest(t, x.enA, at.Add(time.Minute), enUserFor(enU1, cg, userSID)); err != nil {
			t.Fatal(err)
		}
		if st, r, _ := x.state(t, enU1); st != "candidate" || r != "link_unconfirmed" {
			t.Fatalf("proposed link: %s %s", st, r)
		}
		// An AD cycle after the link is confirmed and the tenant attested: matched, without touching the Entra side.
		if err := x.tx(t, x.a, func(ctx context.Context, tx store.Tx) error {
			_, err := tx.Exec(ctx, `UPDATE public.hybrid_links SET state = 'confirmed'`)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := x.ingest(t, x.adA, at.Add(2*time.Minute), adUserCG(usr1, cg)); err != nil {
			t.Fatal(err)
		}
		if st, r, _ := x.state(t, enU1); st != "candidate" || r != "tenant_takeover_open" {
			t.Fatalf("unattested: %s %s", st, r)
		}
		x.attest(t, true, true)
		if _, err := x.ingest(t, x.adA, at.Add(3*time.Minute), adUserCG(usr1, cg)); err != nil {
			t.Fatal(err)
		}
		if st, _, _ := x.state(t, enU1); st != "matched" {
			t.Fatalf("attested: %s", st)
		}
		// The AD SID changes (rename into another domain): the user pair is a candidate for sid_mismatch, never matched.
		moved := adUserCG(usr1, cg)
		moved.SID = []byte{1, 1, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 77, 0, 0, 0}
		if _, err := x.ingest(t, x.adA, at.Add(4*time.Minute), moved); err != nil {
			t.Fatal(err)
		}
		if st, r, _ := x.state(t, enU1); st != "candidate" || r != "sid_mismatch" {
			t.Fatalf("sid moved: %s %s", st, r)
		}
		// The AD object is deleted: broken.
		del := adUserCG(usr1, cg)
		del.State = inventory.ObjDeleted
		if _, err := x.ingest(t, x.adA, at.Add(5*time.Minute), del); err != nil {
			t.Fatal(err)
		}
		if st, _, _ := x.state(t, enU1); st != "broken" {
			t.Fatalf("deleted: %s", st)
		}
	})
}

func TestIngestAmbiguousAnchorFormsNothingAndDemotesTheExistingPair(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		x := newIngestEnv(t, s)
		x.link(t, true)
		x.attest(t, true, true)
		cg := wire(t, "12345678-1234-4234-8234-123456789abc")
		at := x.now.Add(-20 * time.Minute)
		// usr2's objectGUID equals usr1's consistency GUID: the anchor resolves to two AD objects.
		other := adUserCG(usr2, nil)
		other.Object = inventory.GUID("12345678-1234-4234-8234-123456789abc")
		if _, err := x.ingest(t, x.adA, at, adDomainHead(), adUserCG(usr1, cg), other); err != nil {
			t.Fatal(err)
		}
		res, err := x.ingest(t, x.enA, at.Add(time.Minute), enUserFor(enU1, cg, userSID))
		if err != nil || res.Pairs != 0 {
			t.Fatalf("ambiguous anchor must form no pair: %+v %v", res, err)
		}
		// Unambiguous first, then a second claimant appears: the live pair drops to candidate.
		x2 := newIngestEnv(t, s)
		x2.link(t, true)
		x2.attest(t, true, true)
		if _, err := x2.ingest(t, x2.adA, at, adDomainHead(), adUserCG(usr1, cg)); err != nil {
			t.Fatal(err)
		}
		if _, err := x2.ingest(t, x2.enA, at.Add(time.Minute), enUserFor(enU1, cg, userSID)); err != nil {
			t.Fatal(err)
		}
		if st, _, _ := x2.state(t, enU1); st != "matched" {
			t.Fatalf("setup: %s", st)
		}
		if _, err := x2.ingest(t, x2.adA, at.Add(2*time.Minute), other); err != nil {
			t.Fatal(err)
		}
		if st, r, _ := x2.state(t, enU1); st != "candidate" || r != "ambiguous_anchor" {
			t.Fatalf("second claimant: %s %s", st, r)
		}
	})
}

func TestIngestPreconditions(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		x := newIngestEnv(t, s)
		at := x.now.Add(-20 * time.Minute)
		noClass := inventory.Ingester{}
		err := x.tx(t, x.a, func(ctx context.Context, tx store.Tx) error {
			_, err := noClass.Ingest(ctx, tx, inventory.Cycle{Connection: x.adA, Observed: at, Now: x.now})
			return err
		})
		if !errors.Is(err, inventory.ErrNotConfigured) {
			t.Fatalf("no classifier: %v", err)
		}
		if _, err := x.ingest(t, x.adA, at, adDomainHead()); err != nil {
			t.Fatal(err)
		}
		x.link(t, true)
		if _, err := x.ingest(t, x.enA, at, enUserFor(enU1, wire(t, "12345678-1234-4234-8234-123456789abc"), userSID)); err != nil {
			t.Fatal(err)
		}
		// A run older than a stored evaluation is stale and the caller's transaction rolls back.
		_, err = x.ingest(t, x.adA, at.Add(-time.Hour), adDomainHead())
		if !errors.Is(err, inventory.ErrStale) {
			t.Fatalf("stale cycle: %v", err)
		}
	})
}

func TestIngestPrincipalTypeMismatchNeverPassesTheGate(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		cg := wire(t, "12345678-1234-4234-8234-123456789abc")
		at := func(x *ingestEnv) time.Time { return x.now.Add(-20 * time.Minute) }
		for _, kc := range []struct {
			kind  inventory.Kind
			class string
		}{{inventory.KindComputer, "computer"}, {inventory.KindGMSA, "msDS-GroupManagedServiceAccount"},
			{inventory.KindContact, "contact"}, {inventory.KindGroup, "group"}} {
			x := newIngestEnv(t, s)
			x.link(t, true)
			x.attest(t, true, true)
			o := adUserCG(usr1, cg)
			o.Kind, o.Class = kc.kind, kc.class
			if _, err := x.ingest(t, x.adA, at(x), adDomainHead(), o); err != nil {
				t.Fatal(err)
			}
			res, err := x.ingest(t, x.enA, at(x).Add(time.Minute), enUserFor(enU1, cg, userSID))
			if err != nil || res.Pairs != 0 || res.Created != 0 || res.Matched != 0 {
				t.Fatalf("%s must form no pair: %+v %v", kc.kind, res, err)
			}
		}

		// A live matched pair whose AD row changes kind is demoted, never kept matched.
		x := newIngestEnv(t, s)
		x.link(t, true)
		x.attest(t, true, true)
		if _, err := x.ingest(t, x.adA, at(x), adDomainHead(), adUserCG(usr1, cg)); err != nil {
			t.Fatal(err)
		}
		if _, err := x.ingest(t, x.enA, at(x).Add(time.Minute), enUserFor(enU1, cg, userSID)); err != nil {
			t.Fatal(err)
		}
		if st, _, _ := x.state(t, enU1); st != "matched" {
			t.Fatalf("setup: %s", st)
		}
		o := adUserCG(usr1, cg)
		o.Kind, o.Class = inventory.KindComputer, "computer"
		if _, err := x.ingest(t, x.adA, at(x).Add(2*time.Minute), o); err != nil {
			t.Fatal(err)
		}
		if st, _, _ := x.state(t, enU1); st == "matched" {
			t.Fatal("a correlation to a non-user AD object stayed matched")
		}
	})
}
