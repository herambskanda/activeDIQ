package server

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/skenzeriq/activediq/internal/directory/connection"
	"github.com/skenzeriq/activediq/internal/directory/inventory"
	"github.com/skenzeriq/activediq/internal/platform/authn"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/rbac"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
	"github.com/skenzeriq/activediq/internal/platform/tenant/tenanttest"
)

const (
	bkCred = "11111111-1111-4111-8111-111111111111"
	bkSID  = "S-1-5-21-1004336348-1177238915-682003330-1105"
	bkTID  = "99999999-bbbb-4ccc-8ddd-eeeeeeeeeeee"
	ouRoot = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
	ouKid  = "dddddddd-dddd-4ddd-8ddd-ddddddddddd1"
	ncHead = "dddddddd-dddd-4ddd-8ddd-ddddddddddd0"
)

type bkEnv struct {
	db     *store.DB
	ten    tenant.ID
	ad, en string
}

func bkSetup(t *testing.T, s *storetest.Server) *bkEnv {
	t.Helper()
	d := s.NewDatabase(t)
	d.Migrate(t)
	db, err := store.Open(context.Background(), store.Config{DSN: d.AppDSN()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	e := &bkEnv{db: db, ten: tenanttest.Seed(t, d.ExecOwner, "A")}
	mk := func(k connection.Kind, tr connection.Transport) string {
		c, err := connection.NewRegistry(db).Create(context.Background(), e.ten, connection.New{Kind: k, DisplayName: "c", CredentialID: bkCred, Transport: tr})
		if err != nil {
			t.Fatal(err)
		}
		return string(c.ID)
	}
	e.ad = mk(connection.KindADForest, connection.TransportLDAPS)
	e.en = mk(connection.KindEntraTenant, "")
	return e
}

func (e *bkEnv) exec(t *testing.T, sql string, args ...any) {
	t.Helper()
	err := e.db.WithTenant(context.Background(), e.ten, func(ctx context.Context, tx store.Tx) error {
		_, err := tx.Exec(ctx, sql, args...)
		return err
	})
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
}

// account inserts a console account resting on conn/guid. anchor is "", "oid" or "onprem_sid".
func (e *bkEnv) account(t *testing.T, id, kind, conn, guid, anchor, state string) {
	t.Helper()
	switch {
	case kind == "directory":
		e.exec(t, `INSERT INTO public.authn_accounts (tenant_id, id, kind, display_name, state, created_by, directory_connection_id, directory_object_guid)
			VALUES ($1::uuid, $2::uuid, 'directory', 'd', $5, 'system', $3::uuid, $4::uuid)`, e.ten.String(), id, conn, guid, state)
	case anchor == "oid":
		e.exec(t, `INSERT INTO public.authn_accounts (tenant_id, id, kind, display_name, state, created_by, sso_issuer, sso_subject, directory_connection_id, directory_object_guid, anchor_kind, anchor_value, anchor_tid)
			VALUES ($1::uuid, $2::uuid, 'sso', 's', $6, 'system', 'https://idp', $2::text, $3::uuid, $4::uuid, 'oid', $4::text, $5::uuid)`, e.ten.String(), id, conn, guid, bkTID, state)
	default:
		e.exec(t, `INSERT INTO public.authn_accounts (tenant_id, id, kind, display_name, state, created_by, sso_issuer, sso_subject, directory_connection_id, directory_object_guid, anchor_kind, anchor_value)
			VALUES ($1::uuid, $2::uuid, 'sso', 's', $5, 'system', 'https://idp', $2::text, $3::uuid, $4::uuid, 'onprem_sid', $6::text)`, e.ten.String(), id, conn, guid, state, bkSID)
	}
}

func (e *bkEnv) corr(t *testing.T, adG, enG, state string) {
	t.Helper()
	switch state {
	case "candidate":
		e.exec(t, `INSERT INTO public.correlations (tenant_id, ad_connection_id, ad_object_guid, entra_connection_id, entra_object_guid, state, candidate_reason, match, ad_sid)
			VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, $5::uuid, 'candidate', 'not_synced', 'sid', '\x010100000000000515000000')`, e.ten.String(), e.ad, adG, e.en, enG)
	case "matched":
		e.exec(t, `INSERT INTO public.correlations (tenant_id, ad_connection_id, ad_object_guid, entra_connection_id, entra_object_guid, state, match, ad_sid, gate_checked_at, eligible_since, eligibility_class)
			VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, $5::uuid, 'matched', 'sid', '\x010100000000000515000000', now(), now(), 'attested')`, e.ten.String(), e.ad, adG, e.en, enG)
	default: // broken, removed
		e.exec(t, `INSERT INTO public.correlations (tenant_id, ad_connection_id, ad_object_guid, entra_connection_id, entra_object_guid, state, match, ad_sid)
			VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, $5::uuid, $6, 'sid', '\x010100000000000515000000')`, e.ten.String(), e.ad, adG, e.en, enG, state)
	}
}

type noFacts struct{}

func (noFacts) Facts(context.Context, authority.Pins, authority.FactsQuery) (authority.Facts, error) {
	return authority.Facts{}, errors.New("no live read in this test")
}

// T-0385 acceptance 1: BackedBy over the real account and correlation tables. A directory account,
// an oid-bound and an onprem_sid-bound sso account rest on their own objects; every non-removed
// correlation expands, from either side; a removed one does not; deleted accounts are not counted.
func TestBackingExpandsAccountsAndCorrelations(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := bkSetup(t, s)
		const (
			uDir, uOID, uSID                                        = "a0000000-0000-4000-8000-000000000001", "a0000000-0000-4000-8000-000000000002", "a0000000-0000-4000-8000-000000000003"
			uCand, uMatch, uBroke, uRem                             = "a0000000-0000-4000-8000-000000000004", "a0000000-0000-4000-8000-000000000005", "a0000000-0000-4000-8000-000000000006", "a0000000-0000-4000-8000-000000000007"
			eCand, eMatch, eBroke, eRem                             = "e0000000-0000-4000-8000-000000000004", "e0000000-0000-4000-8000-000000000005", "e0000000-0000-4000-8000-000000000006", "e0000000-0000-4000-8000-000000000007"
			aDir, aOID, aSID, aCand, aMatch, aBroke, aRem, aDeleted = "c0000000-0000-4000-8000-000000000001", "c0000000-0000-4000-8000-000000000002", "c0000000-0000-4000-8000-000000000003", "c0000000-0000-4000-8000-000000000004", "c0000000-0000-4000-8000-000000000005", "c0000000-0000-4000-8000-000000000006", "c0000000-0000-4000-8000-000000000007", "c0000000-0000-4000-8000-000000000008"
		)
		e.account(t, aDir, "directory", e.ad, uDir, "", "active")
		e.account(t, aOID, "sso", e.ad, uOID, "oid", "active")
		e.account(t, aSID, "sso", e.ad, uSID, "onprem_sid", "disabled")
		// Accounts that rest on the Entra peers.
		e.account(t, aCand, "sso", e.en, eCand, "oid", "active")
		e.account(t, aMatch, "sso", e.en, eMatch, "oid", "active")
		e.account(t, aBroke, "sso", e.en, eBroke, "oid", "invited")
		e.account(t, aRem, "sso", e.en, eRem, "oid", "active")
		e.account(t, aDeleted, "directory", e.ad, uCand, "", "deleted")
		e.corr(t, uCand, eCand, "candidate")
		e.corr(t, uMatch, eMatch, "matched")
		e.corr(t, uBroke, eBroke, "broken")
		e.corr(t, uRem, eRem, "removed")

		backing := buildBacking(t, e)
		ref := func(conn, g string) authority.TargetRef {
			return authority.TargetRef{Connection: conn, GUID: g, Class: "user"}
		}
		want := func(name string, got rbac.BackedAccounts, err error, ids ...string) {
			t.Helper()
			if err != nil || !got.Complete {
				t.Fatalf("%s: complete=%v err=%v", name, got.Complete, err)
			}
			slices.Sort(ids)
			if !slices.Equal(got.Accounts, ids) {
				t.Errorf("%s: accounts = %v, want %v", name, got.Accounts, ids)
			}
		}
		ctx := context.Background()
		g, err := backing.BackedBy(ctx, e.ten, ref(e.ad, uDir))
		want("directory account", g, err, aDir)
		g, err = backing.BackedBy(ctx, e.ten, ref(e.ad, uOID))
		want("oid-bound sso", g, err, aOID)
		g, err = backing.BackedBy(ctx, e.ten, ref(e.ad, uSID))
		want("onprem_sid-bound sso (disabled still counts)", g, err, aSID)
		g, err = backing.BackedBy(ctx, e.ten, ref(e.ad, uCand))
		want("candidate expands; deleted account does not count", g, err, aCand)
		g, err = backing.BackedBy(ctx, e.ten, ref(e.ad, uMatch))
		want("matched expands", g, err, aMatch)
		g, err = backing.BackedBy(ctx, e.ten, ref(e.ad, uBroke))
		want("broken expands (invited counts)", g, err, aBroke)
		g, err = backing.BackedBy(ctx, e.ten, ref(e.ad, uRem))
		want("removed does not expand", g, err)
		// The other direction: from the Entra peer to the AD object's accounts.
		g, err = backing.BackedBy(ctx, e.ten, ref(e.en, eMatch))
		want("reverse direction", g, err, aMatch)
		// A target that is not a directory object is never complete.
		g, err = backing.BackedBy(ctx, e.ten, authority.TargetRef{GUID: uDir})
		if err != nil || g.Complete {
			t.Errorf("store target: %+v %v; want incomplete", g, err)
		}
	})
}

// T-0421 acceptance 2: Entra-to-AD expansion. The Entra object has no account of its own; the AD
// object it is correlated (candidate) to does. BackedBy on the Entra object must return the AD-side
// account and be complete, so a reset of the Entra object cannot bypass the guard.
func TestBackingExpandsEntraObjectToADSideAccount(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := bkSetup(t, s)
		const (
			adUser = "a0000000-0000-4000-8000-0000000000c1"
			entraU = "e0000000-0000-4000-8000-0000000000c1"
			adAcct = "c0000000-0000-4000-8000-0000000000c1"
			lonely = "e0000000-0000-4000-8000-0000000000c2"
		)
		e.account(t, adAcct, "directory", e.ad, adUser, "", "active")
		e.corr(t, adUser, entraU, "candidate")
		backing := buildBacking(t, e)
		ctx := context.Background()
		got, err := backing.BackedBy(ctx, e.ten, authority.TargetRef{Connection: e.en, GUID: entraU, Class: "user"})
		if err != nil || !got.Complete {
			t.Fatalf("complete=%v err=%v", got.Complete, err)
		}
		if !slices.Equal(got.Accounts, []string{adAcct}) {
			t.Errorf("accounts = %v, want [%s]", got.Accounts, adAcct)
		}
		// Control: an Entra object with neither an account nor a correlation is backed by nothing.
		got, err = backing.BackedBy(ctx, e.ten, authority.TargetRef{Connection: e.en, GUID: lonely, Class: "user"})
		if err != nil || !got.Complete || len(got.Accounts) != 0 {
			t.Errorf("uncorrelated Entra object: %+v %v; want complete and empty", got, err)
		}
	})
}

func buildBacking(t *testing.T, e *bkEnv) rbac.Backing {
	t.Helper()
	idx, err := authn.NewAccountIndex(e.db)
	if err != nil {
		t.Fatal(err)
	}
	b, err := rbac.NewBacking(accountAdapter{idx}, peerAdapter{inventory.NewReader(e.db, nil)})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

type lab map[string]authority.Facts

func (l lab) Facts(_ context.Context, _ authority.Pins, q authority.FactsQuery) (authority.Facts, error) {
	if f, ok := l[q.Target.GUID]; ok {
		return f, nil
	}
	return authority.Facts{}, errors.New("not in lab")
}

// T-0385 acceptance 2: the authorizer rbacAuthorizer builds has the guard wired. A help-desk operator
// scoped to an OU may reset an ordinary user but not the user that backs a console account holding a
// broader scope; the refusal is the typed rbac denial the runner records as a denied, audited run.
func TestComposedAuthorizerRefusesResetOfBackingObject(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := bkSetup(t, s)
		ctx := context.Background()
		if err := e.db.WithTenant(ctx, e.ten, func(ctx context.Context, tx store.Tx) error { return rbac.SeedBuiltIns(ctx, tx, e.ten) }); err != nil {
			t.Fatal(err)
		}
		const (
			plain   = "a0000000-0000-4000-8000-0000000000a1" // an ordinary user in the OU
			backer  = "a0000000-0000-4000-8000-0000000000a2" // a user that backs a console account
			helpdsk = "c0000000-0000-4000-8000-0000000000b1"
			admin   = "c0000000-0000-4000-8000-0000000000b2"
		)
		e.account(t, admin, "directory", e.ad, backer, "", "active")
		assign := func(role, acct string, roots ...rbac.Root) {
			t.Helper()
			e.exec(t, `INSERT INTO public.authz_assignments (tenant_id, account_id, role_id, valid_from, granted_by, assignment_state)
				SELECT $1::uuid, $2::uuid, r.id, now() - interval '2 hours', 'test', 'active' FROM public.authz_roles r WHERE r.tenant_id = $1::uuid AND r.role_name = $3`, e.ten.String(), acct, role)
			for i, r := range roots {
				e.exec(t, `INSERT INTO public.authz_assignment_roots (tenant_id, assignment_id, ordinal, is_exclude, root_kind, connection_id, root_guid)
					SELECT $1::uuid, a.id, $3, false, $4, $5::uuid, $6::uuid FROM public.authz_assignments a WHERE a.tenant_id = $1::uuid AND a.account_id = $2::uuid ORDER BY a.id DESC LIMIT 1`,
					e.ten.String(), acct, i, string(r.Kind), r.Connection, r.GUID)
			}
		}
		assign("helpdesk-operator", helpdsk, rbac.Root{Kind: rbac.OUSubtree, Connection: e.ad, GUID: ouKid})
		assign("platform-administrator", admin, rbac.Root{Kind: rbac.OUSubtree, Connection: e.ad, GUID: ouRoot})

		facts := lab{
			ouKid:  {Exists: true, Ancestors: []string{ouRoot, ncHead}, AncestorsComplete: true},
			ouRoot: {Exists: true, Ancestors: []string{ncHead}, AncestorsComplete: true},
		}
		az, err := rbacAuthorizer(e.db, facts)
		if err != nil {
			t.Fatal(err)
		}
		human := authority.Chain{Requester: authority.Principal{ID: authority.PrincipalID(helpdsk), Kind: authority.Human}}
		target := func(g string) authority.TargetRef {
			return authority.TargetRef{Connection: e.ad, GUID: g, Class: "user", NC: "nc"}
		}
		in := authority.Facts{Exists: true, Ancestors: []string{ouKid, ouRoot, ncHead}, AncestorsComplete: true}
		tc := authority.WithTenant(ctx, e.ten.String())
		const reset authz.Permission = "objects.user.reset_password"
		if err := az.Authorize(tc, human, reset, target(plain), in); err != nil {
			t.Fatalf("reset of an ordinary user in scope: %v", err)
		}
		err = az.Authorize(tc, human, reset, target(backer), in)
		if !errors.Is(err, rbac.ErrDenied) || !strings.Contains(err.Error(), string(rbac.ReasonBackingObject)) {
			t.Fatalf("reset of a backing object by a less-privileged actor = %v, want a %s denial", err, rbac.ReasonBackingObject)
		}
	})
}
