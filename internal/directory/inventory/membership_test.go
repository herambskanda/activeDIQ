package inventory_test

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/directory/inventory"
	"github.com/skenzeriq/activediq/internal/platform/authn"
	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

const (
	mAcct  = "dddddddd-0000-4000-8000-000000000001"
	mUser  = "aaaaaaaa-0000-4000-8000-0000000000c1"
	mSec   = "aaaaaaaa-0000-4000-8000-0000000000c2"
	mDist  = "aaaaaaaa-0000-4000-8000-0000000000c3"
	mWeak  = "aaaaaaaa-0000-4000-8000-0000000000c4"
	mOuter = "aaaaaaaa-0000-4000-8000-0000000000c5"
	mEUser = "eeeeeeee-0000-4000-8000-0000000000c1"
	mEPub  = "eeeeeeee-0000-4000-8000-0000000000c2"
	mEPriv = "eeeeeeee-0000-4000-8000-0000000000c3"
)

type acctSrc map[string]authn.Account

func (a acctSrc) Get(_ context.Context, _ tenant.ID, id string) (authn.Account, error) {
	if x, ok := a[id]; ok {
		return x, nil
	}
	return authn.Account{}, errors.New("no such account")
}

type tkSrc string

func (s tkSrc) TakeoverProtection(context.Context, tenant.ID, inventory.ConnectionID) (string, error) {
	return string(s), nil
}

// adGroup is an AD group row. groupType -2147483646 is a global security group, 2 a global distribution group.
func adGroup(g string, groupType int, broad any, members ...string) inventory.Observation {
	attrs := map[string]any{inventory.AttrGroupType: groupType}
	if broad != nil {
		attrs[inventory.AttrBroadMembershipWrite] = broad
	}
	o := inventory.Observation{Object: inventory.GUID(g), NC: nc1, Kind: inventory.KindGroup, Class: "group", State: inventory.ObjLive, Attributes: attrs}
	for _, m := range members {
		o.Members = append(o.Members, inventory.GUID(m))
	}
	o.MembersComplete = true
	return o
}

// enGroup is an Entra group the sync read as cloud-managed (onPremisesSyncEnabled null) with groupTypes [].
func enGroup(g string, sec bool, vis string, members ...string) inventory.Observation {
	attrs := map[string]any{inventory.AttrSecurityEnabled: sec, inventory.AttrGroupTypes: []string{}, inventory.AttrOnPremisesSyncEnabled: nil}
	if vis != "" {
		attrs[inventory.AttrVisibility] = vis
	}
	o := inventory.Observation{Object: inventory.GUID(g), Kind: inventory.KindGroup, Class: "group", State: inventory.ObjActive, Attributes: attrs}
	for _, m := range members {
		o.Members = append(o.Members, inventory.GUID(m))
	}
	o.MembersComplete = true
	return o
}

func (e *env) membership(ref inventory.Ref, kind authn.AccountKind, tk string) *inventory.Membership {
	accts := acctSrc{mAcct: {ID: mAcct, Kind: kind, State: authn.AccountActive,
		Ref: &authn.DirectoryRef{ConnectionID: string(ref.Connection), ObjectGUID: string(ref.Object)}}}
	return inventory.NewMembership(e.db, accts, e.r, tkSrc(tk))
}

func guids(g authz.Groups) []string {
	var out []string
	for _, x := range g.Groups {
		out = append(out, x.GUID)
	}
	slices.Sort(out)
	return out
}

func TestMembership_eligible_groups(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		ctx := context.Background()
		if _, err := e.populate(t, e.adA, t1, adUser(mUser, nc1),
			adGroup(mSec, -2147483646, false, mUser),
			adGroup(mDist, 2, false, mUser),
			adGroup(mWeak, -2147483646, true, mUser)); err != nil {
			t.Fatal(err)
		}
		// An Entra user in a Public and a private security group and a non-security group.
		const mENonSec = "eeeeeeee-0000-4000-8000-0000000000c4"
		if _, err := e.populate(t, e.enA, t1, enUser(mEUser, nil),
			enGroup(mEPub, true, "Public", mEUser), enGroup(mEPriv, true, "Private", mEUser), enGroup(mENonSec, false, "", mEUser)); err != nil {
			t.Fatal(err)
		}
		g, err := e.membership(inventory.Ref{Connection: e.adA, Object: mUser}, authn.KindDirectory, "").GroupsOf(ctx, e.a.String(), mAcct)
		if err != nil {
			t.Fatal(err)
		}
		if !g.Complete || !slices.Equal(guids(g), []string{mSec}) {
			t.Fatalf("AD: got %v complete=%v, want only the security group", guids(g), g.Complete)
		}
		g, err = e.membership(inventory.Ref{Connection: e.enA, Object: mEUser}, authn.KindSSO, "").GroupsOf(ctx, e.a.String(), mAcct)
		if err != nil {
			t.Fatal(err)
		}
		if !g.Complete || !slices.Equal(guids(g), []string{mEPriv}) {
			t.Fatalf("Entra: got %v complete=%v, want only the private security group", guids(g), g.Complete)
		}
		// A securityEnabled Unified group with no stored visibility may be Public: not granted, incomplete.
		const mEUni = "eeeeeeee-0000-4000-8000-0000000000c5"
		uni := enGroup(mEUni, true, "", mEUser)
		uni.Attributes[inventory.AttrGroupTypes] = []string{"Unified"}
		if _, err := e.populate(t, e.enA, t2, enUser(mEUser, nil), uni); err != nil {
			t.Fatal(err)
		}
		g, err = e.membership(inventory.Ref{Connection: e.enA, Object: mEUser}, authn.KindSSO, "").GroupsOf(ctx, e.a.String(), mAcct)
		if err != nil {
			t.Fatal(err)
		}
		if g.Complete || slices.Contains(guids(g), mEUni) {
			t.Fatalf("Unified group without visibility: got %v complete=%v, want omitted and incomplete", guids(g), g.Complete)
		}
	})
}

func TestMembership_via(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		ctx := context.Background()
		// user -> sec -> outer, and a cycle outer -> sec.
		if _, err := e.populate(t, e.adA, t1, adUser(mUser, nc1),
			adGroup(mSec, -2147483646, false, mUser),
			adGroup(mOuter, -2147483646, false, mSec)); err != nil {
			t.Fatal(err)
		}
		if _, err := e.populate(t, e.adA, t2, adGroup(mSec, -2147483646, false, mUser, mOuter)); err != nil {
			t.Fatal(err)
		}
		g, err := e.membership(inventory.Ref{Connection: e.adA, Object: mUser}, authn.KindDirectory, "").GroupsOf(ctx, e.a.String(), mAcct)
		if err != nil || !g.Complete {
			t.Fatalf("err=%v complete=%v", err, g.Complete)
		}
		if len(g.Groups) != 2 || g.Groups[0].GUID != mSec || g.Groups[1].GUID != mOuter {
			t.Fatalf("groups = %+v, want direct group first then the nested one", g.Groups)
		}
		if want := []string{mUser, mSec, mOuter}; !slices.Equal(g.Groups[1].Path, want) {
			t.Fatalf("nested path = %v, want %v", g.Groups[1].Path, want)
		}
		if g.Groups[1].Via != nil {
			t.Fatal("a same-plane nested group is not correlation-derived: Via must stay nil")
		}

		// Correlation-derived: the AD user matched to an Entra user in a private security group.
		if _, err := e.populate(t, e.enA, t1, enUser(mEUser, nil), enGroup(mEPriv, true, "", mEUser)); err != nil {
			t.Fatal(err)
		}
		e.seed(t, e.a, inventory.Ref{Connection: e.adA, Object: mUser}, inventory.Ref{Connection: e.enA, Object: mEUser},
			"matched", "", "match, ad_sid, facts_as_of", "sid", sid, time.Now())
		for _, c := range []inventory.ConnectionID{e.adA, e.enA} {
			if err := e.exec(e.a, `INSERT INTO public.correlation_evaluations (tenant_id, connection_id, evaluated_at) VALUES ($1::uuid, $2::uuid, now())`,
				e.a.String(), string(c)); err != nil {
				t.Fatal(err)
			}
		}
		g, err = e.membership(inventory.Ref{Connection: e.adA, Object: mUser}, authn.KindDirectory, "attested").GroupsOf(ctx, e.a.String(), mAcct)
		if err != nil || !g.Complete {
			t.Fatalf("err=%v complete=%v", err, g.Complete)
		}
		var d *authz.Group
		for i := range g.Groups {
			if g.Groups[i].GUID == mEPriv {
				d = &g.Groups[i]
			}
		}
		if d == nil || d.Via == nil || d.Via.Correlation == nil {
			t.Fatalf("Entra group must be derived with Via and correlation facts: %+v", g.Groups)
		}
		if c := d.Via.Correlation; c.State != authz.CorrelationMatched || c.Takeover != "attested" || c.Tier0Either {
			t.Fatalf("correlation facts = %+v", c)
		}
		if want := []string{mEUser, mEPriv}; !slices.Equal(d.Path, want) {
			t.Fatalf("derived path = %v, want %v", d.Path, want)
		}
		// Without a takeover source the derived grant carries an unattested fact (the gate refuses it).
		g, _ = e.membership(inventory.Ref{Connection: e.adA, Object: mUser}, authn.KindDirectory, "").GroupsOf(ctx, e.a.String(), mAcct)
		for _, x := range g.Groups {
			if x.GUID == mEPriv && x.Via.Correlation.Takeover == "attested" {
				t.Fatal("empty takeover source must not read as attested")
			}
		}
		// An sso account gets no correlation-derived group here (authority factor, DM-30.I6).
		g, _ = e.membership(inventory.Ref{Connection: e.adA, Object: mUser}, authn.KindSSO, "attested").GroupsOf(ctx, e.a.String(), mAcct)
		for _, x := range g.Groups {
			if x.Via != nil || x.Connection == string(e.enA) {
				t.Fatalf("sso account with an AD ref must not receive a correlation-reached group: %+v", x)
			}
		}
	})
}

func TestMembership_incomplete_not_complete(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		ctx := context.Background()
		// The weak-DACL fact was never computed for mSec: it cannot be established, so it is omitted.
		if _, err := e.populate(t, e.adA, t1, adUser(mUser, nc1), adGroup(mSec, -2147483646, nil, mUser)); err != nil {
			t.Fatal(err)
		}
		m := e.membership(inventory.Ref{Connection: e.adA, Object: mUser}, authn.KindDirectory, "")
		g, err := m.GroupsOf(ctx, e.a.String(), mAcct)
		if err != nil {
			t.Fatal(err)
		}
		if g.Complete || len(g.Groups) != 0 {
			t.Fatalf("unknown eligibility: got %+v, want no groups and Complete=false", g)
		}
		// A group edge to an object the inventory never read.
		if err := e.exec(e.a, `INSERT INTO public.links (tenant_id, connection_id, source_guid, link_attr, target_guid)
			VALUES ($1::uuid, $2::uuid, $3::uuid, 'member', $4::uuid)`, e.a.String(), string(e.adA), mOuter, mUser); err != nil {
			t.Fatal(err)
		}
		if g, _ = m.GroupsOf(ctx, e.a.String(), mAcct); g.Complete || len(g.Groups) != 0 {
			t.Fatalf("group with no object row: got %+v", g)
		}
		// A failed read: unknown account, or wrong tenant, is an error with an empty incomplete answer.
		g, err = m.GroupsOf(ctx, e.a.String(), "dddddddd-0000-4000-8000-0000000000ff")
		if err == nil || g.Complete || len(g.Groups) != 0 {
			t.Fatalf("failed account read: got %+v err=%v", g, err)
		}
		g, err = m.GroupsOf(ctx, "not-a-tenant", mAcct)
		if err == nil || g.Complete {
			t.Fatalf("bad tenant: got %+v err=%v", g, err)
		}
		// A matched correlation whose connection has no completed evaluation has no as-of: incomplete.
		e.seed(t, e.a, inventory.Ref{Connection: e.adA, Object: mUser}, inventory.Ref{Connection: e.enA, Object: mEUser},
			"matched", "", "match, ad_sid, facts_as_of", "sid", sid, time.Now())
		if g, _ = m.GroupsOf(ctx, e.a.String(), mAcct); g.Complete {
			t.Fatalf("correlation without as-of must be incomplete: %+v", g)
		}
	})
}

func TestMembership_unbound_account_has_no_groups(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		m := inventory.NewMembership(e.db, acctSrc{mAcct: {ID: mAcct, Kind: authn.KindLocal, State: authn.AccountActive}}, e.r, nil)
		g, err := m.GroupsOf(context.Background(), e.a.String(), mAcct)
		if err != nil || !g.Complete || len(g.Groups) != 0 {
			t.Fatalf("got %+v err=%v", g, err)
		}
	})
}
