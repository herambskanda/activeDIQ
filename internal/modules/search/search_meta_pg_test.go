package search_test

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/directory/attr/filetime"
	"github.com/skenzeriq/activediq/internal/directory/connection"
	"github.com/skenzeriq/activediq/internal/directory/inventory"
	"github.com/skenzeriq/activediq/internal/modules/search"
	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/reportsql"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
)

// T-1097: the inline metadata of a hit. The world has a domain policy of 42 days maximum password age and 30
// minutes lockout duration; "now" is fixed at 09:22 on 2026-11-01.

var now1097 = time.Date(2026, 11, 1, 9, 22, 0, 0, time.UTC)

func uacObs(o inventory.Observation, uac int64, dis bool) inventory.Observation {
	o.UserAccountControl = &uac
	o.InputsRead = inventory.InputsRead(15)
	o.SID = sidBytes(1100 + uint32(o.Object[len(o.Object)-1]))
	o.PwdLastSet = now1097.Add(-24 * time.Hour)
	if dis {
		no := false
		o.Enabled = &no
	}
	return o
}

func (w *world) policy(t *testing.T, maxAge, lock *filetime.Interval, psosRead bool) {
	t.Helper()
	err := w.db.WithTenant(context.Background(), w.tid, func(ctx context.Context, tx store.Tx) error {
		dp := inventory.DomainPolicy{MaxPwdAge: maxAge, LockoutDuration: lock}
		if psosRead {
			dp.PSOsReadAt = now1097
		}
		return inventory.PolicyWriter{}.SetDomainPolicy(ctx, tx, inventory.ConnectionID(w.conn), inventory.GUID(gDom), dp, now1097)
	})
	if err != nil {
		t.Fatal(err)
	}
}

func dayIvl(n int64) *filetime.Interval { return &filetime.Interval{Ticks: n * 86400 * 10_000_000} }
func minIvl(n int64) *filetime.Interval { return &filetime.Interval{Ticks: n * 60 * 10_000_000} }

func (w *world) askAt(t *testing.T, sc authz.ReadScope, text string) search.Result {
	t.Helper()
	svc, _ := w.service(t, sc)
	svc.Now = func() time.Time { return now1097 }
	res, err := svc.Search(context.Background(), search.Call{Tenant: w.tid, Text: text, Limit: 50})
	if err != nil {
		t.Fatalf("search %q: %v", text, err)
	}
	return res
}

func kinds(h search.Hit) []search.ChipKind {
	out := []search.ChipKind{}
	for _, c := range h.Status {
		out = append(out, c.Kind)
	}
	return out
}

func byName(t *testing.T, g search.Group, name string) search.Hit {
	t.Helper()
	for _, h := range g.Items {
		if h.DisplayName == name {
			return h
		}
	}
	t.Fatalf("no hit %q in %v", name, names(g))
	return search.Hit{}
}

const uacNormal = 512

// AC1 and AC2: each chip lists exactly the matching values with the contract's timestamps, and an unread
// input shows no chip at all.
func Test_status_chips_table(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		w := newWorld(t, s)
		w.policy(t, dayIvl(42), minIvl(30), true)
		u := func(i int, name, sam string) inventory.Observation {
			return obj(inventory.KindUser, "user", guid(1, i), gOUA, name, sam)
		}
		locked := uacObs(u(1, "Chip Locked", "chiplocked"), uacNormal, false)
		locked.LockoutTime = time.Date(2026, 11, 1, 9, 12, 0, 0, time.UTC)
		disabled := uacObs(u(2, "Chip Disabled", "chipdisabled"), uacNormal|2, true)
		expired := uacObs(u(3, "Chip Expired", "chipexpired"), uacNormal, false)
		expired.PwdLastSet = now1097.Add(-50 * 24 * time.Hour)
		soon := uacObs(u(4, "Chip Soon", "chipsoon"), uacNormal, false)
		soon.PwdLastSet = now1097.Add(-39 * 24 * time.Hour)
		far := uacObs(u(5, "Chip Far", "chipfar"), uacNormal, false) // 41 days left: outside the warning window
		acct := uacObs(u(6, "Chip Acct", "chipacct"), uacNormal, false)
		acct.AccountExpires = time.Date(2027, 3, 31, 0, 0, 0, 0, time.UTC)
		deleted := u(7, "Chip Deleted", "chipdeleted")
		deleted.State = inventory.ObjDeleted
		tier0 := uacObs(u(8, "Chip Tier", "chiptier"), uacNormal, false)
		healthy := uacObs(u(9, "Chip Healthy", "chiphealthy"), uacNormal, false)
		// Unknown inputs: nothing was read for this user. No chip, and no "not locked" either.
		unread := u(10, "Chip Unread", "chipunread")
		w.populate(t, locked, disabled, expired, soon, far, acct, deleted, tier0, healthy, unread)
		w.designate(t, guid(1, 8))

		g := group(w.askAt(t, w.tech(), "Chip"), reportsql.TypeUser)
		if len(g.Items) != 10 {
			t.Fatalf("hits = %v", names(g))
		}
		want := map[string][]search.ChipKind{
			"Chip Locked":   {search.ChipLocked},
			"Chip Disabled": {search.ChipDisabled},
			"Chip Expired":  {search.ChipPasswordExpired},
			"Chip Soon":     {search.ChipPasswordExpiresInDays},
			"Chip Far":      {},
			"Chip Acct":     {search.ChipAccountExpires},
			"Chip Deleted":  {search.ChipDeleted},
			"Chip Tier":     {search.ChipTier0},
			"Chip Healthy":  {},
			"Chip Unread":   {},
		}
		for name, k := range want {
			if got := kinds(byName(t, g, name)); !slices.Equal(got, k) {
				t.Errorf("%s chips = %v, want %v", name, got, k)
			}
		}
		if c := byName(t, g, "Chip Locked").Status[0]; !c.At.Equal(time.Date(2026, 11, 1, 9, 12, 0, 0, time.UTC)) {
			t.Errorf("locked at = %v", c.At)
		}
		if c := byName(t, g, "Chip Soon").Status[0]; c.Days == nil || *c.Days != 3 {
			t.Errorf("days = %v", c.Days)
		}
		if c := byName(t, g, "Chip Acct").Status[0]; !c.At.Equal(time.Date(2027, 3, 31, 0, 0, 0, 0, time.UTC)) {
			t.Errorf("account expires at = %v", c.At)
		}

		// A domain whose password policy was never read: the policy-dependent chips go away, never become false.
		w.policy(t, nil, nil, false)
		g = group(w.askAt(t, w.tech(), "Chip"), reportsql.TypeUser)
		for _, name := range []string{"Chip Locked", "Chip Expired", "Chip Soon"} {
			if k := kinds(byName(t, g, name)); len(k) != 0 {
				t.Errorf("%s with no policy read has chips %v", name, k)
			}
		}
		if k := kinds(byName(t, g, "Chip Disabled")); !slices.Equal(k, []search.ChipKind{search.ChipDisabled}) {
			t.Errorf("a stored flag still shows: %v", k)
		}
	})
}

func (w *world) designate(t *testing.T, g string) {
	t.Helper()
	err := w.db.WithTenant(context.Background(), w.tid, func(ctx context.Context, tx store.Tx) error {
		_, err := inventory.Writer{}.Designate(ctx, tx, inventory.ConnectionID(w.conn), inventory.GUID(g), "test")
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}

// AC3: two people called Priya Raman are told apart by DN, disambiguator and (across domains) domain; the
// domain is empty when the permitted answer holds one domain.
func Test_same_name_is_distinguishable(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		w := newWorld(t, s)
		a := obj(inventory.KindUser, "user", guid(1, 1), gOUA, "Priya Raman", "praman")
		b := obj(inventory.KindUser, "user", guid(1, 2), gOUB, "Priya Raman", "praman2")
		a.Attributes = map[string]any{"title": "Analyst", "physicalDeliveryOfficeName": "London"}
		b.Attributes = map[string]any{"department": "Finance"}
		other := obj(inventory.KindUser, "user", guid(1, 3), gOUB, "Priya Raman", "praman3")
		other.DN = "CN=Priya Raman,OU=B,DC=emea,DC=example,DC=test"
		w.populate(t, a, b, other)

		g := group(w.askAt(t, w.admin(), "Priya Raman"), reportsql.TypeUser)
		if len(g.Items) != 3 {
			t.Fatalf("hits %v", names(g))
		}
		seen := map[string]bool{}
		for _, h := range g.Items {
			key := h.DN + "|" + h.Domain
			if seen[key] {
				t.Errorf("two hits are not distinguishable: %s", key)
			}
			seen[key] = true
			if h.Domain == "" {
				t.Errorf("domain missing on %s although the answer spans two", h.DN)
			}
		}
		for _, h := range g.Items {
			switch h.SAMAccountName {
			case "praman":
				if h.Title != "Analyst" || h.Office != "London" || h.Department != "" {
					t.Errorf("disambiguator a: %+v", h)
				}
			case "praman2":
				if h.Title != "" || h.Department != "Finance" {
					t.Errorf("disambiguator b: %+v", h)
				}
			}
		}
		// A caller who can see only one domain gets no domain on any hit.
		single := group(w.askAt(t, w.tech(), "Priya Raman"), reportsql.TypeUser)
		if len(single.Items) != 1 || single.Items[0].Domain != "" || single.Items[0].DN == "" {
			t.Errorf("single-domain answer: %+v", single.Items)
		}
	})
}

// AC4 (service half) and AC5: hostile text comes back byte for byte; nothing in a hit names another object.
func Test_hostile_values_verbatim_and_nothing_outside_scope(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		w := newWorld(t, s)
		long := strings.Repeat("W", 200)
		h := obj(inventory.KindUser, "user", guid(1, 1), gOUA, "Hostile Person", "hostile")
		h.DN = `CN=Hostile\, <b>Person</b>\=*)(cn=*,OU=A,DC=corp,DC=example,DC=test`
		h.Attributes = map[string]any{"title": "<script>alert(1)</script>*)(uid=*", "department": long}
		hidden := obj(inventory.KindUser, "user", guid(1, 2), gOUB, "Hidden Manager Zed", "hmzed")
		h.Attributes["manager"] = hidden.DN // a stored manager DN of a hidden object must not surface
		w.populate(t, h, hidden)
		got := byName(t, group(w.askAt(t, w.tech(), "Hostile Person"), reportsql.TypeUser), "Hostile Person")
		if got.DN != h.DN || got.Title != "<script>alert(1)</script>*)(uid=*" || got.Department != long {
			t.Errorf("not verbatim: %+v", got)
		}
		all := strings.Join([]string{got.DN, got.Title, got.Office, got.Department, got.Domain, got.SAMAccountName, got.Mail}, "|")
		if strings.Contains(all, "Hidden") || strings.Contains(all, "hmzed") {
			t.Errorf("a field reveals a hidden object: %s", all)
		}
		for _, c := range got.Status {
			if c.Kind == "" {
				t.Errorf("empty chip")
			}
		}
	})
}

// AC2: the chip rules are the report derivation's. The search code holds no copy of a policy rule, and the
// status read goes through the inventory.users dataset.
func Test_no_second_copy_of_the_derivation(t *testing.T) {
	forbidden := regexp.MustCompile(`(?i)lockout_duration|max_pwd_age|lockoutDuration|maxPwdAge|inventory_psos|inventory_domain_policies|pso_applies|& ?65536|& ?262144|14336`)
	for _, f := range []string{"search.go", "present.go", "cursor.go", "../../directory/inventory/search_meta.go"} {
		b, err := os.ReadFile(filepath.FromSlash(f))
		if err != nil {
			t.Fatal(err)
		}
		if m := forbidden.Find(b); m != nil {
			t.Errorf("%s restates a derivation rule (%q): use the inventory.users dataset", f, m)
		}
	}
	b, _ := os.ReadFile("../../directory/inventory/search_meta.go")
	if !strings.Contains(string(b), "usersDataset()") || !strings.Contains(string(b), "reportsql.Compile(") {
		t.Errorf("search_meta.go must derive through the users dataset")
	}
}

// Cloud-only: Entra rows, fixtures only (Samba has no Entra). Asked at the metadata port, which is only ever
// given admitted hits.
func Test_cloud_only_chip(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		w := newWorld(t, s)
		c, err := connection.NewRegistry(w.db).Create(context.Background(), w.tid, connection.New{Kind: connection.KindEntraTenant, DisplayName: "e", CredentialID: "22222222-2222-4222-8222-222222222222"})
		if err != nil {
			t.Fatal(err)
		}
		ent := inventory.ConnectionID(c.ID)
		yes, no := true, false
		user := func(i int, sync *bool) inventory.Observation {
			return inventory.Observation{Object: inventory.GUID(guid(5, i)), Kind: inventory.KindUser, Class: "user", State: inventory.ObjActive,
				OnPremisesSyncEnabled: sync, DisplayName: "E"}
		}
		group := func(i int, sync *bool, read, mgd bool) inventory.Observation {
			return inventory.Observation{Object: inventory.GUID(guid(6, i)), Kind: inventory.KindGroup, Class: "group", State: inventory.ObjActive,
				OnPremisesSyncEnabled: sync, OnPremisesSyncEnabledRead: read, CloudManaged: mgd}
		}
		obs := []inventory.Observation{user(1, nil), user(2, &yes), user(3, &no), group(1, nil, true, false), group(2, nil, false, false), group(3, &yes, true, false), group(4, nil, true, true)}
		err = w.db.WithTenant(context.Background(), w.tid, func(ctx context.Context, tx store.Tx) error {
			_, err := w.pop.Populate(ctx, tx, ent, base, obs)
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		want := map[string]bool{guid(5, 1): true, guid(5, 2): false, guid(5, 3): true, guid(6, 1): true, guid(6, 2): false, guid(6, 3): false, guid(6, 4): false}
		var hits []reportsql.SearchHit
		for g := range want {
			ty := reportsql.TypeUser
			if g[:2] == "06" {
				ty = reportsql.TypeGroup
			}
			hits = append(hits, reportsql.SearchHit{Group: ty, Connection: string(ent), Object: g})
		}
		err = w.db.WithTenant(context.Background(), w.tid, func(ctx context.Context, tx store.Tx) error {
			meta, err := w.ix.SearchMetadata(ctx, tx, w.tid, w.admin(), now1097, hits)
			if err != nil {
				return err
			}
			for g, exp := range want {
				if got := meta[inventory.SearchRef{Connection: string(ent), Object: g}].Status.CloudOnly; got != exp {
					t.Errorf("%s cloudOnly = %v, want %v", g, got, exp)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	})
}
