//go:build lab

package server_test

// T-1070: the group datasets (inventory.groups, inventory.group_members, inventory.users) against a REAL
// directory. T-0961 proved AC-19/20/21 on PostgreSQL with a hand-built model; here the model is the lab
// domain, read over LDAPS by the production connector, and the oracles are
//   - LDAP ground truth: `ldapsearch` run by a different client (inside the DC container for Samba) with
//     explicit member;range= pages, and the directory's own primaryGroupID values;
//   - tokenGroups: the DC's own transitive, primary-group-aware expansion, one read per account.
// The seed is lab/seed/generate.py (OU=GroupOracle, T-1070) + post-start.sh (primary groups).
//
// Run: make lab-up && make lab-test-groups   (Samba)       make windows-lab-test-groups (T-1533)   (Windows, windowslab tag)
// A missing lab is a test FAILURE, never a skip.
//
// Observation shape: the connector-side producer of Observation does not exist yet ("Not built" in
// blueprint, T-0326 note), so labObservations below is the test's stand-in for it. It flattens the OU tree
// (every object is a child of the NC head) because hierarchy is not what is under test.

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/connector/ad"
	adsid "github.com/skenzeriq/activediq/internal/directory/attr/sid"
	"github.com/skenzeriq/activediq/internal/directory/dn"
	"github.com/skenzeriq/activediq/internal/directory/inventory"
	"github.com/skenzeriq/activediq/internal/directory/inventory/invtest"
	"github.com/skenzeriq/activediq/internal/directory/ldapfilter"
	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/authz/authztest"
	"github.com/skenzeriq/activediq/internal/platform/report"
	"github.com/skenzeriq/activediq/internal/platform/secret"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/reportsql"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
	"github.com/skenzeriq/activediq/internal/testlab"
)

// labTarget is one directory the oracle runs against.
type labTarget struct {
	name    string
	sess    *ad.Session
	nc      string // naming-context DN
	managed string // OU=Managed,<nc>: the groups compared are the ones below it
	// ldapsearch runs the reference client with args (after the connection flags) and returns stdout.
	ldapsearch func(t *testing.T, args ...string) string
	// wantFSP: the target must hold foreign security principals among the oracle members (Windows).
	wantFSP bool
}

type labObj struct {
	dn, sam, class string
	guid           string
	sid            adsid.SID
	sidBytes       []byte
	uac            int64
	hasUAC         bool
	primaryRID     int64
	security       bool // groupType has the security bit; only security groups are in a token
	kind           inventory.Kind
	members        []string // DNs (groups), complete via ranged retrieval
}

func labAttr(t *testing.T, s *ad.Session, name string) ldapfilter.AttrName {
	t.Helper()
	a, err := ldapfilter.ParseAttrName(name, s.FilterSchema())
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func rdnOf(d string) string {
	for i := 0; i < len(d); i++ {
		if d[i] == '\\' {
			i++
		} else if d[i] == ',' {
			return d[:i]
		}
	}
	return d
}

func kindOf(classes []string) (inventory.Kind, string, bool) {
	has := func(c string) bool {
		return slices.ContainsFunc(classes, func(x string) bool { return strings.EqualFold(x, c) })
	}
	switch {
	case has("computer"):
		return inventory.KindComputer, "computer", true
	case has("group"):
		return inventory.KindGroup, "group", true
	case has("foreignSecurityPrincipal"):
		return inventory.KindFSP, "foreignSecurityPrincipal", true
	case has("user"):
		return inventory.KindUser, "user", true
	}
	return "", "", false
}

// readLab enumerates every security principal of the naming context and reads the full (ranged) member
// list of every group.
func readLab(t *testing.T, tg *labTarget) (head string, objs []*labObj) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	root, err := dn.Parse(tg.nc, dn.Strict)
	if err != nil {
		t.Fatal(err)
	}
	h, err := tg.sess.Read(ctx, dn.DNRef(root), []string{"objectGUID"}, ad.ReadOptions{})
	if err != nil {
		t.Fatalf("read NC head: %v", err)
	}
	hg, err := h.GUID()
	if err != nil {
		t.Fatal(err)
	}
	head = hg.String()
	oc := labAttr(t, tg.sess, "objectClass")
	f := ldapfilter.Or(ldapfilter.Eq(oc, ldapfilter.String("user")), ldapfilter.Eq(oc, ldapfilter.String("group")),
		ldapfilter.Eq(oc, ldapfilter.String("foreignSecurityPrincipal")))
	err = tg.sess.Search(ctx, ad.SearchRequest{Base: dn.DNRef(root), Scope: ad.ScopeSubtree, Filter: f,
		Attributes: []string{"objectGUID", "objectSid", "sAMAccountName", "userAccountControl", "primaryGroupID", "objectClass", "groupType"}},
		func(e *ad.Entry) error {
			k, cl, ok := kindOf(e.Strings("objectClass"))
			if !ok || len(e.Raw("objectSid")) != 1 {
				return nil
			}
			g, err := e.GUID()
			if err != nil {
				return err
			}
			sids, err := e.SIDs("objectSid")
			if err != nil || len(sids) != 1 {
				return fmt.Errorf("objectSid of %s: %v", e.DN, err)
			}
			o := &labObj{dn: e.DN, class: cl, kind: k, guid: g.String(), sid: sids[0], sidBytes: e.Raw("objectSid")[0]}
			if s := e.Strings("sAMAccountName"); len(s) == 1 {
				o.sam = s[0]
			}
			if v, ok, _ := e.Int32("userAccountControl"); ok {
				o.uac, o.hasUAC = int64(v), true
			}
			if v, ok, _ := e.Int32("groupType"); ok {
				o.security = v&-0x80000000 != 0
			}
			if v, ok, _ := e.Int32("primaryGroupID"); ok {
				o.primaryRID = int64(v)
			}
			objs = append(objs, o)
			return nil
		})
	if err != nil {
		t.Fatalf("enumerate: %v", err)
	}
	for _, o := range objs {
		if o.kind != inventory.KindGroup {
			continue
		}
		d, err := dn.Parse(o.dn, dn.Strict)
		if err != nil {
			t.Fatalf("group DN %q: %v", o.dn, err)
		}
		e, err := tg.sess.Read(ctx, dn.DNRef(d), []string{"member"}, ad.ReadOptions{})
		if err != nil {
			t.Fatalf("read members of %s: %v", o.dn, err)
		}
		o.members = e.Strings("member")
	}
	return head, objs
}

// labObservations is the stand-in for the connector-side Observation producer (see file comment).
func labObservations(head string, objs []*labObj) (accounts, groups []inventory.Observation, unresolved int) {
	byDN := map[string]*labObj{}
	groupByRID := map[int64]*labObj{}
	for _, o := range objs {
		byDN[strings.ToLower(o.dn)] = o
		if o.kind == inventory.KindGroup {
			if r, ok := o.sid.RID(); ok {
				groupByRID[int64(r)] = o
			}
		}
	}
	for _, o := range objs {
		ob := inventory.Observation{Object: inventory.GUID(o.guid), NC: inventory.GUID(head), Kind: o.kind, Class: o.class, State: inventory.ObjLive,
			Parent: inventory.GUID(head), Ancestry: []inventory.GUID{inventory.GUID(head)}, DN: o.dn, RDN: rdnOf(o.dn), SID: o.sidBytes, SAMAccountName: o.sam}
		if o.kind == inventory.KindUser || o.kind == inventory.KindComputer {
			u := o.uac
			ob.UserAccountControl = &u
			en := u&2 == 0
			ob.Enabled = &en
			p := o.primaryRID
			ob.PrimaryGroupID = &p
			if g := groupByRID[p]; g != nil {
				ob.PrimaryGroup = inventory.GUID(g.guid)
			}
		}
		if o.kind != inventory.KindGroup {
			accounts = append(accounts, ob)
			continue
		}
		ob.MembersComplete = true
		for _, m := range o.members {
			if t := byDN[strings.ToLower(m)]; t != nil {
				ob.Members = append(ob.Members, inventory.GUID(t.guid))
			} else {
				unresolved++
			}
		}
		groups = append(groups, ob)
	}
	return accounts, groups, unresolved
}

// rangedCount counts member values with the reference client and explicit member;range= pages.
func rangedCount(t *testing.T, tg *labTarget, groupDN string) int {
	t.Helper()
	n := 0
	for lo := 0; ; lo += 1500 {
		// the filter must be explicit: ldapsearch otherwise takes the first attribute for it
		out := tg.ldapsearch(t, "-b", groupDN, "-s", "base", "(objectClass=*)", fmt.Sprintf("member;range=%d-%d", lo, lo+1499))
		label := ""
		for _, l := range strings.Split(out, "\n") {
			if strings.HasPrefix(l, "member;range=") {
				n++
				label, _, _ = strings.Cut(l, ":")
			} else if strings.HasPrefix(l, "member:") {
				t.Fatalf("%s: server returned an unranged member value although range was requested", groupDN)
			}
		}
		if strings.HasSuffix(label, "-*") || label == "" {
			return n
		}
		if lo > 200000 {
			t.Fatalf("%s: ranged retrieval did not terminate", groupDN)
		}
	}
}

func scopeHead(c inventory.ConnectionID, head string) authz.ReadScope {
	return authztest.ReadScope(authz.ScopeGrant{Include: []authz.ScopeTerm{{Kind: authz.TermNamingContext, Connection: labObjectID(string(c)), Root: labObjectID(head)}}})
}

// runGroupOracle is the whole check, shared by the Samba and Windows targets.
func runGroupOracle(t *testing.T, tg *labTarget) {
	t.Helper()
	t0 := time.Now()
	head, objs := readLab(t, tg)
	t.Logf("[%s] read %d principals + ranged member lists over LDAPS in %v", tg.name, len(objs), time.Since(t0).Round(time.Millisecond))

	byName := map[string]*labObj{}
	byGUID := map[string]*labObj{}
	groupByRID := map[int64]*labObj{} // one domain: a RID names one group
	for _, o := range objs {
		byGUID[o.guid] = o
		if o.kind == inventory.KindGroup {
			byName[strings.ToLower(o.sam)] = o
			groupByRID[int64(ridOf(o.sid))] = o
		}
	}
	grp := func(name string) *labObj {
		g := byName[strings.ToLower(name)]
		if g == nil {
			t.Fatalf("lab group %s is not seeded (make lab-rebuild: the T-1070 seed is OU=GroupOracle)", name)
		}
		return g
	}
	top, mid, low := grp("GG-Oracle-Top"), grp("GG-Oracle-Mid"), grp("GG-Oracle-Low")
	g1501, g6000 := grp("GG-Oracle-1501"), grp("GG-Oracle-6000")
	prim, only, empty := grp("GG-Oracle-Primary"), grp("GG-Oracle-PrimaryOnly"), grp("GG-Empty")

	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := invtest.Setup(t, s)
		reg := e.Registry(t)
		c := e.AdA
		now := time.Now()
		observed := now.Add(-time.Hour)
		accounts, groups, unresolved := labObservations(head, objs)
		t.Logf("[%s] %d accounts, %d groups; %d member DNs without a principal in the NC (FSPs on Samba)", tg.name, len(accounts), len(groups), unresolved)

		start := time.Now()
		pending := []inventory.Observation{{Object: inventory.GUID(head), NC: inventory.GUID(head), Kind: inventory.KindOther, Class: "domainDNS", State: inventory.ObjLive}}
		flush := func(at time.Time) {
			for len(pending) > 0 {
				n := min(len(pending), 1000)
				if _, err := e.Populate(t, c, at, pending[:n]...); err != nil {
					t.Fatal(err)
				}
				pending = pending[n:]
			}
		}
		pending = append(pending, accounts...)
		flush(observed)
		if err := e.D.ExecOwner(context.Background(), "ANALYZE"); err != nil { // see Test_group_member_counts_at_scale
			t.Fatal(err)
		}
		pending = groups
		flush(observed.Add(time.Minute))
		if err := e.D.ExecOwner(context.Background(), "ANALYZE"); err != nil {
			t.Fatal(err)
		}
		t.Logf("[%s] TIMING populate of %d objects (edges + closure refresh): %v", tg.name, len(accounts)+len(groups), time.Since(start).Round(time.Millisecond))

		scope := scopeHead(c, head)
		start = time.Now()
		gres := labRun(t, e, reg, hQuery{dataset: inventory.DatasetGroups, scope: scope, now: now,
			cols: []report.ColumnID{"sam_account_name", "has_members", "direct_members", "effective_members", "primary_group_members"}})
		t.Logf("[%s] TIMING inventory.groups (%d rows, both counts): %v", tg.name, len(gres.rows), time.Since(start).Round(time.Millisecond))
		start = time.Now()
		mres := labRun(t, e, reg, hQuery{dataset: inventory.DatasetGroupMembers, cols: gmCols, scope: scope, now: now})
		t.Logf("[%s] TIMING inventory.group_members (%d rows): %v", tg.name, len(mres.rows), time.Since(start).Round(time.Millisecond))

		// ---- acceptance 1: effective members == tokenGroups, once each --------------------------------
		if len(mres.order) != len(mres.rows) {
			t.Errorf("group_members returned %d rows for %d distinct (group, member) keys: a member appears more than once", len(mres.order), len(mres.rows))
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()
		start = time.Now()
		token := map[string]map[string]bool{} // account guid -> group SIDs of its token
		for _, o := range objs {
			if o.kind != inventory.KindUser && o.kind != inventory.KindComputer {
				continue
			}
			d, err := dn.Parse(o.dn, dn.Strict)
			if err != nil {
				t.Fatal(err)
			}
			en, err := tg.sess.Read(ctx, dn.DNRef(d), []string{"tokenGroups"}, ad.ReadOptions{})
			if err != nil {
				t.Fatalf("tokenGroups of %s: %v", o.dn, err)
			}
			sids, err := en.SIDs("tokenGroups")
			if err != nil {
				t.Fatal(err)
			}
			m := make(map[string]bool, len(sids))
			for _, x := range sids {
				m[x.String()] = true
			}
			token[o.guid] = m
		}
		t.Logf("[%s] tokenGroups oracle: %d accounts read in %v", tg.name, len(token), time.Since(start).Round(time.Millisecond))

		memberRows := func(g *labObj) (accts map[string]bool, rows map[string]map[report.ColumnID]report.Cell) {
			accts, rows = map[string]bool{}, map[string]map[report.ColumnID]report.Cell{}
			for k, r := range mres.rows {
				gg, mm, _ := strings.Cut(k, "|")
				if gg != g.guid {
					continue
				}
				rows[mm] = r
				if mk := cellStr(r, "member_kind"); mk == "user" || mk == "computer" {
					accts[mm] = true
				}
			}
			return accts, rows
		}
		compared, accountsChecked, distribution := 0, 0, 0
		for _, g := range objs {
			if g.kind != inventory.KindGroup || !strings.HasSuffix(strings.ToLower(g.dn), strings.ToLower(tg.managed)) {
				continue
			}
			// oracle 1 (security groups): the DC's own token. Distribution groups are never in a token.
			// oracle 2 (every group): a walk over the LDAP member values plus primaryGroupID, cycles cut.
			want := map[string]bool{}
			if g.security {
				for guid, tok := range token {
					if tok[g.sid.String()] {
						want[guid] = true
					}
				}
				if walk := ldapClosure(objs, g); !slices.Equal(sortedKeys(walk), sortedKeys(want)) {
					t.Errorf("group %s: the LDAP member walk (%d accounts) disagrees with tokenGroups (%d): the oracles differ", g.sam, len(walk), len(want))
				}
			} else {
				want = ldapClosure(objs, g)
				distribution++
			}
			got, _ := memberRows(g)
			if gr := gres.rows[g.guid]; cellStr(gr, "effective_members") == "" {
				t.Errorf("group %s has no row in inventory.groups", g.sam)
			}
			if !slices.Equal(sortedKeys(got), sortedKeys(want)) {
				t.Errorf("group %s: inventory.group_members has %d account members, tokenGroups says %d\n only in dataset: %v\n only in tokenGroups: %v",
					g.sam, len(got), len(want), firstN(minus(got, want), 5), firstN(minus(want, got), 5))
			}
			compared++
			accountsChecked += len(want)
		}
		t.Logf("[%s] %d groups under %s compared (%d distribution groups against the LDAP walk, the rest against tokenGroups; %d account memberships)", tg.name, compared, tg.managed, distribution, accountsChecked)
		if compared < 100 || accountsChecked < 5000 {
			t.Errorf("only %d groups / %d memberships compared: the lab is not seeded at the standard tier", compared, accountsChecked)
		}

		// the nested family, by name: three levels, a cycle, a disabled member, an account in two branches
		topAccts, topRows := memberRows(top)
		for _, name := range []string{"GG-Oracle-Mid", "GG-Oracle-Low"} {
			if _, ok := topRows[grp(name).guid]; !ok {
				t.Errorf("%s is not an effective member of Top", name)
			}
		}
		if r := topRows[top.guid]; r == nil || cellStr(r, "edge_kind") != "cycle" {
			t.Errorf("Top → Mid → Low → Top: the row (Top, Top) = %v, want edge_kind cycle", r)
		}
		wantDisabled := 0
		for guid := range topAccts {
			o := byGUID[guid]
			if o.uac&2 != 0 {
				wantDisabled++
				if got := cellStr(topRows[guid], "member_enabled"); got != "false" {
					t.Errorf("disabled member %s: member_enabled = %q, want false", o.sam, got)
				}
			}
		}
		if wantDisabled != 2 {
			t.Errorf("Top has %d disabled effective members, the seed puts 2", wantDisabled)
		}
		if len(topAccts) < 4 { // 2 users + 2 disabled + 1 computer, one user in two branches
			t.Errorf("Top has %d account members, want at least 5 (users, disabled, a computer)", len(topAccts))
		}
		for _, g := range []*labObj{mid, low} {
			a, _ := memberRows(g)
			if len(a) != len(topAccts) {
				t.Errorf("%s: %d effective accounts, Top has %d (a cycle makes them one set)", g.sam, len(a), len(topAccts))
			}
		}

		// FSP: Windows only (Samba cannot hold a foreign security principal)
		fsps := 0
		for _, o := range objs {
			if o.kind == inventory.KindFSP {
				fsps++
				for _, r := range mres.rows {
					if strings.EqualFold(cellStr(r, "member_sid"), o.sid.String()) && cellStr(r, "member_unresolved") != "true" {
						t.Errorf("FSP %s appears resolved in group_members", o.sid)
					}
				}
			}
		}
		if tg.wantFSP && fsps == 0 {
			t.Errorf("[%s] no foreign security principal in the lab: the Windows seed must add one to GG-Oracle-Top", tg.name)
		}
		if !tg.wantFSP {
			t.Logf("[%s] %d FSPs in the directory; foreign security principals are exercised by the Windows target only", tg.name, fsps)
		}

		// ---- acceptance 2: 1,501 and 6,000 member groups vs ranged ldapsearch -----------------------
		for _, tc := range []struct {
			g    *labObj
			want int
		}{{g1501, 1501}, {g6000, 6000}} {
			start := time.Now()
			ref := rangedCount(t, tg, tc.g.dn)
			t.Logf("[%s] TIMING reference ranged ldapsearch of %s: %v", tg.name, tc.g.sam, time.Since(start).Round(time.Millisecond))
			r := gres.rows[tc.g.guid]
			d, ef := cellStr(r, "direct_members"), cellStr(r, "effective_members")
			if ref != tc.want || d != fmt.Sprint(ref) || ef != fmt.Sprint(ref) {
				t.Errorf("%s: ldapsearch ranged = %d, dataset direct = %s effective = %s, seed says %d", tc.g.sam, ref, d, ef, tc.want)
			}
		}

		// ---- acceptance 3: primary group ----------------------------------------------------------------
		ures := labRun(t, e, reg, hQuery{dataset: inventory.DatasetUsers, cols: []report.ColumnID{"sam_account_name", "primary_group", "primary_group_id"}, scope: scope, now: now})
		nonDefault := 0
		for _, o := range objs {
			if o.kind != inventory.KindUser || o.primaryRID == 513 {
				continue
			}
			pg := groupByRID[o.primaryRID]
			if pg == nil {
				t.Errorf("user %s: primaryGroupID %d names no group in the lab", o.sam, o.primaryRID)
				continue
			}
			nonDefault++
			if got := cellStr(ures.rows[o.guid], "primary_group"); got != pg.sam {
				t.Errorf("user %s: primaryGroupID %d: inventory.users primary_group = %q, want %q", o.sam, o.primaryRID, got, pg.sam)
			}
		}
		if nonDefault < 3 {
			t.Errorf("%d users with primaryGroupID != 513 in the lab, the seed puts 3", nonDefault)
		}
		// the group whose only members come through primaryGroupID is not "Groups Without Members"
		if len(only.members) != 0 {
			t.Fatalf("seed: %s has %d member values; it must be primary-group-only", only.sam, len(only.members))
		}
		if cellStr(gres.rows[only.guid], "has_members") != "true" || cellStr(gres.rows[only.guid], "primary_group_members") != "1" {
			t.Errorf("%s: has_members = %q, primary_group_members = %q, want true and 1", only.sam, cellStr(gres.rows[only.guid], "has_members"), cellStr(gres.rows[only.guid], "primary_group_members"))
		}
		if cellStr(gres.rows[prim.guid], "primary_group_members") != "2" {
			t.Errorf("%s: primary_group_members = %q, want 2", prim.sam, cellStr(gres.rows[prim.guid], "primary_group_members"))
		}
		if cellStr(gres.rows[empty.guid], "has_members") != "false" { // positive control: the report can still say "empty"
			t.Errorf("GG-Empty: has_members = %q, want false", cellStr(gres.rows[empty.guid], "has_members"))
		}
	})
}

// ldapClosure is the accounts that are effective members of g by the directory's own data: member values,
// nested groups followed with a visited set, and primaryGroupID of every group reached.
func ldapClosure(objs []*labObj, g *labObj) map[string]bool {
	byDN := map[string]*labObj{}
	for _, o := range objs {
		byDN[strings.ToLower(o.dn)] = o
	}
	primaryOf := map[int64][]string{}
	for _, o := range objs {
		if o.kind == inventory.KindUser || o.kind == inventory.KindComputer {
			primaryOf[o.primaryRID] = append(primaryOf[o.primaryRID], o.guid)
		}
	}
	out, seen := map[string]bool{}, map[string]bool{}
	stack := []*labObj{g}
	for len(stack) > 0 {
		cur := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if seen[cur.guid] {
			continue
		}
		seen[cur.guid] = true
		for _, id := range primaryOf[int64(ridOf(cur.sid))] {
			out[id] = true
		}
		for _, m := range cur.members {
			switch t := byDN[strings.ToLower(m)]; {
			case t == nil:
			case t.kind == inventory.KindGroup:
				stack = append(stack, t)
			case t.kind == inventory.KindUser || t.kind == inventory.KindComputer:
				out[t.guid] = true
			}
		}
	}
	return out
}

func ridOf(s adsid.SID) uint32 { r, _ := s.RID(); return r }

func minus(a, b map[string]bool) []string {
	var out []string
	for k := range a {
		if !b[k] {
			out = append(out, k)
		}
	}
	slices.Sort(out)
	return out
}

func firstN(s []string, n int) []string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// sambaTarget opens the per-worktree Samba lab (lab/.lab.env).
func sambaTarget(t *testing.T) *labTarget {
	t.Helper()
	env := testlab.Load(t)
	pw := env.Values["LAB_SVC_PASSWORD"]
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	s, err := ad.Open(ctx, ad.Config{Servers: []string{"localhost:" + env.Port}, RootCAs: env.Pool, PageSize: 500,
		Credential: ad.Credential{BindName: "svc-activediq@lab.activediq.test", Password: secret.FromBytes([]byte(pw))}})
	if err != nil {
		t.Fatalf("open lab: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return &labTarget{name: "samba", sess: s, nc: "DC=lab,DC=activediq,DC=test", managed: "OU=Managed,DC=lab,DC=activediq,DC=test",
		ldapsearch: func(t *testing.T, args ...string) string {
			t.Helper()
			// the group DN is a positional argument, never interpolated into the shell text
			// the password arrives on stdin, never in the host's environment or argv
			sh := `IFS= read -r PW; exec ldapsearch -H ldaps://dc1.lab.activediq.test:636 -x -D svc-activediq@lab.activediq.test -w "$PW" -LLL -o ldif-wrap=no "$@"`
			cmd := exec.Command("docker", append([]string{"exec", "-i", "-e", "LDAPTLS_CACERT=/var/lib/samba/lab-tls/ca.pem", env.Container, "sh", "-c", sh, "sh"}, args...)...)
			cmd.Stdin = strings.NewReader(pw + "\n")
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			out, err := cmd.Output()
			if err != nil {
				t.Fatalf("ldapsearch in the DC container: %v\n%s", err, stderr.String())
			}
			return string(out)
		}}
}

func TestLabGroupDatasetsMatchLDAPAndTokenGroupsSamba(t *testing.T) {
	runGroupOracle(t, sambaTarget(t))
}

func labObjectID(s string) authz.ObjectID {
	id, err := authz.ParseObjectID(s)
	if err != nil {
		panic(err)
	}
	return id
}

type hQuery struct {
	dataset report.DatasetID
	cols    []report.ColumnID
	scope   authz.ReadScope
	now     time.Time
}

type hResult struct {
	rows  map[string]map[report.ColumnID]report.Cell // by lower-case GUID
	order []string
}

// labRun resolves, compiles and executes one report over a dataset as tenant A, collecting every row.
func labRun(t *testing.T, e *invtest.Env, reg *reportsql.Registry, q hQuery) hResult {
	t.Helper()
	src := slices.IndexFunc(inventory.Datasets(), func(d report.Dataset) bool { return d.ID == q.dataset })
	ds, ok := reg.Dataset(q.dataset)
	if src < 0 || !ok {
		t.Fatalf("dataset %s", q.dataset)
	}
	def := report.Definition{ID: "t1070-01", Version: 1, Category: report.CategoryUsers, Title: "T-1070", Dataset: q.dataset, Columns: q.cols,
		Presets: []report.Preset{{ID: "all"}}}
	rq, err := report.Resolve(def, "all", report.RunParams{}, inventory.Datasets()[src])
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	rowsQ, err := reportsql.Compile(rq, ds, q.scope, reportsql.Inputs{Now: q.now})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	res := hResult{rows: map[string]map[report.ColumnID]report.Cell{}}
	err = e.Tx(t, e.A, func(ctx context.Context, tx store.Tx) error {
		_, err := reportsql.Exec(ctx, tx, rowsQ, 500, func(_ context.Context, rows []report.Row) error {
			for _, row := range rows {
				k := strings.ToLower(row.Key)
				m := map[report.ColumnID]report.Cell{}
				for i, c := range q.cols {
					m[c] = row.Cells[i]
				}
				res.rows[k] = m
				res.order = append(res.order, k)
			}
			return nil
		})
		return err
	})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	return res
}

// cellStr is the typed text of a cell without its tag.
func cellStr(r map[report.ColumnID]report.Cell, c report.ColumnID) string {
	s := invtest.CellKey(r[c])
	if i := strings.Index(s, ":"); i >= 0 {
		return s[i+1:]
	}
	return s
}

var gmCols = []report.ColumnID{"group_name", "member_name", "member_kind", "edge_kind", "depth", "via_path", "finding", "member_enabled", "member_unresolved", "member_sid"}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}
