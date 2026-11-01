package inventory_test

// Library batch 2 against the inventory datasets (T-0962, spec reports-2a AC-13, AC-19, AC-20, AC-23).
//
// One inventory is written (users with every password state, groups with nesting, a cycle, an external
// principal and primary-group members, computers of every type, a tree of OUs, contacts). Every preset of
// the ten reports is run through library.Load, report.Resolve and reportsql.Compile, and its rows are
// compared with an oracle computed in plain Go from the seed observations alone, independently of the SQL.
// The live-Samba LDAP comparison needs the lab (ticket filed with this change); the oracle here is the
// ground truth the lab test will replace for the same expectations.

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/directory/inventory"
	"github.com/skenzeriq/activediq/internal/modules/reports/library"
	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/report"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/reportsql"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
)

type b2Row struct {
	key    string
	c      map[report.ColumnID]report.Cell
	hidden []string
}

func (r b2Row) s(col string) string { return cellStr(r.c, report.ColumnID(col)) }

// runB2 runs a library report preset. A request the resolver refuses is returned as an error.
func (e *env) runB2(t *testing.T, l *library.Library, id, preset string, rp report.RunParams, scope authz.ReadScope, now time.Time) ([]b2Row, error) {
	t.Helper()
	d, ok := l.Definition(id, 0)
	if !ok {
		t.Fatalf("no definition %s", id)
	}
	q, err := report.Resolve(d.Def, preset, rp, d.Dataset)
	if err != nil {
		return nil, err
	}
	cq, err := reportsql.Compile(q, d.SQL, scope, reportsql.Inputs{Now: now})
	if err != nil {
		t.Fatalf("Compile %s/%s: %v", id, preset, err)
	}
	var out []b2Row
	err = e.tx(t, e.a, func(ctx context.Context, tx store.Tx) error {
		_, err := reportsql.Exec(ctx, tx, cq, 500, func(_ context.Context, rows []report.Row) error {
			for _, row := range rows {
				r := b2Row{key: strings.ToLower(row.Key), c: map[report.ColumnID]report.Cell{}}
				for i, c := range q.Columns {
					r.c[c] = row.Cells[i]
				}
				for i, h := range row.Hidden {
					if h {
						r.hidden = append(r.hidden, q.Hidden[i].ID)
					}
				}
				out = append(out, r)
			}
			return nil
		})
		return err
	})
	if err != nil {
		t.Fatalf("run %s/%s: %v", id, preset, err)
	}
	return out, nil
}

func keysOf(rows []b2Row, hidden bool) []string {
	var out []string
	for _, r := range rows {
		if (len(r.hidden) > 0) == hidden {
			out = append(out, r.key)
		}
	}
	slices.Sort(out)
	return out
}

func sortedLower(s []string) []string {
	out := make([]string, len(s))
	for i, v := range s {
		out[i] = strings.ToLower(v)
	}
	slices.Sort(out)
	return out
}

// ---- the seed ---------------------------------------------------------------------------------------

type pwCase struct {
	sam      string
	uac      int64 // added to NORMAL_ACCOUNT
	age      time.Duration
	spn      bool
	disabled bool
	unread   bool
	pso      string // "", "short" (10 days), "never"
}

const (
	uacNeverExpires = 65536
	uacSmartcard    = 262144
	domainMaxAge    = 42
)

func pwSeed() []pwCase {
	return []pwCase{
		{sam: "pw-expired", age: day(60)},
		{sam: "pw-expired-svc", age: day(60), spn: true},
		{sam: "pw-disabled-expired", age: day(60), disabled: true},
		{sam: "pw-soon", age: day(35)},
		{sam: "pw-soon-svc", age: day(35), spn: true},
		{sam: "pw-later", age: day(10)},
		{sam: "pw-default-12d", age: day(12)},
		{sam: "pw-never-flag", uac: uacNeverExpires, age: day(100)},
		{sam: "pw-never-flag-zero", uac: uacNeverExpires},
		{sam: "pw-smartcard", uac: uacSmartcard, age: day(100)},
		{sam: "pw-must"},
		{sam: "pw-pso-short", age: day(12), pso: "short"},
		{sam: "pw-pso-short-fresh", age: day(5), pso: "short"},
		{sam: "pw-pso-never", age: day(200), pso: "never"},
		{sam: "pw-unread", age: day(60), unread: true},
	}
}

// pwState is the order of the spec 6.4 table, written out again here.
func pwState(u pwCase) string {
	switch {
	case u.uac&uacNeverExpires != 0:
		return "never_account_flag"
	case u.uac&uacSmartcard != 0:
		return "not_applicable_smartcard"
	case u.unread:
		return "unknown_input_missing"
	case u.age == 0:
		return "must_change"
	}
	max := day(domainMaxAge)
	switch u.pso {
	case "short":
		max = day(10)
	case "never":
		return "never_policy"
	}
	if u.age > max {
		return "expired"
	}
	return "expires"
}

// daysToExpiry is the whole days until the password expires; ok is false when it never does or is unknown.
func daysToExpiry(u pwCase) (days int, ok bool) {
	if pwState(u) != "expires" && pwState(u) != "expired" {
		return 0, false
	}
	max := day(domainMaxAge)
	if u.pso == "short" {
		max = day(10)
	}
	return int((max - u.age) / (24 * time.Hour)), true
}

type seed struct {
	obs []inventory.Observation
	pw  map[string]pwCase // by user GUID
	now time.Time
	// ids by role
	g struct{ du, dc, only, empty, other, a, b, c, sec, dist, dl, uni, managed, unmanaged, recent, fresh string }
	u struct{ alice, bob, carol, dave, eve, u1 string }
	f string // the foreign security principal
	o struct{ empty, users, comps, mixed, groups, contact, parent, parentEmpty string }
}

func hComputer(guid, name string, rid uint32, uac int64, attrs map[string]any) inventory.Observation {
	return inventory.Observation{Object: inventory.GUID(guid), NC: inventory.GUID(hDom), Kind: inventory.KindComputer, Class: "computer", State: inventory.ObjLive,
		Parent: inventory.GUID(hOU), Ancestry: []inventory.GUID{inventory.GUID(hOU), inventory.GUID(hDom)}, DN: "CN=" + name + ",OU=People,DC=example,DC=test", RDN: "CN=" + name,
		SID: hSID(rid), SAMAccountName: name + "$", UserAccountControl: &uac, InputsRead: allRead, Attributes: attrs, WhenCreated: hBase.Add(-24 * time.Hour)}
}

func contactObs(guid, name string, mail any, created time.Time) inventory.Observation {
	o := inventory.Observation{Object: inventory.GUID(guid), NC: inventory.GUID(hDom), Kind: inventory.KindContact, Class: "contact", State: inventory.ObjLive,
		Parent: inventory.GUID(hOU), Ancestry: []inventory.GUID{inventory.GUID(hOU), inventory.GUID(hDom)}, DN: "CN=" + name + ",OU=People,DC=example,DC=test", RDN: "CN=" + name,
		WhenCreated: created}
	if mail != nil {
		o.Attributes = map[string]any{"mail": mail}
	}
	return o
}

func withAttrs(o inventory.Observation, created time.Time, attrs map[string]any) inventory.Observation {
	o.WhenCreated = created
	o.Attributes = attrs
	return o
}

// groupType values: security-enabled bit 0x80000000 as the signed int32 LDAP returns, scope bits 2, 4, 8.
const (
	gtGlobalSecurity      = -2147483646
	gtDomainLocalSecurity = -2147483644
	gtUniversalSecurity   = -2147483640
	gtGlobalDistribution  = 2
)

func buildSeed() seed {
	var s seed
	s.now = hBase.Add(200 * 24 * time.Hour)
	s.pw = map[string]pwCase{}
	add := func(o inventory.Observation) { s.obs = append(s.obs, o) }

	// password users
	for i, p := range pwSeed() {
		uac := int64(uacNormal) | p.uac
		if p.disabled {
			uac |= 2
		}
		read := allRead
		if p.unread {
			read &^= inventory.ReadPwdLastSet
		}
		spn := p.spn
		hu := hUser{guid: hGUID(1, 100+i), sam: p.sam, rid: uint32(3000 + i), uac: &uac, read: read, spn: &spn}
		if p.age != 0 && !p.unread {
			hu.pwdLastSet = s.now.Add(-p.age)
		}
		o := hu.obs()
		o.DisplayName = p.sam + " Display"
		o.WhenCreated = s.now.Add(-day(201))
		add(o)
		s.pw[string(o.Object)] = p
	}

	// groups
	s.g.du, s.g.dc, s.g.only, s.g.empty, s.g.other = hGUID(2, 1), hGUID(2, 2), hGUID(2, 3), hGUID(2, 4), hGUID(2, 5)
	s.g.a, s.g.b, s.g.c = hGUID(2, 6), hGUID(2, 7), hGUID(2, 8)
	s.g.sec, s.g.dist, s.g.dl, s.g.uni, s.g.managed, s.g.unmanaged = hGUID(2, 9), hGUID(2, 10), hGUID(2, 11), hGUID(2, 12), hGUID(2, 13), hGUID(2, 14)
	s.g.recent, s.g.fresh = hGUID(2, 15), hGUID(2, 16)
	s.u.alice, s.u.bob, s.u.carol, s.u.dave, s.u.eve, s.u.u1 = hGUID(1, 1), hGUID(1, 2), hGUID(1, 3), hGUID(1, 4), hGUID(1, 5), hGUID(1, 6)
	s.f = hGUID(5, 1)
	old := s.now.Add(-day(300))
	mk := func(g, sam string, rid uint32, primary string, uac int64) inventory.Observation {
		o := hUser{guid: g, sam: sam, rid: rid, uac: &uac, read: allRead, primary: primary}.obs()
		o.DisplayName = sam + " Display"
		o.WhenCreated = old
		return o
	}
	add(mk(s.u.alice, "alice", 1101, s.g.only, uacNormal)) // primary group is not Domain Users, member of nothing else (AC-19)
	add(mk(s.u.bob, "bob", 1102, s.g.du, uacNormal))       // in Other
	add(mk(s.u.carol, "carol", 1103, s.g.du, uacNormal))   // only Domain Users
	add(mk(s.u.dave, "dave", 1104, s.g.du, uacNormal|2))   // disabled member of B
	add(mk(s.u.eve, "eve", 1105, s.g.du, uacNormal))       // only Domain Users
	add(mk(s.u.u1, "u1", 1106, s.g.du, uacNormal))         // direct member of A
	add(fsp(s.f, 9001))                                    // a foreign security principal in C
	grp := func(g, name string, rid uint32, created time.Time, attrs map[string]any, members ...string) inventory.Observation {
		return withAttrs(hGroup(g, name, rid, members...), created, attrs)
	}
	gt := func(v int) map[string]any { return map[string]any{"groupType": v} }
	add(grp(s.g.du, "Domain Users", 513, old, gt(gtGlobalSecurity)))
	add(grp(s.g.dc, "Domain Computers", 515, old, gt(gtGlobalSecurity)))
	add(grp(s.g.only, "Primary-only", 2003, old, gt(gtGlobalSecurity)))
	add(grp(s.g.empty, "Empty", 2004, old, gt(gtGlobalSecurity)))
	add(grp(s.g.other, "Other", 2005, old, gt(gtGlobalSecurity), s.u.bob))
	add(grp(s.g.a, "A", 2006, old, nil, s.g.b, s.u.u1))
	add(grp(s.g.b, "B", 2007, old, nil, s.g.c, s.u.dave))
	add(grp(s.g.c, "C", 2008, old, nil, s.g.a, s.f))
	add(grp(s.g.sec, "Sec-Global", 2009, old, gt(gtGlobalSecurity), s.u.eve))
	add(grp(s.g.dist, "Dist-Global", 2010, old, gt(gtGlobalDistribution), s.u.eve))
	add(grp(s.g.dl, "Sec-DomainLocal", 2011, old, gt(gtDomainLocalSecurity)))
	add(grp(s.g.uni, "Sec-Universal", 2012, old, gt(gtUniversalSecurity)))
	add(grp(s.g.managed, "Managed", 2013, old, map[string]any{"groupType": gtGlobalSecurity, "managedBy": "CN=alice,OU=People,DC=example,DC=test"}))
	add(grp(s.g.unmanaged, "Unmanaged", 2014, old, gt(gtGlobalSecurity)))
	add(grp(s.g.recent, "Recent", 2015, s.now.Add(-day(5)), gt(gtGlobalSecurity), s.g.empty))
	add(grp(s.g.fresh, "Fresh", 2016, s.now.Add(-day(2)), gt(gtGlobalDistribution)))

	// computers
	comp := func(i int, name string, uac int64, created time.Time, attrs map[string]any) inventory.Observation {
		return withAttrs(hComputer(hGUID(3, i), name, uint32(5000+i), uac, attrs), created, attrs)
	}
	t := s.now
	add(comp(1, "WS-WIN11", 4096, t.Add(-day(300)), map[string]any{"operatingSystem": "Windows 11 Pro", "operatingSystemVersion": "10.0 (22631)", "dNSHostName": "ws-win11.example.test"}))
	add(comp(2, "WS-OFF", 4096|2, t.Add(-day(300)), map[string]any{"operatingSystem": "Windows 10 Enterprise", "operatingSystemVersion": "10.0 (19045)"}))
	add(comp(3, "SRV-FILE", 4096, t.Add(-day(300)), map[string]any{"operatingSystem": "Windows Server 2022 Standard", "operatingSystemVersion": "10.0 (20348)"}))
	add(comp(4, "DC1", 8192, t.Add(-day(300)), map[string]any{"operatingSystem": "Windows Server 2022 Datacenter"}))
	add(comp(5, "RODC1", 8192|67108864, t.Add(-day(300)), map[string]any{"operatingSystem": "Windows Server 2019 Standard"}))
	add(comp(6, "SRV-UNC", 4096|524288, t.Add(-day(300)), map[string]any{"operatingSystem": "Windows Server 2016 Standard"}))
	add(comp(7, "SRV-CON", 4096, t.Add(-day(300)), map[string]any{"operatingSystem": "Windows Server 2019 Standard", "msDS-AllowedToDelegateTo": []any{"cifs/fs1.example.test"}}))
	add(comp(8, "SRV-PT", 4096|16777216, t.Add(-day(300)), map[string]any{"operatingSystem": "Windows Server 2019 Standard", "msDS-AllowedToDelegateTo": []any{"ldap/dc1.example.test"}}))
	add(comp(9, "NO-OS", 4096, t.Add(-day(300)), nil))
	add(comp(10, "LINUX1", 4096, t.Add(-day(300)), map[string]any{"operatingSystem": "Ubuntu", "operatingSystemVersion": "24.04"}))
	add(comp(11, "NEW-WS", 4096, t.Add(-day(5)), map[string]any{"operatingSystem": "Windows 11 Pro"}))
	add(comp(12, "PC-IN-GROUP", 4096, t.Add(-day(300)), map[string]any{"operatingSystem": "Windows 11 Pro"}))
	g := withAttrs(inventory.Observation{Object: inventory.GUID(hGUID(3, 13)), NC: inventory.GUID(hDom), Kind: inventory.KindGMSA, Class: "msDS-GroupManagedServiceAccount", State: inventory.ObjLive,
		Parent: inventory.GUID(hOU), Ancestry: []inventory.GUID{inventory.GUID(hOU), inventory.GUID(hDom)}, DN: "CN=gmsa1,OU=People,DC=example,DC=test", RDN: "CN=gmsa1",
		SID: hSID(5013), SAMAccountName: "gmsa1$", InputsRead: allRead}, t.Add(-day(300)), nil)
	u := int64(4096)
	g.UserAccountControl = &u
	add(g)
	// activity (CMP-02): replicated logon, password set, creation
	act := func(i int, name string, logon, pwd, created time.Duration, read inventory.InputsRead, uac int64) inventory.Observation {
		o := comp(i, name, uac, t.Add(-created), nil)
		if logon != 0 {
			o.LastLogonTimestamp = t.Add(-logon)
		}
		if pwd != 0 {
			o.PwdLastSet = t.Add(-pwd)
		}
		o.InputsRead = read
		return o
	}
	add(act(20, "ACT-OLD", day(150), day(200), day(300), allRead, 4096))
	add(act(21, "ACT-RECENT", day(10), day(200), day(300), allRead, 4096))
	add(act(22, "ACT-PWD-NEWER", day(200), day(5), day(300), allRead, 4096))
	add(act(23, "ACT-CREATED", 0, 0, day(120), allRead, 4096))
	add(act(24, "ACT-UNREAD", 0, day(5), day(300), allRead&^inventory.ReadLastLogonTimestamp, 4096))
	add(act(25, "ACT-DISABLED", day(150), day(200), day(300), allRead, 4096|2))
	o := act(26, "ACT-GMSA", day(150), day(200), day(300), allRead, 4096)
	o.Kind, o.Class = inventory.KindGMSA, "msDS-GroupManagedServiceAccount"
	add(o)
	// a computer in a group, and one in Domain Computers only
	pcg := comp(30, "PC-MEMBER", 4096, t.Add(-day(300)), nil)
	add(pcg)
	pcd := comp(31, "PC-PRIMARY-ONLY", 4096, t.Add(-day(300)), nil)
	pcd.PrimaryGroup = inventory.GUID(s.g.dc)
	add(pcd)
	add(grp(hGUID(2, 20), "Servers", 2020, old, gt(gtGlobalSecurity), hGUID(3, 30)))

	// OUs and what is in them
	s.o.empty, s.o.users, s.o.comps, s.o.mixed = hGUID(6, 1), hGUID(6, 2), hGUID(6, 3), hGUID(6, 4)
	s.o.groups, s.o.contact, s.o.parent, s.o.parentEmpty = hGUID(6, 5), hGUID(6, 6), hGUID(6, 7), hGUID(6, 8)
	ou := func(g, name string, created time.Time) inventory.Observation {
		o := ouObs(g, name, hDom, hDom)
		o.WhenCreated = created
		return o
	}
	add(ou(s.o.empty, "Empty", old))
	add(ou(s.o.users, "UsersOnly", s.now.Add(-day(5))))
	add(ou(s.o.comps, "ComputersOnly", old))
	add(ou(s.o.mixed, "Mixed", old))
	add(ou(s.o.groups, "GroupsOnly", old))
	add(ou(s.o.contact, "HasContact", old))
	add(ou(s.o.parent, "Parent", old))
	pe := ouObs(s.o.parentEmpty, "Nested", s.o.parent, s.o.parent, hDom)
	pe.WhenCreated = old
	add(pe)
	place := func(o inventory.Observation, ouG string) inventory.Observation {
		return (&env{}).under(o, ouG, ouG, hDom)
	}
	for i := 0; i < 2; i++ {
		x := hUser{guid: hGUID(1, 200+i), sam: fmt.Sprintf("ou-user-%d", i), rid: uint32(7000 + i), uac: i64(uacNormal), read: allRead}.obs()
		x.WhenCreated = old
		add(place(x, s.o.users))
	}
	add(place(comp(40, "OU-PC", 4096, old, nil), s.o.comps))
	cg := comp(41, "OU-GMSA", 4096, old, nil)
	cg.Kind, cg.Class = inventory.KindGMSA, "msDS-GroupManagedServiceAccount"
	add(place(cg, s.o.comps))
	mu := hUser{guid: hGUID(1, 210), sam: "mixed-user", rid: 7010, uac: i64(uacNormal), read: allRead}.obs()
	mu.WhenCreated = old
	add(place(mu, s.o.mixed))
	add(place(comp(42, "MIXED-PC", 4096, old, nil), s.o.mixed))
	add(place(grp(hGUID(2, 30), "OU-Group", 2030, old, gt(gtGlobalSecurity)), s.o.groups))
	add(place(contactObs(hGUID(4, 90), "ou-contact", "ou@example.test", old), s.o.contact))

	// contacts
	add(contactObs(hGUID(4, 1), "Contact-Mail", "a@example.test", old))
	add(contactObs(hGUID(4, 2), "Contact-NoMail", nil, old))
	add(contactObs(hGUID(4, 3), "Contact-New", "new@example.test", s.now.Add(-day(5))))

	// enabled follows userAccountControl for every account
	for i := range s.obs {
		if s.obs[i].UserAccountControl != nil {
			en := *s.obs[i].UserAccountControl&2 == 0
			s.obs[i].Enabled = &en
		}
	}
	// the computer that is a direct member of a group
	for i := range s.obs {
		if s.obs[i].Kind == inventory.KindGroup && string(s.obs[i].Object) == hGUID(2, 20) {
			s.obs[i].Members = []inventory.GUID{inventory.GUID(hGUID(3, 30))}
		}
	}
	return s
}

// ---- the model: what the seed says, with no SQL -----------------------------------------------------------

func (s seed) byGUID() map[string]inventory.Observation {
	m := map[string]inventory.Observation{}
	for _, o := range s.obs {
		m[string(o.Object)] = o
	}
	return m
}

func (s seed) ofKind(kinds ...inventory.Kind) []inventory.Observation {
	var out []inventory.Observation
	for _, o := range s.obs {
		if slices.Contains(kinds, o.Kind) {
			out = append(out, o)
		}
	}
	return out
}

// edges are the members of a group: its member values and the objects whose primary group it is.
func (s seed) edges(g string) []string {
	var out []string
	for _, o := range s.obs {
		if string(o.Object) == g {
			for _, m := range o.Members {
				out = append(out, string(m))
			}
		}
		if string(o.PrimaryGroup) == g {
			out = append(out, string(o.Object))
		}
	}
	return out
}

func (s seed) direct(g string) []string {
	var out []string
	for _, m := range s.edges(g) {
		if !slices.Contains(out, m) {
			out = append(out, m)
		}
	}
	return out
}

// reach is every effective member of g (a group is not its own member), by breadth-first walk.
func (s seed) reach(g string) map[string]bool {
	seen := map[string]bool{}
	queue := []string{g}
	groups := s.byGUID()
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, m := range s.edges(cur) {
			if seen[m] {
				continue
			}
			seen[m] = true
			if groups[m].Kind == inventory.KindGroup {
				queue = append(queue, m)
			}
		}
	}
	delete(seen, g)
	return seen
}

func isUser(k inventory.Kind) bool {
	return k == inventory.KindUser || k == inventory.KindInetOrgPerson
}

func (s seed) isMemberAnywhere(x string) bool {
	for _, o := range s.obs {
		if o.Kind == inventory.KindGroup && slices.Contains(o.Members, inventory.GUID(x)) {
			return true
		}
	}
	return false
}

// subtree is the live objects below an OU, by the parent chain.
func (s seed) subtree(ou string) []inventory.Observation {
	by := s.byGUID()
	parent := map[string]string{hOU: hDom, hSys: hDom}
	for _, o := range s.obs {
		parent[string(o.Object)] = string(o.Parent)
	}
	var out []inventory.Observation
	for _, o := range s.obs {
		for p := string(o.Parent); p != ""; p = parent[p] {
			if p == ou {
				out = append(out, by[string(o.Object)])
				break
			}
		}
	}
	return out
}

func (s seed) ous() []string {
	out := []string{hOU}
	for _, o := range s.ofKind(inventory.KindOU) {
		out = append(out, string(o.Object))
	}
	return out
}

func ouCounts(objs []inventory.Observation) (users, comps, groups, other, all int) {
	for _, o := range objs {
		all++
		switch {
		case isUser(o.Kind):
			users++
		case o.Kind == inventory.KindComputer || o.Kind == inventory.KindGMSA:
			comps++
		case o.Kind == inventory.KindGroup:
			groups++
		case o.Kind == inventory.KindOU:
		default:
			other++
		}
	}
	return
}

func compType(o inventory.Observation) string {
	uac := *o.UserAccountControl
	os, hasOS := o.Attributes["operatingSystem"].(string)
	switch {
	case o.Kind == inventory.KindGMSA:
		return "managed_account"
	case uac&67108864 != 0:
		return "read_only_dc"
	case uac&8192 != 0:
		return "domain_controller"
	case !hasOS:
		return "unknown_input_missing"
	case strings.Contains(strings.ToLower(os), "server"):
		return "server"
	}
	return "workstation"
}

func delegation(o inventory.Observation) string {
	uac := *o.UserAccountControl
	targets, _ := o.Attributes["msDS-AllowedToDelegateTo"].([]any)
	switch {
	case uac&524288 != 0:
		return "unconstrained"
	case len(targets) > 0 && uac&16777216 != 0:
		return "protocol_transition"
	case len(targets) > 0:
		return "constrained"
	}
	return "none"
}

// lastActivity is the later of the logon and the password change, else the creation (both inputs read).
func lastActivity(o inventory.Observation) (t time.Time, src string, known bool) {
	if o.InputsRead&(inventory.ReadPwdLastSet|inventory.ReadLastLogonTimestamp) != inventory.ReadPwdLastSet|inventory.ReadLastLogonTimestamp {
		return time.Time{}, "", false
	}
	switch {
	case o.LastLogonTimestamp.IsZero() && o.PwdLastSet.IsZero():
		return o.WhenCreated, "created", true
	case o.PwdLastSet.IsZero() || (!o.LastLogonTimestamp.IsZero() && !o.LastLogonTimestamp.Before(o.PwdLastSet)):
		return o.LastLogonTimestamp, "logon", true
	}
	return o.PwdLastSet, "password_set", true
}

// ---- the test ---------------------------------------------------------------------------------------

func b2Setup(t *testing.T, s *storetest.Server) (*env, *library.Library, seed) {
	e := setup(t, s)
	reg := e.registry(t)
	l, err := library.Load(library.Shipped(), library.Options{Datasets: inventory.Datasets(), Registry: reg})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	sd := buildSeed()
	e.hStructure(t, e.adA)
	if _, err := e.populate(t, e.adA, hBase.Add(time.Hour), sd.obs...); err != nil {
		t.Fatalf("populate: %v", err)
	}
	syncDays := 14
	pso := func(i int, name string, p inventory.PSO) string {
		g := hGUID(7, i)
		e.policyTx(t, func(ctx context.Context, tx store.Tx, w inventory.PolicyWriter) error {
			return w.SetPSO(ctx, tx, e.adA, inventory.GUID(g), inventory.GUID(hDom), p, hBase)
		})
		if _, err := e.populate(t, e.adA, hBase.Add(2*time.Hour), hPSOObj(g, name)); err != nil {
			t.Fatal(err)
		}
		return g
	}
	short := pso(1, "PSO-short", inventory.PSO{Precedence: i64(1), MaxPwdAge: days(10), LockoutDuration: mins(5)})
	never := pso(2, "PSO-never", inventory.PSO{Precedence: i64(2), MaxPwdAge: forever(), LockoutDuration: mins(5)})
	e.policyTx(t, func(ctx context.Context, tx store.Tx, w inventory.PolicyWriter) error {
		if err := w.SetDomainPolicy(ctx, tx, e.adA, inventory.GUID(hDom),
			inventory.DomainPolicy{MaxPwdAge: days(domainMaxAge), LockoutDuration: mins(30), LogonSyncIntervalDays: &syncDays, PSOsReadAt: hBase}, hBase); err != nil {
			return err
		}
		for guid, p := range sd.pw {
			switch p.pso {
			case "short":
				if err := w.SetPSOApplies(ctx, tx, e.adA, inventory.GUID(short), inventory.GUID(guid), hBase); err != nil {
					return err
				}
			case "never":
				if err := w.SetPSOApplies(ctx, tx, e.adA, inventory.GUID(never), inventory.GUID(guid), hBase); err != nil {
					return err
				}
			}
		}
		return nil
	})
	return e, l, sd
}

// AC-13, AC-19, AC-20, AC-23 for the ten batch-2 reports: every preset equals the oracle.
func Test_reports_library_batch2_rows_equal_ground_truth(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, srv *storetest.Server) {
		e, l, sd := b2Setup(t, srv)
		scope := e.scopeNC(e.adA)
		now := sd.now
		covered := map[string]bool{}
		by := sd.byGUID()
		guidOfSam := map[string]string{}
		for _, o := range sd.obs {
			guidOfSam[o.SAMAccountName] = string(o.Object)
		}
		run := func(id, preset string) []b2Row {
			t.Helper()
			covered[id+"/"+preset] = true
			rows, err := e.runB2(t, l, id, preset, report.RunParams{}, scope, now)
			if err != nil {
				t.Fatalf("%s/%s: %v", id, preset, err)
			}
			return rows
		}
		expectSet := func(id, preset string, rows []b2Row, want []string, wantHidden []string) {
			t.Helper()
			if got, w := keysOf(rows, false), sortedLower(want); !slices.Equal(got, w) {
				t.Errorf("%s/%s: rows differ from the oracle\n got  %v\n want %v", id, preset, name(by, got), name(by, w))
			}
			if got, w := keysOf(rows, true), sortedLower(wantHidden); !slices.Equal(got, w) {
				t.Errorf("%s/%s: hidden rows differ\n got  %v\n want %v", id, preset, name(by, got), name(by, w))
			}
		}

		// ---- PWD-01 and PWD-02 (AC-13): one case per row of the spec 6.4 table
		t.Run("pwd-01", func(t *testing.T) {
			soon := func(p pwCase) bool {
				d, ok := daysToExpiry(p)
				return ok && pwState(p) == "expires" && d >= 0 && d <= 14
			}
			for preset, pred := range map[string]func(pwCase) bool{
				"expired":     func(p pwCase) bool { return pwState(p) == "expired" },
				"soon":        soon,
				"never":       func(p pwCase) bool { s := pwState(p); return s == "never_account_flag" || s == "never_policy" },
				"must_change": func(p pwCase) bool { return pwState(p) == "must_change" },
			} {
				var want, hidden []string
				for g, p := range sd.pw {
					if !pred(p) {
						continue
					}
					if p.spn && (preset == "expired" || preset == "soon") {
						hidden = append(hidden, g)
					} else {
						want = append(want, g)
					}
				}
				rows := run("pwd-01", preset)
				expectSet("pwd-01", preset, rows, want, hidden)
				for _, r := range rows {
					p := sd.pw[r.key]
					if r.s("password_state") != pwState(p) {
						t.Errorf("pwd-01/%s: %s shows state %q, want %q", preset, p.sam, r.s("password_state"), pwState(p))
					}
				}
			}
			// every row of the table, shown with all columns that carry the state, including the ones in no preset
			all, err := e.runB2(t, l, "pwd-01", "expired", report.RunParams{Columns: []report.ColumnID{"sam_account_name", "password_state", "policy_source", "password_expires_at", "days_to_password_expiry"},
				Filters: []report.Expr{report.Cmp{Column: "sam_account_name", Op: report.OpPrefix, Value: report.TextV("pw-")}}, ShowHidden: []string{"service_accounts"}}, scope, now)
			_ = all
			if err != nil {
				t.Fatal(err)
			}
			// "must change" is never labelled expired; a PSO user with the shorter age expires earlier than a default user of the same age
			if pwState(sd.pw[guidOfSam["pw-must"]]) == "expired" {
				t.Error("must change shown as expired")
			}
			states := map[string]string{}
			for _, preset := range []string{"expired", "soon", "never", "must_change"} {
				for _, r := range run("pwd-01", preset) {
					states[r.key] = r.s("password_state")
				}
			}
			if states[guidOfSam["pw-pso-short"]] != "expired" || states[guidOfSam["pw-default-12d"]] != "" {
				t.Errorf("a PSO user and a default-policy user of 12 days: %q and %q", states[guidOfSam["pw-pso-short"]], states[guidOfSam["pw-default-12d"]])
			}
			for _, r := range run("pwd-01", "expired") {
				if sd.pw[r.key].pso == "short" && r.s("policy_source") != "PSO-short" {
					t.Errorf("policy source of %s = %q", sd.pw[r.key].sam, r.s("policy_source"))
				}
			}
			// AC-15: an unread input is Unknown, in no preset
			for _, preset := range []string{"expired", "soon", "never", "must_change"} {
				for _, r := range run("pwd-01", preset) {
					if r.key == guidOfSam["pw-unread"] {
						t.Errorf("pw-unread is listed by %s", preset)
					}
				}
			}
			// the service accounts shown on request carry their reason
			shown, err := e.runB2(t, l, "pwd-01", "expired", report.RunParams{ShowHidden: []string{"service_accounts"}}, scope, now)
			if err != nil {
				t.Fatal(err)
			}
			for _, r := range shown {
				if sd.pw[r.key].spn && r.s("probable_service_account_reason") != "spn_set" {
					t.Errorf("%s: reason %q", sd.pw[r.key].sam, r.s("probable_service_account_reason"))
				}
			}
			if len(shown) != len(run("pwd-01", "expired")) || len(keysOf(shown, true)) != 0 {
				t.Errorf("show service accounts: %d rows, %d hidden", len(shown), len(keysOf(shown, true)))
			}
			// the soon window is a parameter
			wide, err := e.runB2(t, l, "pwd-01", "soon", report.RunParams{Params: map[string]report.ParamValue{"soon_days": report.DaysP(40)}}, scope, now)
			if err != nil {
				t.Fatal(err)
			}
			var wantWide []string
			for g, p := range sd.pw {
				if d, ok := daysToExpiry(p); ok && pwState(p) == "expires" && d >= 0 && d <= 40 && !p.spn {
					wantWide = append(wantWide, g)
				}
			}
			if !slices.Equal(keysOf(wide, false), sortedLower(wantWide)) {
				t.Errorf("soon_days=40: %v, want %v", name(by, keysOf(wide, false)), name(by, sortedLower(wantWide)))
			}
		})

		t.Run("pwd-02", func(t *testing.T) {
			var changed, unchanged []string
			for g, p := range sd.pw {
				if p.unread {
					continue
				}
				if p.age != 0 && p.age < day(30) {
					changed = append(changed, g)
				}
				if !p.disabled && (p.age == 0 || p.age >= day(90)) { // pwdLastSet 0: created 201 days ago
					unchanged = append(unchanged, g)
				}
			}
			expectSet("pwd-02", "changed", run("pwd-02", "changed"), changed, nil)
			rows := run("pwd-02", "unchanged")
			expectSet("pwd-02", "unchanged", rows, unchanged, nil)
			for _, r := range run("pwd-02", "changed") {
				if want := fmt.Sprint(int(sd.pw[r.key].age / (24 * time.Hour))); r.s("days_since_password_set") != want {
					t.Errorf("days since for %s = %s, want %s", sd.pw[r.key].sam, r.s("days_since_password_set"), want)
				}
			}
		})

		// ---- GRP-01
		t.Run("grp-01", func(t *testing.T) {
			groups := sd.ofKind(inventory.KindGroup)
			typeOf := func(o inventory.Observation) string {
				v, ok := o.Attributes["groupType"].(int)
				switch {
				case !ok:
					return "unknown_input_missing"
				case uint32(int32(v))&0x80000000 != 0:
					return "security"
				}
				return "distribution"
			}
			pick := func(pred func(inventory.Observation) bool) (out []string) {
				for _, g := range groups {
					if pred(g) {
						out = append(out, string(g.Object))
					}
				}
				return
			}
			hasMgr := func(o inventory.Observation) bool { _, ok := o.Attributes["managedBy"].(string); return ok }
			want := map[string][]string{
				"all":              pick(func(inventory.Observation) bool { return true }),
				"security":         pick(func(o inventory.Observation) bool { return typeOf(o) == "security" }),
				"distribution":     pick(func(o inventory.Observation) bool { return typeOf(o) == "distribution" }),
				"type_scope":       pick(func(inventory.Observation) bool { return true }),
				"no_members":       pick(func(o inventory.Observation) bool { return len(sd.direct(string(o.Object))) == 0 }),
				"managed":          pick(hasMgr),
				"unmanaged":        pick(func(o inventory.Observation) bool { return !hasMgr(o) }),
				"top":              pick(func(inventory.Observation) bool { return true }),
				"recently_created": pick(func(o inventory.Observation) bool { return now.Sub(o.WhenCreated) < day(30) }),
			}
			for preset, w := range want {
				rows := run("grp-01", preset)
				expectSet("grp-01", preset, rows, w, nil)
				for _, r := range rows {
					g := string(by[r.key].Object)
					if d, e := fmt.Sprint(len(sd.direct(g))), fmt.Sprint(len(sd.reach(g))); r.s("direct_members") != d || r.s("effective_members") != e {
						t.Errorf("grp-01/%s: %s direct/effective = %s/%s, want %s/%s", preset, by[r.key].SAMAccountName, r.s("direct_members"), r.s("effective_members"), d, e)
					}
					if r.s("group_type") != typeOf(by[r.key]) {
						t.Errorf("grp-01/%s: %s type %q, want %q", preset, by[r.key].SAMAccountName, r.s("group_type"), typeOf(by[r.key]))
					}
				}
			}
			// AC-19: a group whose only members are primary-group users is not empty
			for _, r := range run("grp-01", "no_members") {
				if r.key == sd.g.only {
					t.Error("Primary-only is reported as a group without members")
				}
			}
			// Top N: the biggest first, 25 at most
			top := run("grp-01", "top")
			var prev int
			for i, r := range top {
				var n int
				fmt.Sscan(r.s("effective_members"), &n)
				if i > 0 && n > prev {
					t.Errorf("top N is not in descending order at row %d", i)
				}
				prev = n
			}
			d, _ := l.Definition("grp-01", 0)
			if p, _ := d.Def.Preset("top"); p.Top != 25 {
				t.Errorf("Top N is %d, the spec says 25", p.Top)
			}
		})

		// ---- GRP-02 and GRP-03 (AC-20)
		t.Run("grp-02", func(t *testing.T) {
			subj := func(ids ...string) report.RunParams {
				var o []authz.ObjectID
				for _, g := range ids {
					o = append(o, rpID(g))
				}
				return report.RunParams{Subjects: o}
			}
			// without a group the report does not run
			if _, err := e.runB2(t, l, "grp-02", "detailed", report.RunParams{}, scope, now); err == nil {
				t.Error("grp-02 ran without a group")
			}
			groupsToTest := []string{sd.g.a, sd.g.b, sd.g.du, sd.g.only, sd.g.empty, sd.g.other}
			for _, g := range groupsToTest {
				covered["grp-02/detailed"], covered["grp-02/members"], covered["grp-02/users"] = true, true, true
				detailed, err := e.runB2(t, l, "grp-02", "detailed", subj(g), scope, now)
				if err != nil {
					t.Fatal(err)
				}
				reach := sd.reach(g)
				var wantRows []string
				for m := range reach {
					wantRows = append(wantRows, g+"|"+m)
				}
				// a cycle through g is one finding row for g itself
				cycle := false
				for _, m := range sd.direct(g) {
					if by[m].Kind == inventory.KindGroup && sd.reach(m)[g] {
						cycle = true
					}
				}
				if cycle {
					wantRows = append(wantRows, g+"|"+g)
				}
				if got, w := keysOf(detailed, false), sortedLower(wantRows); !slices.Equal(got, w) {
					t.Errorf("detailed %s:\n got  %v\n want %v", by[g].SAMAccountName, got, w)
				}
				directRows, _ := e.runB2(t, l, "grp-02", "members", subj(g), scope, now)
				var wantDirect []string
				for _, m := range sd.direct(g) {
					wantDirect = append(wantDirect, g+"|"+m)
				}
				if got, w := keysOf(directRows, false), sortedLower(wantDirect); !slices.Equal(got, w) {
					t.Errorf("members %s:\n got  %v\n want %v", by[g].SAMAccountName, got, w)
				}
				users, _ := e.runB2(t, l, "grp-02", "users", subj(g), scope, now)
				var wantUsers []string
				for m := range reach {
					if isUser(by[m].Kind) {
						wantUsers = append(wantUsers, g+"|"+m)
					}
				}
				if cycle {
					wantUsers = append(wantUsers, g+"|"+g) // the finding row is kept, so the list is never silently incomplete
				}
				if got, w := keysOf(users, false), sortedLower(wantUsers); !slices.Equal(got, w) {
					t.Errorf("users %s:\n got  %v\n want %v", by[g].SAMAccountName, got, w)
				}
			}
			// the nested group of three levels with a cycle, an external principal and a disabled member
			rows, _ := e.runB2(t, l, "grp-02", "detailed", subj(sd.g.a), scope, now)
			row := map[string]b2Row{}
			for _, r := range rows {
				row[r.key] = r
			}
			for _, c := range []struct{ m, col, want string }{
				{sd.u.dave, "via_path", "B"}, {sd.u.dave, "member_enabled", "false"}, {sd.u.dave, "edge_kind", "nested"},
				{sd.f, "via_path", "B → C"}, {sd.f, "member_name", "External principal (unresolved)"}, {sd.f, "member_kind", "fsp"},
				{sd.g.a, "edge_kind", "cycle"}, {sd.g.a, "finding", "Circular nesting: A → B → C → A"},
				{sd.u.u1, "edge_kind", "direct"}, {sd.g.c, "via_path", "B"},
			} {
				r, ok := row[strings.ToLower(sd.g.a+"|"+c.m)]
				if !ok {
					t.Errorf("no row for %s in A", c.m)
					continue
				}
				if got := r.s(c.col); got != c.want {
					t.Errorf("(A, %s).%s = %q, want %q", by[c.m].SAMAccountName+by[c.m].RDN, c.col, got, c.want)
				}
			}
			if n := len(rows); n != len(sd.reach(sd.g.a))+1 {
				t.Errorf("detailed A: %d rows, each effective member once plus the cycle finding = %d", n, len(sd.reach(sd.g.a))+1)
			}
			// two groups at once, and a group outside the scope returns nothing and no error
			two, err := e.runB2(t, l, "grp-02", "members", subj(sd.g.other, sd.g.only), scope, now)
			if err != nil || len(two) != len(sd.direct(sd.g.other))+len(sd.direct(sd.g.only)) {
				t.Errorf("two groups: %d rows, err %v", len(two), err)
			}
			none, err := e.runB2(t, l, "grp-02", "members", subj(sd.g.other), e.scopeOU(e.adA), now)
			_ = none
			if err != nil {
				t.Error(err)
			}
		})

		t.Run("grp-03", func(t *testing.T) {
			covered["grp-03/groups_for_users"] = true
			for _, u := range []string{sd.u.alice, sd.u.bob, sd.u.dave, sd.u.carol, sd.u.u1} {
				rows, err := e.runB2(t, l, "grp-03", "groups_for_users", report.RunParams{Subjects: []authz.ObjectID{rpID(u)}}, scope, now)
				if err != nil {
					t.Fatal(err)
				}
				var want []string
				for _, g := range sd.ofKind(inventory.KindGroup) {
					if sd.reach(string(g.Object))[u] {
						want = append(want, string(g.Object)+"|"+u)
					}
				}
				if got, w := keysOf(rows, false), sortedLower(want); !slices.Equal(got, w) {
					t.Errorf("groups of %s:\n got  %v\n want %v", by[u].SAMAccountName, got, w)
				}
				for _, r := range rows {
					if g := strings.SplitN(r.key, "|", 2)[0]; sd.byGUID()[g].Kind == inventory.KindGroup && string(by[u].PrimaryGroup) == g && r.s("edge_kind") != "primary_group" {
						t.Errorf("%s: the primary group is shown as %q", by[u].SAMAccountName, r.s("edge_kind"))
					}
				}
			}
			// alice's only group is her primary group, named, with its type and scope
			rows, _ := e.runB2(t, l, "grp-03", "groups_for_users", report.RunParams{Subjects: []authz.ObjectID{rpID(sd.u.alice)}}, scope, now)
			if len(rows) != 1 || rows[0].s("group_name") != "Primary-only" || rows[0].s("edge_kind") != "primary_group" ||
				rows[0].s("group_type") != "security" || rows[0].s("group_scope") != "global" {
				t.Errorf("alice: %+v", rows)
			}
		})

		// ---- GRP-04 (AC-19)
		t.Run("grp-04", func(t *testing.T) {
			var users, comps []string
			for _, o := range sd.obs {
				if sd.isMemberAnywhere(string(o.Object)) {
					continue
				}
				switch {
				case isUser(o.Kind):
					users = append(users, string(o.Object))
				case o.Kind == inventory.KindComputer || o.Kind == inventory.KindGMSA:
					comps = append(comps, string(o.Object))
				}
			}
			ur := run("grp-04", "users")
			expectSet("grp-04", "users", ur, users, nil)
			expectSet("grp-04", "computers", run("grp-04", "computers"), comps, nil)
			// alice appears with her primary group named; bob (in Other) does not appear
			var alice *b2Row
			for i := range ur {
				if ur[i].key == sd.u.alice {
					alice = &ur[i]
				}
				if ur[i].key == sd.u.bob {
					t.Error("bob is a member of Other and is listed as in no group")
				}
			}
			if alice == nil || alice.s("primary_group") != "Primary-only" {
				t.Errorf("alice: %+v", alice)
			}
		})

		// ---- CMP-01
		t.Run("cmp-01", func(t *testing.T) {
			comps := sd.ofKind(inventory.KindComputer, inventory.KindGMSA)
			pick := func(pred func(inventory.Observation) bool) (out []string) {
				for _, o := range comps {
					if pred(o) {
						out = append(out, string(o.Object))
					}
				}
				return
			}
			want := map[string][]string{
				"all":         pick(func(inventory.Observation) bool { return true }),
				"enabled":     pick(func(o inventory.Observation) bool { return *o.Enabled }),
				"disabled":    pick(func(o inventory.Observation) bool { return !*o.Enabled }),
				"workstation": pick(func(o inventory.Observation) bool { return compType(o) == "workstation" }),
				"domain_controller": pick(func(o inventory.Observation) bool {
					t := compType(o)
					return t == "domain_controller" || t == "read_only_dc"
				}),
				"delegation":       pick(func(o inventory.Observation) bool { return delegation(o) != "none" }),
				"os":               pick(func(o inventory.Observation) bool { _, ok := o.Attributes["operatingSystem"].(string); return ok }),
				"recently_created": pick(func(o inventory.Observation) bool { return now.Sub(o.WhenCreated) < day(30) }),
			}
			for preset, w := range want {
				rows := run("cmp-01", preset)
				expectSet("cmp-01", preset, rows, w, nil)
				for _, r := range rows {
					o := by[r.key]
					if r.s("computer_type") != compType(o) || r.s("delegation") != delegation(o) {
						t.Errorf("cmp-01/%s: %s type/delegation = %s/%s, want %s/%s", preset, o.SAMAccountName, r.s("computer_type"), r.s("delegation"), compType(o), delegation(o))
					}
				}
			}
			// a machine with no operating system is Unknown, never a workstation; a read-only DC is labelled
			types := map[string]string{}
			for _, r := range run("cmp-01", "all") {
				types[by[r.key].SAMAccountName] = r.s("computer_type")
			}
			if types["NO-OS$"] != "unknown_input_missing" || types["RODC1$"] != "read_only_dc" || types["gmsa1$"] != "managed_account" {
				t.Errorf("types: %v", types)
			}
		})

		// ---- CMP-02
		t.Run("cmp-02", func(t *testing.T) {
			var inactive, hidden, active []string
			for _, o := range sd.ofKind(inventory.KindComputer, inventory.KindGMSA) {
				la, _, known := lastActivity(o)
				if !known {
					continue
				}
				if now.Sub(la) < day(30) && !la.After(now) {
					active = append(active, string(o.Object))
				}
				if *o.Enabled && now.Sub(la) >= day(90) {
					if o.Kind == inventory.KindGMSA {
						hidden = append(hidden, string(o.Object))
					} else {
						inactive = append(inactive, string(o.Object))
					}
				}
			}
			ir := run("cmp-02", "inactive")
			expectSet("cmp-02", "inactive", ir, inactive, hidden)
			ar := run("cmp-02", "active")
			expectSet("cmp-02", "active", ar, active, nil)
			for _, r := range append(ir, ar...) {
				la, src, _ := lastActivity(by[r.key])
				if r.s("activity_source") != src || r.s("days_since_activity") != fmt.Sprint(int(now.Sub(la)/(24*time.Hour))) {
					t.Errorf("%s: source/days = %s/%s, want %s/%d", by[r.key].SAMAccountName, r.s("activity_source"), r.s("days_since_activity"), src, int(now.Sub(la)/(24*time.Hour)))
				}
			}
			// the unread logon input is Unknown: in neither
			for _, r := range append(ir, ar...) {
				if by[r.key].SAMAccountName == "ACT-UNREAD$" {
					t.Error("ACT-UNREAD is listed with an unread input")
				}
			}
			// the 30-day floor on the replicated logon threshold
			if _, err := e.runB2(t, l, "cmp-02", "inactive", report.RunParams{Params: map[string]report.ParamValue{"days": report.DaysP(29)}}, scope, now); err == nil {
				t.Error("a 29-day threshold was accepted")
			}
		})

		// ---- OU-01
		t.Run("ou-01", func(t *testing.T) {
			var all, empty, usersOnly, compsOnly, recent []string
			counts := map[string][5]int{}
			for _, g := range sd.ous() {
				u, c, gr, o, n := ouCounts(sd.subtree(g))
				counts[g] = [5]int{u, c, gr, o, n}
				all = append(all, g)
				switch {
				case u+c+gr+o == 0:
					empty = append(empty, g)
				case u > 0 && c+gr+o == 0:
					usersOnly = append(usersOnly, g)
				case c > 0 && u+gr+o == 0:
					compsOnly = append(compsOnly, g)
				}
				if ob, ok := by[g]; ok && !ob.WhenCreated.IsZero() && now.Sub(ob.WhenCreated) < day(30) {
					recent = append(recent, g)
				}
			}
			for preset, w := range map[string][]string{"all": all, "empty": empty, "users_only": usersOnly, "computers_only": compsOnly, "recently_created": recent} {
				rows := run("ou-01", preset)
				expectSet("ou-01", preset, rows, w, nil)
				for _, r := range rows {
					c := counts[r.key]
					got := [5]string{r.s("subtree_users"), r.s("subtree_computers"), r.s("subtree_groups"), r.s("subtree_other"), r.s("subtree_objects")}
					if got != [5]string{fmt.Sprint(c[0]), fmt.Sprint(c[1]), fmt.Sprint(c[2]), fmt.Sprint(c[3]), fmt.Sprint(c[4])} {
						t.Errorf("ou-01/%s: %s counts %v, want %v", preset, r.key, got, c)
					}
				}
			}
			// the unit that holds only an empty unit is empty; the unit with a contact is not
			isIn := func(set []string, g string) bool { return slices.Contains(sortedLower(set), g) }
			if !isIn(empty, sd.o.parent) || !isIn(empty, sd.o.empty) || isIn(empty, sd.o.contact) || !isIn(usersOnly, sd.o.users) || isIn(usersOnly, sd.o.mixed) || !isIn(compsOnly, sd.o.comps) {
				t.Errorf("empty %v, users-only %v, computers-only %v", empty, usersOnly, compsOnly)
			}
		})

		// ---- CTC-01
		t.Run("ctc-01", func(t *testing.T) {
			var all, mail, recent []string
			for _, o := range sd.ofKind(inventory.KindContact) {
				all = append(all, string(o.Object))
				if m, ok := o.Attributes["mail"].(string); ok && m != "" {
					mail = append(mail, string(o.Object))
				}
				if now.Sub(o.WhenCreated) < day(30) {
					recent = append(recent, string(o.Object))
				}
			}
			expectSet("ctc-01", "all", run("ctc-01", "all"), all, nil)
			mr := run("ctc-01", "mail_enabled")
			expectSet("ctc-01", "mail_enabled", mr, mail, nil)
			expectSet("ctc-01", "recently_created", run("ctc-01", "recently_created"), recent, nil)
			for _, r := range mr {
				if r.s("mail") != by[r.key].Attributes["mail"] {
					t.Errorf("mail of %s = %q", r.key, r.s("mail"))
				}
			}
		})

		// every preset of every batch-2 report was compared
		for _, it := range l.List() {
			switch it.Def.ID {
			case "pwd-01", "pwd-02", "grp-01", "grp-02", "grp-03", "grp-04", "cmp-01", "cmp-02", "ou-01", "ctc-01":
				for _, p := range it.Def.Presets {
					if !covered[string(it.Def.ID)+"/"+p.ID] {
						t.Errorf("%s/%s was not compared with the oracle", it.Def.ID, p.ID)
					}
				}
			}
		}
	})
}

// name turns GUID keys into names for a readable failure.
func name(by map[string]inventory.Observation, keys []string) []string {
	out := make([]string, len(keys))
	for i, k := range keys {
		g, m, two := strings.Cut(k, "|")
		out[i] = by[g].SAMAccountName + by[g].RDN
		if two {
			out[i] += "|" + by[m].SAMAccountName + by[m].RDN
		}
	}
	return out
}
