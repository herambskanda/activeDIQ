package latency_test

// The 50,000-object seed of the search latency benchmark (T-1102, ADR-0011 rule 14).
//
// The seed is a pure function of (n, seed constants): same input, same bytes. Nothing here reads the clock,
// the environment or a map in iteration order, and every random choice comes from one PCG stream consumed in
// a fixed order. Seed.Digest() is a SHA-256 over every row written, printed with the results and pinned for
// n = 50,000 in TestSeedIsDeterministic, so a change to the seed shows up as a changed digest, not as a
// silently different benchmark.
//
// Shape (ticket acceptance 1), for n = 50,000: 30,000 users, 8,000 groups, 10,000 computers, 2,000
// contacts (the 30:8:10:2 ratio scales for smaller n); two connections (60 % / 40 %), each with an OU tree
// six levels deep; 5 % of the display names of each kind duplicate another object's of that kind; 10 % of
// the users and of the computers are disabled (groups and contacts have no enabled state).

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/rand/v2"
	"strings"

	"github.com/skenzeriq/activediq/internal/directory/inventory"
)

const (
	seedA = 0x7a11_ed01_5ea2_c4d1
	seedB = 0x0b5e_55ed_1d0c_a110
)

// ouFanout is the number of children each OU has, per level: level 1 has 4 OUs under the domain, each with 3
// children, and so on. 4*3*2*2*2*2 = 192 leaves per connection, 376 OUs.
var ouFanout = [6]int{4, 3, 2, 2, 2, 2}

// Domains of the two connections.
var domains = [2]struct{ DNS, DC string }{
	{"corp.example.test", "DC=corp,DC=example,DC=test"},
	{"emea.example.test", "DC=emea,DC=example,DC=test"},
}

type seedOU struct {
	GUID   string
	Conn   int
	Level  int // 1..6
	Parent int // index into Seed.OUs, -1 under the naming context
	Name   string
	DN     string
	// Chain is the OU indexes from this OU up to level 1, this OU first.
	Chain []int
}

type seedObj struct {
	Conn    int
	Kind    inventory.Kind
	GUID    string
	OU      int // index into Seed.OUs
	Display string
	Sam     string
	UPN     string
	Mail    string
	Host    string
	Enabled *bool
	DN, RDN string
	SID     []byte
	Dup     bool // the display name copies another object's
}

// Seed is the generated inventory.
type Seed struct {
	N      int
	NC     [2]string // naming-context GUIDs
	OUs    []seedOU
	Objs   []seedObj
	Counts map[inventory.Kind]int
}

func guidOf(class byte, conn, i int) string {
	return fmt.Sprintf("%02x%06x-0000-4000-8000-%012x", class, conn, i)
}

// syllable pools: names are built, not listed, so the pool is large, deterministic and licence-free.
var (
	onsets = []string{"b", "d", "f", "g", "h", "j", "k", "l", "m", "n", "p", "r", "s", "t", "v", "z", "br", "pr", "kr", "tr", "ch", "sh", "st", "gr"}
	nuclei = []string{"a", "e", "i", "o", "u", "ia", "ar", "an", "el", "or", "ay", "in"}
	codas  = []string{"", "", "n", "m", "r", "l", "s", "t", "d", "k", "sh", "x"}
)

func title(s string) string { return strings.ToUpper(s[:1]) + s[1:] }

func buildWord(r *rand.Rand, syllables int) string {
	var b strings.Builder
	for i := 0; i < syllables; i++ {
		b.WriteString(onsets[r.IntN(len(onsets))])
		b.WriteString(nuclei[r.IntN(len(nuclei))])
	}
	b.WriteString(codas[r.IntN(len(codas))])
	return b.String()
}

func pool(r *rand.Rand, n, syl int) []string {
	seen := map[string]bool{}
	var out []string
	for len(out) < n {
		w := buildWord(r, syl)
		if len(w) < 4 || len(w) > 11 || seen[w] {
			continue
		}
		seen[w] = true
		out = append(out, title(w))
	}
	return out
}

var (
	depts = []string{"Engineering", "Finance", "Sales", "Operations", "Legal", "Support", "Marketing", "Procurement", "Security", "Research", "Facilities", "Logistics",
		"Compliance", "Analytics", "Platform", "Payroll", "Training", "Quality", "Design", "Treasury", "Audit", "Estates", "Fleet", "Records"}
	funcs = []string{"Admins", "Readers", "Writers", "Reviewers", "Approvers", "Managers", "Leads", "Contractors", "Interns", "Auditors", "Operators", "Owners",
		"Backup", "Deploy", "Access", "Print", "VPN", "Mailbox", "Shared", "Project", "Budget", "Travel", "Onsite", "Remote", "Pilot", "Escalation", "Oncall", "Vendors",
		"Hardware", "Software", "Licensing", "Reporting", "Planning", "Intake", "Billing", "Archive", "Payments", "Orders", "Returns", "Stores"}
	sites = []string{"LON", "NYC", "PAR", "BER", "MAD", "ROM", "AMS", "DUB", "OSL", "HEL", "ZRH", "VIE", "PRG", "WAW", "LIS", "ATH", "SFO", "SEA", "BOS", "CHI",
		"DAL", "MIA", "TOR", "MTL", "SYD", "MEL", "SIN", "TYO", "BOM", "DXB"}
	kinds = []string{"WKS", "LAP", "SRV", "VDI"}
)

// NewSeed generates the inventory of n objects (n a multiple of 50; 50,000 for the benchmark).
func NewSeed(n int) *Seed {
	if n < 50 || n%50 != 0 {
		panic("seed: n must be a positive multiple of 50")
	}
	r := rand.New(rand.NewPCG(seedA, seedB))
	s := &Seed{N: n, Counts: map[inventory.Kind]int{
		inventory.KindUser: n * 30 / 50, inventory.KindGroup: n * 8 / 50, inventory.KindComputer: n * 10 / 50, inventory.KindContact: n * 2 / 50}}
	for c := range s.NC {
		s.NC[c] = guidOf(0x10, c, 0)
	}
	// The OU trees, level by level, so a parent always precedes its children.
	for c := 0; c < 2; c++ {
		var prev []int
		for lvl := 1; lvl <= 6; lvl++ {
			var cur []int
			parents := prev
			if lvl == 1 {
				parents = []int{-1}
			}
			for _, p := range parents {
				for k := 0; k < ouFanout[lvl-1]; k++ {
					idx := len(s.OUs)
					name := fmt.Sprintf("L%d-%02d", lvl, k+1)
					if lvl == 1 {
						name = depts[k]
					}
					ou := seedOU{GUID: guidOf(0x20, c, idx), Conn: c, Level: lvl, Parent: p, Name: name, Chain: []int{idx}}
					if p >= 0 {
						ou.Chain = append(ou.Chain, s.OUs[p].Chain...)
						ou.DN = "OU=" + name + "," + s.OUs[p].DN
					} else {
						ou.DN = "OU=" + name + "," + domains[c].DC
					}
					s.OUs = append(s.OUs, ou)
					cur = append(cur, idx)
				}
			}
			prev = cur
		}
	}
	// Placement. A third of the objects of connection 0 land in the OU that the scoped benchmark caller has
	// excluded (ScopedExclude), a quarter elsewhere in the caller's own OU (ScopedRoot), the rest anywhere.
	var all, leaves [2][]int
	for i, ou := range s.OUs {
		all[ou.Conn] = append(all[ou.Conn], i)
		if ou.Level == 6 {
			leaves[ou.Conn] = append(leaves[ou.Conn], i)
		}
	}
	root, excl := s.ScopedRoot(), s.ScopedExclude()
	var inRoot, inExcl []int // leaves of connection 0 under the caller's OU and under the exclusion
	for _, l := range leaves[0] {
		switch {
		case s.Under(l, excl):
			inExcl = append(inExcl, l)
		case s.Under(l, root):
			inRoot = append(inRoot, l)
		}
	}
	place := func(conn int) int {
		x := r.Float64()
		switch {
		case conn == 0 && x < 0.30:
			return inExcl[r.IntN(len(inExcl))]
		case conn == 0 && x < 0.50:
			return inRoot[r.IntN(len(inRoot))]
		case x < 0.80:
			return leaves[conn][r.IntN(len(leaves[conn]))]
		default: // some objects sit in OUs above the leaves, so subtree membership is not a leaf-only fact
			return all[conn][r.IntN(len(all[conn]))]
		}
	}

	firsts, lasts := pool(r, 240, 2), pool(r, 330, 2)
	pairs := r.Perm(len(firsts) * len(lasts))
	nextPair := 0
	person := func() (first, last string) {
		p := pairs[nextPair]
		nextPair++
		return firsts[p/len(lasts)], lasts[p%len(lasts)]
	}
	usedSam := map[string]bool{}
	uniqueSam := func(base string) string {
		sam := base
		for k := 2; usedSam[sam]; k++ {
			sam = fmt.Sprintf("%s%d", base, k)
		}
		usedSam[sam] = true
		return sam
	}

	// emit adds one object; display is the identity's own name, the duplicate flag swaps in another's.
	var byKind = map[inventory.Kind][]int{}
	rid := uint32(1000)
	emit := func(kind inventory.Kind, i int, display string, mk func(o *seedObj)) {
		conn := 1
		if r.Float64() < 0.6 {
			conn = 0
		}
		o := seedObj{Conn: conn, Kind: kind, OU: place(conn)}
		o.GUID = guidOf(map[inventory.Kind]byte{inventory.KindUser: 1, inventory.KindGroup: 2, inventory.KindComputer: 3, inventory.KindContact: 4}[kind], conn, i)
		o.Display = display
		prior := byKind[kind]
		if len(prior) > 0 && r.Float64() < 0.05 {
			src := s.Objs[prior[r.IntN(len(prior))]]
			// A duplicate keeps its own identity (sam, mail, host); only the display name repeats.
			o.Display, o.Dup = src.Display, true
		}
		mk(&o)
		if s.OUs[o.OU].Conn != conn {
			panic("seed: placement crossed connections")
		}
		o.RDN = "CN=" + o.Display
		o.DN = o.RDN + "," + s.OUs[o.OU].DN
		if kind == inventory.KindUser || kind == inventory.KindGroup || kind == inventory.KindComputer {
			rid++
			o.SID = sidBytes(rid)
		}
		byKind[kind] = append(byKind[kind], len(s.Objs))
		s.Objs = append(s.Objs, o)
	}
	disabled := func(i int) *bool { v := i%10 != 7; return &v } // exactly 10 % false when the kind's count is a multiple of 10

	for i := 0; i < s.Counts[inventory.KindUser]; i++ {
		f, l := person()
		display := f + " " + l
		emit(inventory.KindUser, i, display, func(o *seedObj) {
			o.Sam = uniqueSam(strings.ToLower(f[:1] + l))
			o.UPN = o.Sam + "@" + domains[o.Conn].DNS
			o.Enabled = disabled(i)
		})
	}
	for i := 0; i < s.Counts[inventory.KindGroup]; i++ {
		d, f := depts[i%len(depts)], funcs[(i/len(depts))%len(funcs)]
		display := fmt.Sprintf("%s %s %03d", d, f, i/(len(depts)*len(funcs)))
		emit(inventory.KindGroup, i, display, func(o *seedObj) {
			o.Sam = uniqueSam(strings.ToLower(fmt.Sprintf("gg-%s-%s-%d", d, f, i)))
		})
	}
	for i := 0; i < s.Counts[inventory.KindComputer]; i++ {
		name := fmt.Sprintf("%s-%s-%05d", sites[i%len(sites)], kinds[(i/len(sites))%len(kinds)], i)
		emit(inventory.KindComputer, i, name, func(o *seedObj) {
			o.Sam = uniqueSam(strings.ToLower(name) + "$")
			o.Host = strings.ToLower(name) + "." + domains[o.Conn].DNS
			o.Enabled = disabled(i)
		})
	}
	for i := 0; i < s.Counts[inventory.KindContact]; i++ {
		f, l := person()
		display := f + " " + l
		emit(inventory.KindContact, i, display, func(o *seedObj) {
			o.Mail = strings.ToLower(f+"."+l) + fmt.Sprintf("@vendor-%d.example.test", i%40)
		})
	}
	return s
}

func sidBytes(rid uint32) []byte {
	b := []byte{1, 5, 0, 0, 0, 0, 0, 5}
	for _, v := range []uint32{21, 1, 2, 3, rid} {
		b = append(b, byte(v), byte(v>>8), byte(v>>16), byte(v>>24))
	}
	return b
}

// ScopedRoot is the OU the scoped caller reads: the first level-1 OU of connection 0.
func (s *Seed) ScopedRoot() int { return s.firstOU(0, 1, -1) }

// ScopedExclude is the large sub-OU excluded from it: the first level-2 child of ScopedRoot.
func (s *Seed) ScopedExclude() int { return s.firstOU(0, 2, s.ScopedRoot()) }

func (s *Seed) firstOU(conn, level, parent int) int {
	for i, ou := range s.OUs {
		if ou.Conn == conn && ou.Level == level && (parent < 0 || ou.Parent == parent) {
			return i
		}
	}
	panic("seed: no such OU")
}

// Under reports whether OU ou is root or lies below it.
func (s *Seed) Under(ou, root int) bool {
	for _, c := range s.OUs[ou].Chain {
		if c == root {
			return true
		}
	}
	return false
}

// Visible reports whether the caller kind sees object i. "admin" reads both naming contexts whole; "scoped"
// reads the subtree of ScopedRoot in connection 0 minus the subtree of ScopedExclude. This is the oracle's
// own implementation of the scope; it shares nothing with the scope renderer.
func (s *Seed) Visible(caller string, i int) bool {
	o := s.Objs[i]
	if caller == "admin" {
		return true
	}
	return o.Conn == 0 && s.Under(o.OU, s.ScopedRoot()) && !s.Under(o.OU, s.ScopedExclude())
}

// Digest is a SHA-256 over every OU and object, in order.
func (s *Seed) Digest() string {
	h := sha256.New()
	for _, ou := range s.OUs {
		fmt.Fprintf(h, "ou|%s|%d|%d|%d|%s\n", ou.GUID, ou.Conn, ou.Level, ou.Parent, ou.DN)
	}
	for _, o := range s.Objs {
		en := "-"
		if o.Enabled != nil {
			en = fmt.Sprint(*o.Enabled)
		}
		fmt.Fprintf(h, "obj|%s|%d|%s|%d|%s|%s|%s|%s|%s|%s|%t|%x\n", o.GUID, o.Conn, o.Kind, o.OU, o.Display, o.Sam, o.UPN, o.Mail, o.Host, en, o.Dup, o.SID)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// Observations returns the writer input for connection conn: the naming context, the OUs, then the objects,
// in order, so a parent is always written before its children.
func (s *Seed) Observations(conn int) (head []inventory.Observation, objs []inventory.Observation) {
	nc := inventory.GUID(s.NC[conn])
	head = append(head, inventory.Observation{Object: nc, NC: nc, Kind: inventory.KindOther, Class: "domainDNS", State: inventory.ObjLive, DN: domains[conn].DC})
	for _, ou := range s.OUs {
		if ou.Conn != conn {
			continue
		}
		anc := make([]inventory.GUID, 0, ou.Level)
		for _, c := range ou.Chain[1:] {
			anc = append(anc, inventory.GUID(s.OUs[c].GUID))
		}
		anc = append(anc, nc)
		parent := nc
		if ou.Parent >= 0 {
			parent = inventory.GUID(s.OUs[ou.Parent].GUID)
		}
		head = append(head, inventory.Observation{Object: inventory.GUID(ou.GUID), NC: nc, Kind: inventory.KindOU, Class: "organizationalUnit", State: inventory.ObjLive,
			Parent: parent, Ancestry: anc, DN: ou.DN, RDN: "OU=" + ou.Name, DisplayName: ou.Name})
	}
	for _, o := range s.Objs {
		if o.Conn != conn {
			continue
		}
		ou := s.OUs[o.OU]
		anc := make([]inventory.GUID, 0, ou.Level+1)
		for _, c := range ou.Chain {
			anc = append(anc, inventory.GUID(s.OUs[c].GUID))
		}
		anc = append(anc, nc)
		ob := inventory.Observation{Object: inventory.GUID(o.GUID), NC: nc, Kind: o.Kind, Class: string(o.Kind), State: inventory.ObjLive,
			Parent: inventory.GUID(ou.GUID), Ancestry: anc, DN: o.DN, RDN: o.RDN, DisplayName: o.Display, SAMAccountName: o.Sam, UPN: o.UPN, Enabled: o.Enabled, SID: o.SID}
		attrs := map[string]any{}
		if o.Mail != "" {
			attrs["mail"] = o.Mail
		}
		if o.Host != "" {
			attrs["dNSHostName"] = o.Host
		}
		if len(attrs) > 0 {
			ob.Attributes = attrs
		}
		objs = append(objs, ob)
	}
	return head, objs
}
