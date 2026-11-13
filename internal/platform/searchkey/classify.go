package searchkey

import (
	"regexp"
	"strings"
	"unicode/utf8"
)

// Kind is the key_kind stored with a key (ADR-0011 rule 9). The numbers are stored: never renumber.
type Kind int16

// The key kinds of the 2a set. Every one is read under DirectoryRead.
const (
	KindName            Kind = 1  // display name and rdn value, NormName form
	KindNameWord        Kind = 2  // one word of a multi-word name
	KindSAM             Kind = 3  // sAMAccountName (computers also without the trailing $)
	KindUPN             Kind = 4  // userPrincipalName
	KindMail            Kind = 5  // contact mail
	KindDNSHost         Kind = 6  // dNSHostName
	KindSID             Kind = 7  // S-1-5-… canonical text
	KindGUID            Kind = 8  // objectGUID canonical text
	KindConsistencyGUID Kind = 9  // ms-DS-ConsistencyGuid as a GUID, and as base64
	KindDN              Kind = 10 // dn snapshot
	// Added by T-1129 (migration 0074). The BitLocker key ID is not here: it is gated by a permission the
	// catalogue does not define yet (ADR-0011 rule 9), so it has no kind until that ticket adds both.
	KindMailNickname Kind = 11 // mailNickname
	KindEmployeeID   Kind = 12 // employeeID and employeeNumber, NormIdent form (leading zeros kept)
	KindSIDHistory   Kind = 13 // sIDHistory values, canonical S-1-5-… text
	KindSPN          Kind = 14 // a whole servicePrincipalName, NormIdent form (the host part is also a dns_host key)
	KindOrgText      Kind = 15 // title and department: NormName of the whole value, and its words
)

// DirectoryRead is the permission every 2a kind is read under. A gated kind (the BitLocker key ID,
// T-1129) names another permission here and is only searched with a scope for that permission.
const DirectoryRead = "directory.read"

// AllKinds lists the kinds in key order.
var AllKinds = []Kind{KindName, KindNameWord, KindSAM, KindUPN, KindMail, KindDNSHost, KindSID, KindGUID, KindConsistencyGUID, KindDN, KindMailNickname, KindEmployeeID, KindSIDHistory, KindSPN, KindOrgText}

// Valid reports whether k is a known kind.
func (k Kind) Valid() bool { return k >= KindName && k <= KindOrgText }

// FuzzyEligible kinds have trigram postings (ADR-0011 rule 5a): name and sam. A name_word is redundant
// for word_similarity against the whole name; upn and mail carry a domain suffix that multiplies the
// postings and adds nothing to name matching. migration 0073's trigger function names the same list.
func (k Kind) FuzzyEligible() bool {
	switch k {
	case KindName, KindSAM:
		return true
	}
	return false
}

// MaxFuzzyRunes is the longest normalised query that gets a fuzzy class (ADR-0011 rule 8). It bounds the
// number of trigrams of the query, so the candidate aggregate reads a bounded number of posting lists.
const MaxFuzzyRunes = 32

// Permission is the permission the kind is read under.
func (k Kind) Permission() string { return DirectoryRead }

// Shape is what a query looks like (rule 9). A query can have several: "jsmith" is both a sam and a host name.
type Shape uint8

// Shapes.
const (
	ShapeText Shape = iota + 1
	ShapeSAM
	ShapeDomainSAM // DOMAIN\sam
	ShapeEmail     // x@y: a UPN, a mail, or sam@dnsdomain
	ShapeHost      // a host name or FQDN
	ShapeSID
	ShapeGUID
	ShapeDN
	ShapeDigits // digits only: an employeeID or employeeNumber (also tried as text)
	ShapeSPN    // service/host[:port][/name]
)

// Probe is one exact lookup: the key of Kind equals Key.
type Probe struct {
	Kind Kind
	Key  string
}

// Prefix is one prefix lookup: the keys of Kind that start with Lo. Hi is the exclusive upper bound
// (PrefixUpper); Bounded false means there is none.
type Prefix struct {
	Kind    Kind
	Lo, Hi  string
	Bounded bool
}

// Parsed is a prepared and classified query: the only form the search statement is built from. It
// holds normalised text for bind parameters, never SQL.
type Parsed struct {
	Shapes []Shape
	// Name is the NormName form. Runes counts its characters: fuzzy matching and counts need three.
	Name  string
	Runes int
	// Domain is the DOMAIN or dnsdomain part of DOMAIN\sam or sam@domain, NormIdent form. It narrows to
	// the connection with that name when the connection record holds one; at 2a it holds none, so it is
	// dropped and the sam matches in every connection (rule 9). It is never an error.
	Domain string
	Exact  []Probe
	Prefix []Prefix
	// Fuzzy is the text for the trigram operator; empty when the query is shorter than three or longer than
	// MaxFuzzyRunes characters.
	Fuzzy string
}

var (
	guidRE   = regexp.MustCompile(`^\{?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\}?$`)
	sidRE    = regexp.MustCompile(`^s-1-[0-9]+(-[0-9]+){1,15}$`)
	b64GUID  = regexp.MustCompile(`^[a-z0-9+/]{22}==$`)
	hostRE   = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]*(\.[a-z0-9_-]+)*\$?$`)
	dnStartR = regexp.MustCompile(`^(cn|ou|dc|uid|o)=`)
)

// Classify prepares a query (rule 7 refusals) and works out which exact and prefix lookups and which
// fuzzy text apply. A refused query returns the refusal and nothing else.
func Classify(raw string) (Parsed, error) {
	s, err := Prepare(raw)
	if err != nil {
		return Parsed{}, err
	}
	s = strings.TrimSpace(s)
	if s == "" {
		return Parsed{}, ErrEmpty
	}
	p := Parsed{Name: NormName(s)}
	p.Runes = utf8.RuneCountInString(p.Name)
	ident := NormIdent(s)
	noSpace := !strings.ContainsAny(ident, " \t\r\n")

	addExact := func(k Kind, key string) {
		if key != "" {
			p.Exact = append(p.Exact, Probe{k, key})
		}
	}
	addPrefix := func(k Kind, lo string) {
		if lo == "" {
			return
		}
		hi, ok := PrefixUpper(lo)
		p.Prefix = append(p.Prefix, Prefix{Kind: k, Lo: lo, Hi: hi, Bounded: ok})
	}

	switch {
	case guidRE.MatchString(ident):
		g := guidRE.FindStringSubmatch(ident)[1]
		p.Shapes = append(p.Shapes, ShapeGUID)
		addExact(KindGUID, g)
		addExact(KindConsistencyGUID, g)
	case b64GUID.MatchString(ident):
		p.Shapes = append(p.Shapes, ShapeGUID)
		addExact(KindConsistencyGUID, ident)
	case sidRE.MatchString(ident):
		p.Shapes = append(p.Shapes, ShapeSID)
		addExact(KindSID, ident)
		addExact(KindSIDHistory, ident)
	case dnStartR.MatchString(ident) && strings.Contains(ident, ","):
		p.Shapes = append(p.Shapes, ShapeDN)
		addExact(KindDN, NormDN(s))
	case noSpace && strings.Count(ident, `\`) == 1 && !strings.Contains(ident, "="):
		dom, sam, _ := strings.Cut(ident, `\`)
		p.Shapes = append(p.Shapes, ShapeDomainSAM)
		p.Domain = dom
		addExact(KindSAM, sam)
		addPrefix(KindSAM, sam)
	case noSpace && strings.Count(ident, "@") == 1 && !strings.HasPrefix(ident, "@") && !strings.HasSuffix(ident, "@"):
		local, dom, _ := strings.Cut(ident, "@")
		p.Shapes = append(p.Shapes, ShapeEmail)
		p.Domain = dom
		addExact(KindUPN, ident)
		addExact(KindMail, ident)
		addExact(KindSAM, local)
		addPrefix(KindUPN, ident)
		addPrefix(KindMail, ident)
	case noSpace && strings.Contains(ident, "/") && !strings.Contains(ident, "=") && !strings.HasPrefix(ident, "/"):
		p.Shapes = append(p.Shapes, ShapeSPN)
		addExact(KindSPN, ident)
		addPrefix(KindSPN, ident)
	case noSpace && hostRE.MatchString(ident):
		p.Shapes = append(p.Shapes, ShapeSAM, ShapeHost)
		if allDigits(ident) {
			p.Shapes = append(p.Shapes, ShapeDigits)
		}
		// A token with no dot may also be an employeeID or a mail alias.
		if !strings.ContainsAny(ident, ".$") {
			addExact(KindEmployeeID, ident)
			addExact(KindMailNickname, ident)
			addPrefix(KindEmployeeID, ident)
			addPrefix(KindMailNickname, ident)
		}
		addExact(KindSAM, ident)
		addExact(KindDNSHost, ident)
		addExact(KindName, p.Name)
		addPrefix(KindSAM, ident)
		addPrefix(KindDNSHost, ident)
		addPrefix(KindUPN, ident)
		addPrefix(KindMail, ident)
	default:
		p.Shapes = append(p.Shapes, ShapeText)
	}
	if len(p.Shapes) == 0 {
		p.Shapes = []Shape{ShapeText}
	}

	// Name matching always runs: "jsmith" also prefix-matches "jsmith2" and "pri" finds "Priya Raman".
	addPrefix(KindName, p.Name)
	addPrefix(KindOrgText, p.Name)
	if p.Name != "" && !strings.Contains(p.Name, " ") {
		addPrefix(KindNameWord, p.Name)
	}
	// "Raman, Priya": exactly one comma with text on both sides is also tried swapped.
	if strings.Count(s, ",") == 1 {
		l, r, _ := strings.Cut(s, ",")
		if sw := NormName(r + " " + l); NormName(l) != "" && NormName(r) != "" && sw != p.Name {
			addPrefix(KindName, sw)
		}
	}
	if p.Runes >= 3 && p.Runes <= MaxFuzzyRunes {
		p.Fuzzy = p.Name
	}
	return p, nil
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
