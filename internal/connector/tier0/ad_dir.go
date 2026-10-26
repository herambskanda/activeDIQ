package tier0

import (
	"context"
	"errors"
	"strings"

	"github.com/skenzeriq/activediq/internal/connector/ad"
	"github.com/skenzeriq/activediq/internal/directory/attr/sid"
	"github.com/skenzeriq/activediq/internal/directory/dn"
	"github.com/skenzeriq/activediq/internal/directory/ldapfilter"
)

// Naming holds the naming-context heads of the bound domain's forest (rootDSE).
type Naming struct {
	Domain, RootDomain, Config, Schema dn.DN
}

// AttrEq and AttrInt are equality terms of a Query.
type AttrEq struct{ Attr, Value string }
type AttrInt struct {
	Attr  string
	Value int32
}

// Query is the closed set of searches the classifier needs, expressed as data. The session adapter
// turns it into a typed filter (never a string); a test double evaluates it directly. Terms are
// AND-ed; Classes are OR-ed within their term. The zero Query matches every object.
type Query struct {
	Classes []string
	Eq      []AttrEq
	EqInt   []AttrInt
	// AnyInt matches objects where at least one of the terms holds (OR-ed, one term of the AND).
	AnyInt []AttrInt
	Has    []string
	// UACAny matches objects whose userAccountControl has any of these bits set.
	UACAny uint32
	// AnySID matches objects whose objectSid is any of these (OR-ed, one term of the AND).
	AnySID []sid.SID
}

// ADDirectory is what the AD classifier reads through. *Session wraps an *ad.Session; tests use an
// in-memory forest. Every method must be paged/ranged and return entries that carry objectGUID.
type ADDirectory interface {
	Naming(ctx context.Context) (Naming, error)
	// Get reads one object. A missing object is an *ad.Error with CodeObjectNotFound.
	Get(ctx context.Context, ref dn.ObjectRef, attrs []string) (*ad.Entry, error)
	// Find streams the objects under base matching q.
	Find(ctx context.Context, base dn.DN, scope ad.Scope, q Query, attrs []string, fn func(*ad.Entry) error) error
}

// ForestDirectory is the second seam, for a sIDHistory value whose domain is another domain of the
// forest (TM-D26 rule 6b). A domain controller cannot resolve that SID; the Global Catalog can.
// An ADDirectory that does not implement it cannot resolve a foreign-domain SID, and the classifier
// then fails closed (rule 8) instead of calling the value "unresolved".
type ForestDirectory interface {
	// ForestDomains are the SIDs of every domain in the forest.
	ForestDomains(ctx context.Context) ([]sid.SID, error)
	// GCLookup resolves a SID through the GC. found is false only when the GC has no such object;
	// any failure is an error.
	GCLookup(ctx context.Context, s sid.SID, attrs []string) (e *ad.Entry, found bool, err error)
}

// ErrNoGC is returned by SessionDirectory when a foreign-domain SID must be resolved and no Global
// Catalog resolver is configured.
var ErrNoGC = errors.New("tier0: a Global Catalog is required to resolve a sIDHistory value from another domain")

// SessionDirectory adapts an *ad.Session to ADDirectory.
type SessionDirectory struct {
	S *ad.Session
	// GC resolves SIDs of other domains of the forest. Nil means such a SID fails closed.
	GC *ad.GCResolver
}

var (
	_ ADDirectory     = SessionDirectory{}
	_ ForestDirectory = SessionDirectory{}
)

func (d SessionDirectory) ForestDomains(ctx context.Context) ([]sid.SID, error) {
	if d.GC == nil {
		return nil, ErrNoGC
	}
	return d.GC.DomainSIDs(ctx)
}

func (d SessionDirectory) GCLookup(ctx context.Context, s sid.SID, attrs []string) (*ad.Entry, bool, error) {
	if d.GC == nil {
		return nil, false, ErrNoGC
	}
	return d.GC.LookupSID(ctx, s, attrs)
}

func (d SessionDirectory) Naming(ctx context.Context) (Naming, error) {
	r, err := d.S.RootDSE(ctx)
	if err != nil {
		return Naming{}, err
	}
	var n Naming
	for _, x := range []struct {
		src string
		dst *dn.DN
	}{{r.DefaultNamingContext, &n.Domain}, {r.RootDomainNamingContext, &n.RootDomain},
		{r.ConfigurationNamingContext, &n.Config}, {r.SchemaNamingContext, &n.Schema}} {
		v, err := dn.Parse(x.src, dn.Strict)
		if err != nil {
			return Naming{}, err
		}
		*x.dst = v
	}
	return n, nil
}

func (d SessionDirectory) Get(ctx context.Context, ref dn.ObjectRef, attrs []string) (*ad.Entry, error) {
	return d.S.Read(ctx, ref, attrs, ad.ReadOptions{})
}

func (d SessionDirectory) Find(ctx context.Context, base dn.DN, scope ad.Scope, q Query, attrs []string, fn func(*ad.Entry) error) error {
	f, err := q.filter()
	if err != nil {
		return err
	}
	return d.S.Search(ctx, ad.SearchRequest{Base: dn.DNRef(base), Scope: scope, Filter: f, Attributes: attrs}, fn)
}

// filter renders q with the typed builder.
func (q Query) filter() (ldapfilter.Filter, error) {
	sc := ad.DefaultSchema()
	attr := func(n string) (ldapfilter.AttrName, error) { return ldapfilter.ParseAttrName(n, sc) }
	var terms []ldapfilter.Filter
	if len(q.Classes) > 0 {
		oc, err := attr("objectClass")
		if err != nil {
			return nil, err
		}
		var alts []ldapfilter.Filter
		for _, c := range q.Classes {
			alts = append(alts, ldapfilter.Eq(oc, ldapfilter.String(c)))
		}
		terms = append(terms, ldapfilter.Or(alts...))
	}
	for _, e := range q.Eq {
		a, err := attr(e.Attr)
		if err != nil {
			return nil, err
		}
		terms = append(terms, ldapfilter.Eq(a, ldapfilter.String(e.Value)))
	}
	for _, e := range q.EqInt {
		a, err := attr(e.Attr)
		if err != nil {
			return nil, err
		}
		terms = append(terms, ldapfilter.Eq(a, ldapfilter.Int32(e.Value)))
	}
	if len(q.AnyInt) > 0 {
		var alts []ldapfilter.Filter
		for _, e := range q.AnyInt {
			a, err := attr(e.Attr)
			if err != nil {
				return nil, err
			}
			alts = append(alts, ldapfilter.Eq(a, ldapfilter.Int32(e.Value)))
		}
		terms = append(terms, ldapfilter.Or(alts...))
	}
	if len(q.AnySID) > 0 {
		a, err := attr("objectSid")
		if err != nil {
			return nil, err
		}
		var alts []ldapfilter.Filter
		for _, s := range q.AnySID {
			alts = append(alts, ldapfilter.Eq(a, ldapfilter.SID(s)))
		}
		terms = append(terms, ldapfilter.Or(alts...))
	}
	for _, h := range q.Has {
		a, err := attr(h)
		if err != nil {
			return nil, err
		}
		terms = append(terms, ldapfilter.Present(a))
	}
	if q.UACAny != 0 {
		a, err := attr("userAccountControl")
		if err != nil {
			return nil, err
		}
		terms = append(terms, ldapfilter.BitOr(a, q.UACAny))
	}
	if len(terms) == 0 {
		oc, err := attr("objectClass")
		if err != nil {
			return nil, err
		}
		return ldapfilter.Present(oc), nil
	}
	return ldapfilter.And(terms...), nil
}

// wellKnownDN extracts the DN for a well-known GUID from wellKnownObjects values
// ("B:32:<hex guid>:<DN>"). It returns false when absent.
func wellKnownDN(values []string, hexGUID string) (string, bool) {
	prefix := "B:32:" + hexGUID + ":"
	for _, v := range values {
		if len(v) > len(prefix) && strings.EqualFold(v[:len(prefix)], prefix) {
			return v[len(prefix):], true
		}
	}
	return "", false
}
