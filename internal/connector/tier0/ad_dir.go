package tier0

import (
	"context"
	"strings"

	"github.com/skenzeriq/activediq/internal/connector/ad"
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
	Has     []string
	// UACAny matches objects whose userAccountControl has any of these bits set.
	UACAny uint32
}

// ADDirectory is what the AD classifier reads through. *Session wraps an *ad.Session; tests use an
// in-memory forest. Every method must be paged/ranged and return entries that carry objectGUID.
type ADDirectory interface {
	Naming(ctx context.Context) (Naming, error)
	// Get reads one object. A missing object is an *ad.Error with CodeObjectNotFound.
	Get(ctx context.Context, ref dn.ObjectRef, attrs []string) (*ad.Entry, error)
	// Find streams the objects under base matching q.
	Find(ctx context.Context, base dn.DN, scope ad.Scope, q Query, attrs []string, fn func(*ad.Entry) error) error
	// TransitiveMembers streams every transitive member (users, computers and nested groups) of a
	// group, resolved by the DC (LDAP_MATCHING_RULE_IN_CHAIN on memberOf), cycle-safe.
	TransitiveMembers(ctx context.Context, group dn.DN, attrs []string, fn func(*ad.Entry) error) error
}

// SessionDirectory adapts an *ad.Session to ADDirectory.
type SessionDirectory struct{ S *ad.Session }

var _ ADDirectory = SessionDirectory{}

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

func (d SessionDirectory) TransitiveMembers(ctx context.Context, group dn.DN, attrs []string, fn func(*ad.Entry) error) error {
	a, err := ldapfilter.ParseAttrName("memberOf", ad.DefaultSchema())
	if err != nil {
		return err
	}
	root, err := d.rootOf(ctx)
	if err != nil {
		return err
	}
	return d.S.Search(ctx, ad.SearchRequest{Base: dn.DNRef(root), Scope: ad.ScopeSubtree, Filter: ldapfilter.InChain(a, group), Attributes: attrs}, fn)
}

func (d SessionDirectory) rootOf(ctx context.Context) (dn.DN, error) {
	n, err := d.Naming(ctx)
	return n.Domain, err
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
