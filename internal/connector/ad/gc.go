package ad

import (
	"context"
	"errors"

	"github.com/go-ldap/ldap/v3"

	"github.com/skenzeriq/activediq/internal/directory/attr/sid"
	"github.com/skenzeriq/activediq/internal/directory/ldapfilter"
)

// GCResolver resolves a SID to its object through a Global Catalog (LDAPS, port 3269). It is a
// separate type from Session on purpose: LF-33 keeps every Session off the GC because the GC spans
// every domain, and the only thing activeDIQ wants from it is a read-only lookup by objectSid for the
// Tier-0 classifier (TM-D26 rule 6b/8). It exposes no search, no write and no secret read.
type GCResolver struct{ s *Session }

// OpenGC connects and binds to the first reachable Servers entry, each of which must be host:3269.
func OpenGC(ctx context.Context, cfg Config) (*GCResolver, error) {
	s, err := open(ctx, cfg, true)
	if err != nil {
		return nil, err
	}
	return &GCResolver{s: s}, nil
}

// Close releases the connection.
func (g *GCResolver) Close() error { return g.s.Close() }

// ErrAmbiguousSID is returned when more than one GC entry carries the SID: the answer is unknown.
var ErrAmbiguousSID = errors.New("ad: more than one object carries the SID")

// LookupSID returns the object whose objectSid is s, with attrs (the GC holds only the partial
// attribute set). found is false when the GC has no such object. Any failure is an error and never
// "not found": a caller that cannot tell must fail closed.
func (g *GCResolver) LookupSID(ctx context.Context, s sid.SID, attrs []string) (e *Entry, found bool, err error) {
	if len(attrs) == 0 {
		return nil, false, fail(CodeInvalidArgument, "attributes required", nil)
	}
	names, err := g.s.checkAttrs(attrs, false)
	if err != nil {
		return nil, false, err
	}
	a, err := ldapfilter.ParseAttrName("objectSid", g.s.schema)
	if err != nil {
		return nil, false, fail(CodeInvalidArgument, "objectSid", err)
	}
	flt, err := ldapfilter.Render(ldapfilter.Eq(a, ldapfilter.SID(s)), g.s.schema)
	if err != nil {
		return nil, false, fail(CodeFilterRejected, ldapfilter.Code(err), err)
	}
	var got []*Entry
	err = g.search(ctx, flt.String(), names, func(e *Entry) { got = append(got, e) })
	if err != nil {
		return nil, false, err
	}
	switch len(got) {
	case 0:
		return nil, false, nil
	case 1:
		return got[0], true, nil
	}
	return nil, false, ErrAmbiguousSID
}

// DomainSIDs returns the objectSid of every domain in the forest (the domainDNS objects the GC holds).
func (g *GCResolver) DomainSIDs(ctx context.Context) ([]sid.SID, error) {
	oc, err := ldapfilter.ParseAttrName("objectClass", g.s.schema)
	if err != nil {
		return nil, fail(CodeInvalidArgument, "objectClass", err)
	}
	flt, err := ldapfilter.Render(ldapfilter.Eq(oc, ldapfilter.String("domainDNS")), g.s.schema)
	if err != nil {
		return nil, fail(CodeFilterRejected, ldapfilter.Code(err), err)
	}
	var out []sid.SID
	var bad error
	err = g.search(ctx, flt.String(), []string{"objectSid"}, func(e *Entry) {
		ss, err := e.SIDs("objectSid")
		if err != nil || len(ss) != 1 {
			bad = fail(CodeProtocol, "domainDNS objectSid unreadable", err)
			return
		}
		out = append(out, ss[0])
	})
	if err != nil {
		return nil, err
	}
	if bad != nil {
		return nil, bad
	}
	if len(out) == 0 {
		return nil, fail(CodeProtocol, "the global catalog returned no domain", nil)
	}
	return out, nil
}

// search pages a forest-wide GC search from the empty base. No domain-scope control: that would
// limit the search to the server's own domain.
func (g *GCResolver) search(ctx context.Context, filter string, attrs []string, fn func(*Entry)) error {
	g.s.mu.Lock()
	defer g.s.mu.Unlock()
	if g.s.conn == nil {
		return fail(CodeUnreachable, "session closed", nil)
	}
	stop := g.s.watch(ctx, g.s.conn)
	defer stop()
	var cookie []byte
	for {
		paging := ldap.NewControlPaging(g.s.pageSize)
		paging.SetCookie(cookie)
		res, err := g.s.searchRaw(ctx, "", ldap.ScopeWholeSubtree, filter, attrs, []ldap.Control{paging})
		if err != nil {
			return err
		}
		for _, e := range res.Entries {
			fn(toEntry(e))
		}
		if cookie = pagingCookie(res.Controls); len(cookie) == 0 {
			return nil
		}
		if err := ctx.Err(); err != nil {
			return fail(CodeCanceled, "", err)
		}
	}
}
