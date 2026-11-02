package ad

import (
	"context"
	"errors"
	"strings"

	"github.com/go-ldap/ldap/v3"

	"github.com/skenzeriq/activediq/internal/directory/dn"
	"github.com/skenzeriq/activediq/internal/directory/ldapfilter"
)

// Scope of a search. There is no "above the base" and the root of a search is always typed.
type Scope uint8

const (
	ScopeBase Scope = iota + 1
	ScopeOneLevel
	ScopeSubtree
)

func (s Scope) ldap() (int, bool) {
	switch s {
	case ScopeBase:
		return ldap.ScopeBaseObject, true
	case ScopeOneLevel:
		return ldap.ScopeSingleLevel, true
	case ScopeSubtree:
		return ldap.ScopeWholeSubtree, true
	}
	return 0, false
}

const (
	oidDomainScope = "1.2.840.113556.1.4.1339"
)

// objectClassPresent is the filter for "any object": rendered by the builder, like every filter.
var objectClassPresent = func() string {
	a, err := ldapfilter.ParseAttrName("objectClass", DefaultSchema())
	if err != nil {
		panic(err)
	}
	f, err := ldapfilter.Render(ldapfilter.Present(a), DefaultSchema())
	if err != nil {
		panic(err)
	}
	return f.String()
}()

// domainScope is the control that stops the DC returning continuation references.
type domainScope struct{}

func (domainScope) GetControlType() string { return oidDomainScope }
func (domainScope) Encode() *berPacket     { return encodeValuelessControl(oidDomainScope) }
func (domainScope) String() string         { return "Domain scope control" }

// SearchRequest is a paged search. Base is a typed reference (DN or GUID); Filter is a typed AST.
type SearchRequest struct {
	Base       dn.ObjectRef
	Scope      Scope
	Filter     ldapfilter.Filter
	Attributes []string // explicit names; "*" and "+" are refused
	PageSize   uint32   // 0 = the session default; clamped to MaxPageSize
	// ExtendedDN asks the DC for extended DNs (<GUID=…>;<SID=…>;dn) in DN-syntax values, so a link
	// value carries the identity of its target. Entry.DN stays plain.
	ExtendedDN bool
}

// Search streams every matching entry to fn, one page at a time; it never buffers the result set.
// fn returning an error stops the search and releases the DC's paging state. Referrals are never
// chased and fail the search. Constructed attributes (tokenGroups ...) are refused here: they are
// Read-only.
func (s *Session) Search(ctx context.Context, req SearchRequest, fn func(*Entry) error) error {
	if fn == nil {
		return fail(CodeInvalidArgument, "callback required", nil)
	}
	return s.search(ctx, req, func(page []*Entry) error {
		for _, e := range page {
			if err := fn(e); err != nil {
				return err
			}
		}
		return nil
	})
}

// search validates req and runs the paged loop, handing each page to deliver.
func (s *Session) search(ctx context.Context, req SearchRequest, deliver func([]*Entry) error) error {
	scope, ok := req.Scope.ldap()
	if !ok {
		return fail(CodeInvalidArgument, "scope", nil)
	}
	base, err := req.Base.ForRequest()
	if err != nil {
		return fail(CodeInvalidArgument, "base", err)
	}
	flt, err := ldapfilter.Render(req.Filter, s.schema)
	if err != nil {
		return fail(CodeFilterRejected, ldapfilter.Code(err), err)
	}
	if len(req.Attributes) == 0 {
		return fail(CodeInvalidArgument, "attributes required", nil)
	}
	attrs, err := s.checkAttrs(req.Attributes, false)
	if err != nil {
		return err
	}
	ps := req.PageSize
	if ps == 0 {
		ps = s.pageSize
	}
	if ps > MaxPageSize {
		ps = MaxPageSize
	}

	var extra []ldap.Control
	if req.ExtendedDN {
		extra = append(extra, extendedDN{})
	}
	return s.pages(ctx, base, scope, flt.String(), attrs, ps, extra, deliver)
}

// SearchPages is Search delivering one whole page at a time. The session lock is NOT held while
// page runs, so page may call Read and the other session methods (resolving parents, T-0694); the
// lock is taken only around each page request, so a long page callback does not starve other users
// of the session. Paging state lives on the DC per search, and AD allows other operations on the
// connection while a cursor is open.
func (s *Session) SearchPages(ctx context.Context, req SearchRequest, page func([]*Entry) error) error {
	if page == nil {
		return fail(CodeInvalidArgument, "callback required", nil)
	}
	return s.search(ctx, req, page)
}

// pages runs the paged loop. The lock is held only for each round trip, never across deliver.
func (s *Session) pages(ctx context.Context, base string, scope int, flt string, attrs []string, ps uint32, extra []ldap.Control, deliver func([]*Entry) error) error {
	// one round trip under the lock
	trip := func(c []byte, size uint32) (*ldap.SearchResult, error) {
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.conn == nil {
			return nil, fail(CodeUnreachable, "session closed", nil)
		}
		stop := s.watch(ctx, s.conn)
		defer stop()
		p := ldap.NewControlPaging(size)
		p.SetCookie(c)
		return s.searchOnceLocked(ctx, base, scope, flt, attrs, append([]ldap.Control{p}, extra...))
	}
	// abandon tells the DC to drop a paging cursor: the same request with page size 0 and the cookie.
	abandon := func(c []byte) {
		if len(c) != 0 {
			_, _ = trip(c, 0)
		}
	}
	var cookie []byte
	for {
		res, err := trip(cookie, ps)
		if err != nil {
			return err
		}
		next := pagingCookie(res.Controls)
		page := make([]*Entry, len(res.Entries))
		for i, e := range res.Entries {
			page[i] = toEntry(e)
		}
		if err := deliver(page); err != nil {
			abandon(next)
			return err
		}
		if len(next) == 0 {
			return nil
		}
		if err := ctx.Err(); err != nil {
			return fail(CodeCanceled, "", err) // the watcher closes the connection, which frees the cursor
		}
		cookie = next
	}
}

func pagingCookie(ctrls []ldap.Control) []byte {
	if c := ldap.FindControl(ctrls, ldap.ControlTypePaging); c != nil {
		if p, ok := c.(*ldap.ControlPaging); ok {
			return p.Cookie
		}
	}
	return nil
}

// checkAttrs validates requested attribute names with the schema allowlist and refuses secrets.
// Constructed attributes are allowed only when allowConstructed (Read).
func (s *Session) checkAttrs(names []string, allowConstructed bool) ([]string, error) {
	out := make([]string, 0, len(names))
	seen := map[string]struct{}{}
	for _, n := range names {
		a, err := ldapfilter.ParseAttrName(n, s.schema)
		if err != nil {
			return nil, fail(CodeInvalidArgument, "attribute: "+ldapfilter.Code(err), err)
		}
		// Render a presence test to learn how the schema classifies the attribute: the builder is
		// the single place that knows Secret and Constructed.
		_, rerr := ldapfilter.Render(ldapfilter.Present(a), s.schema)
		switch ldapfilter.Code(rerr) {
		case ldapfilter.SecretAttribute:
			return nil, fail(CodeSecretAttribute, "", rerr)
		case "", ldapfilter.ConstructedNotFilterable:
		default:
			return nil, fail(CodeInvalidArgument, "attribute: "+ldapfilter.Code(rerr), rerr)
		}
		key := strings.ToLower(a.String())
		if _, ro := constructedReadOnly[key]; ro && !allowConstructed {
			return nil, fail(CodeAttributeNotAllowed, "constructed attribute is Read-only", nil)
		}
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, a.String())
	}
	return out, nil
}

func (s *Session) searchOnce(ctx context.Context, base string, scope int, filter string, attrs []string, ctrls []ldap.Control) (*ldap.SearchResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn == nil {
		return nil, fail(CodeUnreachable, "session closed", nil)
	}
	stop := s.watch(ctx, s.conn)
	defer stop()
	return s.searchOnceLocked(ctx, base, scope, filter, attrs, ctrls)
}

// searchOnceLocked runs one request with the domain-scope control and maps results to our errors.
func (s *Session) searchOnceLocked(ctx context.Context, base string, scope int, filter string, attrs []string, ctrls []ldap.Control) (*ldap.SearchResult, error) {
	return s.searchRaw(ctx, base, scope, filter, attrs, append([]ldap.Control{domainScope{}}, ctrls...))
}

func (s *Session) searchRaw(ctx context.Context, base string, scope int, filter string, attrs []string, ctrls []ldap.Control) (*ldap.SearchResult, error) {
	req := ldap.NewSearchRequest(base, scope, ldap.NeverDerefAliases, 0, int(s.cfg.Timeout.Seconds()), false, filter, attrs, ctrls)
	res, err := s.conn.Search(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, fail(CodeCanceled, "", ctx.Err())
		}
		var le *ldap.Error
		if errors.As(err, &le) {
			switch le.ResultCode {
			case ldap.LDAPResultNoSuchObject:
				return nil, fail(CodeObjectNotFound, "", nil)
			case ldap.LDAPResultInsufficientAccessRights:
				return nil, fail(CodeInsufficientRights, "", nil)
			case ldap.LDAPResultReferral:
				return nil, fail(CodeUnexpectedReferral, "", nil)
			}
			return nil, fail(CodeProtocol, ldapCode(err), nil)
		}
		return nil, fail(CodeUnreachable, ldapCode(err), nil)
	}
	if len(res.Referrals) > 0 {
		return nil, fail(CodeUnexpectedReferral, "", nil) // count only; URLs are never kept (LF-32)
	}
	return res, nil
}

func toEntry(e *ldap.Entry) *Entry {
	out := newEntry(plainDN(e.DN))
	for _, a := range e.Attributes {
		out.attrs[strings.ToLower(a.Name)] = a.ByteValues
	}
	return out
}
