package search

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/skenzeriq/activediq/internal/directory/inventory"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/rbac"
	"github.com/skenzeriq/activediq/internal/platform/searchkey"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/reportsql"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// ReadPermission is what universal search is read under at 2a. Every key kind of searchkey declares its own
// permission (rule 9); Service asks the producer for each distinct one.
const ReadPermission authz.Permission = "directory.read"

// DefaultTimeout is the safety net of rule 13 (the statement is expected to finish far inside it).
const DefaultTimeout = 2 * time.Second

// Default and largest group limits (contract).
const (
	DefaultGroupLimit = 5
	DefaultPageSize   = reportsql.MaxSearchGroupLimit
)

// Errors a caller maps to Problems. None carries the search text.
var (
	// ErrForbidden: no read scope can be produced for the caller (no producer, dead owner, refused token,
	// unsupported chain, no directory.read).
	ErrForbidden = errors.New("search: forbidden")
	// ErrUnavailable: the search could not finish in time or the index could not answer; no count is given.
	ErrUnavailable = errors.New("search: unavailable")
	// ErrCursorRequiresType: a cursor without a type.
	ErrCursorRequiresType = errors.New("search: a cursor needs a type")
)

// QueryError is a refused text. Code is the contract's errors[].code. It carries no text.
type QueryError struct{ Code string }

func (e *QueryError) Error() string { return "search: query refused: " + e.Code }

// The codes of the contract's SearchQueryInvalid response.
const (
	CodeTooShort  = "query_too_short"
	CodeTooLong   = "query_too_long"
	CodeInvalid   = "query_invalid"
	CodeRefused   = "query_refused"
	CodeCursor    = "cursor_invalid"
	CodeCursorTyp = "cursor_requires_type"
)

// ReadScopes produces the caller's read scope for one permission: the composed port over the one producer,
// rbac.ReadScopes.For (T-0987). It is the same method set as directory.ReadScopes, which the composition
// root's implementation satisfies.
type ReadScopes interface {
	ReadScope(ctx context.Context, tid tenant.ID, chain authority.Chain, perm authz.Permission) (authz.ReadScope, error)
}

// Index is the inventory search port (ADR-0011 rule 11). *inventory.Searcher implements it.
type Index interface {
	Search(ctx context.Context, tx store.Tx, tid tenant.ID, scopes reportsql.SearchScopes, req inventory.SearchRequest) (inventory.SearchResult, error)
	SearchMetadata(ctx context.Context, tx store.Tx, tid tenant.ID, scope authz.ReadScope, now time.Time, hits []reportsql.SearchHit) (map[inventory.SearchRef]inventory.SearchMeta, error)
}

// Tenants opens the tenant transaction the index reads in. *store.DB implements it.
type Tenants interface {
	WithTenant(ctx context.Context, id tenant.ID, fn func(ctx context.Context, tx store.Tx) error) error
}

// Freshness answers the as-of of the inventory behind an answer: the oldest last sync pass among the given
// connections, or the zero time when none has completed one.
type Freshness interface {
	AsOf(ctx context.Context, tid tenant.ID, connections []authz.ObjectID, now time.Time) (time.Time, error)
}

// Service answers universal search.
type Service struct {
	DB      Tenants
	Scopes  ReadScopes
	Index   Index
	Fresh   Freshness
	Cursors Cursors
	Log     *slog.Logger
	Now     func() time.Time
	// Timeout bounds one search; zero means DefaultTimeout.
	Timeout time.Duration
}

// Call is one search as the handler gives it: the authenticated tenant and the human behind the session.
type Call struct {
	Tenant tenant.ID
	Chain  authority.Chain
	// Text is the typed text, never logged.
	Text string
	// Type is the facet; zero means all four groups.
	Type reportsql.SearchType
	// Limit is the hits per group (page size with a cursor); zero means the default.
	Limit int
	// Cursor is the opaque cursor of a "show all" page.
	Cursor string
}

// Hit is one permitted object.
type Hit struct {
	Type                                    reportsql.SearchType
	Object                                  string
	DisplayName                             string
	Class                                   reportsql.SearchClass
	Highlights                              []Highlight
	SAMAccountName, UserPrincipalName, Mail string
	DN, Domain                              string
	// Disambiguator is title, office and department as stored; a member that was never read is "".
	Title, Office, Department string
	// Status are the chips, most urgent first. A chip exists only for a stored fact; unknown inputs add none.
	Status []Chip
}

// Group is the permitted hits of one type. Count is nil when it is not exact (under 3 characters, refine,
// or a cursor page); More and NextCursor are zero under refine.
type Group struct {
	Type         reportsql.SearchType
	Items        []Hit
	Count        *int
	More         bool
	NextCursor   string
	LimitReached bool
}

// Result is the grouped answer.
type Result struct {
	// AsOf is the zero time when nothing has synced yet.
	AsOf   time.Time
	Refine bool
	Groups []Group
}

func (s *Service) log() *slog.Logger {
	if s.Log != nil {
		return s.Log
	}
	return slog.Default()
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// queryError maps a searchkey refusal to its contract code. The log line carries the code only.
func (s *Service) queryError(err error) error {
	code := CodeInvalid
	switch {
	case errors.Is(err, searchkey.ErrEmpty):
		code = CodeTooShort
	case errors.Is(err, searchkey.ErrTooLong), errors.Is(err, searchkey.ErrTooManyRunes):
		code = CodeTooLong
	case errors.Is(err, searchkey.ErrRecoveryPassword):
		code = CodeRefused
	}
	s.log().Info("directory search refused", "reason", code)
	return &QueryError{Code: code}
}

var shapeNames = map[searchkey.Shape]string{
	searchkey.ShapeText: "text", searchkey.ShapeSAM: "sam", searchkey.ShapeDomainSAM: "domain_sam", searchkey.ShapeEmail: "email",
	searchkey.ShapeHost: "host", searchkey.ShapeSID: "sid", searchkey.ShapeGUID: "guid", searchkey.ShapeDN: "dn",
}

// scopes asks the producer for the read scope of every permission the key kinds are read under. A failure of
// directory.read is a refusal; a gated permission the caller does not hold is simply absent, and its kinds
// compile to nothing.
func (s *Service) scopes(ctx context.Context, c Call) (reportsql.SearchScopes, error) {
	if s.Scopes == nil {
		return nil, ErrForbidden
	}
	out := reportsql.SearchScopes{}
	for _, k := range searchkey.AllKinds {
		perm := authz.Permission(k.Permission())
		if _, done := out[perm]; done {
			continue
		}
		sc, err := s.Scopes.ReadScope(ctx, c.Tenant, c.Chain, perm)
		switch {
		case err == nil:
			out[perm] = sc
		case errors.Is(err, authz.ErrOwnerDead), errors.Is(err, authz.ErrTokenRefused), errors.Is(err, rbac.ErrUnsupportedChain), errors.Is(err, rbac.ErrDenied):
			if perm == ReadPermission {
				return nil, ErrForbidden
			}
		default:
			s.log().Error("directory search: read scope failed", "error_class", "store")
			return nil, err
		}
	}
	return out, nil
}

// Search answers one search. The order is: refuse the text (nothing read), ask the producer for the scope,
// verify the cursor against that scope, then one tenant transaction with the index statement and its batched
// metadata read.
func (s *Service) Search(ctx context.Context, c Call) (Result, error) {
	if s == nil || s.Index == nil || s.DB == nil {
		return Result{}, ErrUnavailable
	}
	parsed, err := searchkey.Classify(c.Text)
	if err != nil {
		return Result{}, s.queryError(err)
	}
	prepared, _ := searchkey.Prepare(c.Text) // cannot fail: Classify ran it
	prepared = strings.TrimSpace(prepared)
	if c.Cursor != "" && c.Type == 0 {
		return Result{}, ErrCursorRequiresType
	}
	scopes, err := s.scopes(ctx, c)
	if err != nil {
		return Result{}, err
	}
	types := reportsql.AllSearchTypes
	if c.Type != 0 {
		types = []reportsql.SearchType{c.Type}
	}
	limit := c.Limit
	if limit == 0 {
		limit = DefaultGroupLimit
		if c.Cursor != "" {
			limit = DefaultPageSize
		}
	}

	bind := cursorBinding{Query: prepared, Classes: classSet(parsed), Type: c.Type, Scopes: scopes}
	var after *reportsql.SearchAfter
	sent := 0
	if c.Cursor != "" {
		a, n, err := s.Cursors.Verify(c.Cursor, bind)
		if err != nil {
			s.log().Info("directory search refused", "reason", CodeCursor)
			return Result{}, err
		}
		after, sent = &a, n
		limit = min(limit, MaxPagedHits-sent)
	}

	s.log().Info("directory search", "rune_length", utf8.RuneCountInString(prepared), "shapes", shapeList(parsed), "classes", bind.Classes, "paged", c.Cursor != "")

	// An empty scope grants nothing: the answer is empty and nothing is read (rule 10).
	if sc := scopes[ReadPermission]; sc.Empty() {
		return emptyResult(types, parsed.Runes, c.Cursor != ""), nil
	}

	timeout := s.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var res inventory.SearchResult
	var meta map[inventory.SearchRef]inventory.SearchMeta
	err = s.DB.WithTenant(ctx, c.Tenant, func(ctx context.Context, tx store.Tx) error {
		var err error
		res, err = s.Index.Search(ctx, tx, c.Tenant, scopes, inventory.SearchRequest{Text: c.Text, Types: types, GroupLimit: limit, After: after})
		if err != nil {
			return err
		}
		meta, err = s.Index.SearchMetadata(ctx, tx, c.Tenant, scopes[ReadPermission], s.now(), res.Hits)
		return err
	})
	if err != nil {
		return Result{}, s.indexError(ctx, err)
	}

	out := Result{Refine: res.Refine}
	if s.Fresh != nil {
		var conns []authz.ObjectID
		for _, sc := range scopes {
			conns = append(conns, sc.Connections()...)
		}
		if len(conns) > 0 {
			if out.AsOf, err = s.Fresh.AsOf(ctx, c.Tenant, dedupe(conns), s.now()); err != nil {
				s.log().Error("directory search: freshness failed", "error_class", "store")
				return Result{}, s.indexError(ctx, err)
			}
		}
	}

	byType := map[reportsql.SearchType][]Hit{}
	last := map[reportsql.SearchType]reportsql.SearchAfter{}
	for _, h := range res.Hits {
		byType[h.Group] = append(byType[h.Group], present(h, meta[inventory.SearchRef{Connection: h.Connection, Object: h.Object}], prepared, s.now()))
		last[h.Group] = h.Rank
	}
	for _, t := range types {
		g := Group{Type: t, Items: byType[t]}
		if g.Items == nil {
			g.Items = []Hit{}
		}
		if !res.Refine {
			if res.Count != nil && c.Cursor == "" {
				n := res.Count[t]
				g.Count = &n
			}
			if res.More[t] {
				g.More = true
				switch total := sent + len(g.Items); {
				case total >= MaxPagedHits:
					g.LimitReached = true
				default:
					b := bind
					b.Type = t
					if g.NextCursor, err = s.Cursors.Sign(last[t], total, b); err != nil {
						s.log().Error("directory search: cursor signing failed", "error_class", "internal")
						return Result{}, err
					}
				}
			}
		}
		out.Groups = append(out.Groups, g)
	}
	hideSingleDomain(out.Groups)
	return out, nil
}

// indexError separates "ran out of time or the statement timed out" (a generic unavailable, no count) from a
// fault. Neither carries text.
func (s *Service) indexError(ctx context.Context, err error) error {
	switch {
	case errors.Is(err, reportsql.ErrQueryTimeout), errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled), ctx.Err() != nil:
		s.log().Warn("directory search timed out")
		return ErrUnavailable
	case errors.Is(err, reportsql.ErrScopeTooLarge):
		s.log().Warn("directory search: read scope too large to render")
		return ErrUnavailable
	}
	s.log().Error("directory search failed", "error_class", "internal")
	return err
}

func emptyResult(types []reportsql.SearchType, runes int, paged bool) Result {
	r := Result{}
	for _, t := range types {
		g := Group{Type: t, Items: []Hit{}}
		if runes >= 3 && !paged {
			zero := 0
			g.Count = &zero
		}
		r.Groups = append(r.Groups, g)
	}
	return r
}

func classSet(p searchkey.Parsed) string {
	var b []string
	if len(p.Exact) > 0 {
		b = append(b, "exact")
	}
	if len(p.Prefix) > 0 {
		b = append(b, "prefix")
	}
	if p.Fuzzy != "" {
		b = append(b, "fuzzy")
	}
	return strings.Join(b, "+")
}

func shapeList(p searchkey.Parsed) string {
	var b []string
	for _, s := range p.Shapes {
		b = append(b, shapeNames[s])
	}
	return strings.Join(b, "+")
}

func dedupe(in []authz.ObjectID) []authz.ObjectID {
	seen := map[authz.ObjectID]bool{}
	var out []authz.ObjectID
	for _, c := range in {
		if !seen[c] {
			seen[c] = true
			out = append(out, c)
		}
	}
	return out
}
