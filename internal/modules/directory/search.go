package directory

import (
	"context"
	"encoding/json/jsontext"
	"errors"

	"github.com/skenzeriq/activediq/internal/modules/directory/api"
	"github.com/skenzeriq/activediq/internal/modules/search"
	"github.com/skenzeriq/activediq/internal/platform/apihost"
	"github.com/skenzeriq/activediq/internal/platform/apihost/apitypes"
	"github.com/skenzeriq/activediq/internal/platform/authn/tenantref"
	"github.com/skenzeriq/activediq/internal/platform/authority"
)

// UniversalSearch is the search service (modules/search). *search.Service implements it.
type UniversalSearch interface {
	Search(ctx context.Context, c search.Call) (search.Result, error)
}

// SearchDirectory implements api.Handlers: POST /directory/search (T-1096, ADR-0011). The permission
// directory.read was checked by the host; here the tenant and the human behind the session are taken from the
// authenticated principal, and the service trims by the producer's scope. A token is refused for the reason
// readScope gives. The text is never echoed, logged or put in a problem. Reads are not audited.
func (h Handlers) SearchDirectory(ctx context.Context, in api.SearchDirectoryInput) (api.SearchDirectoryOutput, error) {
	p, ok := apihost.PrincipalFrom(ctx)
	if !ok || p.ID == "" {
		return nil, apitypes.Unauthenticated("")
	}
	tid, err := tenantref.TenantFromText(p.Tenant)
	if err != nil || h.Searcher == nil || p.Kind != apihost.KindSession {
		return nil, apitypes.Forbidden("")
	}
	call := search.Call{Tenant: tid, Text: in.Body.Q,
		Chain: authority.Chain{Requester: authority.Principal{ID: authority.PrincipalID(p.ID), Kind: authority.Human}}}
	if in.Body.Type != nil {
		t, ok := search.ParseType(string(*in.Body.Type))
		if !ok {
			return nil, searchQueryProblem(search.CodeInvalid)
		}
		call.Type = t
	}
	if in.Body.GroupLimit != nil {
		call.Limit = int(*in.Body.GroupLimit)
	}
	if in.Body.Cursor != nil {
		call.Cursor = string(*in.Body.Cursor)
	}
	res, err := h.Searcher.Search(ctx, call)
	if err != nil {
		return nil, h.searchError(err)
	}
	body, err := searchBody(res)
	if err != nil {
		h.log().Error("directory search: unparseable object guid", "error_class", "protocol")
		return nil, apitypes.Internal("")
	}
	return api.SearchDirectory200{Body: body}, nil
}

// searchError maps the service's errors to problems. The text of no error is sent.
func (h Handlers) searchError(err error) error {
	var qe *search.QueryError
	switch {
	case errors.As(err, &qe):
		return searchQueryProblem(qe.Code)
	case errors.Is(err, search.ErrCursorInvalid):
		return searchQueryProblem(search.CodeCursor)
	case errors.Is(err, search.ErrCursorRequiresType):
		return searchQueryProblem(search.CodeCursorTyp)
	case errors.Is(err, search.ErrForbidden):
		return apitypes.Forbidden("")
	case errors.Is(err, search.ErrUnavailable):
		return apitypes.SearchUnavailable("")
	}
	return apitypes.Internal("")
}

// searchQueryProblem is the 400 of the contract: a code and a fixed sentence, never the text.
func searchQueryProblem(code string) error {
	var e apitypes.Errors
	field := "/q"
	if code == search.CodeCursor || code == search.CodeCursorTyp {
		field = "/cursor"
	}
	e.AddBody(jsontext.Pointer(field), code, searchQueryDetail[code])
	return apitypes.SearchQueryInvalid("").WithErrors(&e)
}

var searchQueryDetail = map[string]string{
	search.CodeTooShort:  "Enter something to search for.",
	search.CodeTooLong:   "The search text is too long.",
	search.CodeInvalid:   "The search text cannot be used.",
	search.CodeRefused:   "This search cannot be run.",
	search.CodeCursor:    "The page cursor is not valid for this search. Search again.",
	search.CodeCursorTyp: "A page cursor needs the type it was given with.",
}

func searchBody(r search.Result) (api.DirectorySearchResult, error) {
	out := api.DirectorySearchResult{Refine: r.Refine, Groups: make([]api.DirectorySearchGroup, 0, len(r.Groups))}
	if !r.AsOf.IsZero() {
		ts := apitypes.NewTimestamp(r.AsOf)
		out.AsOf = &ts
	}
	for _, g := range r.Groups {
		ag := api.DirectorySearchGroup{Type: api.DirectorySearchObjectType(search.TypeName(g.Type)), Items: make([]api.DirectorySearchHit, 0, len(g.Items))}
		for _, h := range g.Items {
			hit, err := searchHit(h)
			if err != nil {
				return api.DirectorySearchResult{}, err
			}
			ag.Items = append(ag.Items, hit)
		}
		if g.Count != nil {
			n := int64(*g.Count)
			ag.Count = &n
		}
		if !r.Refine {
			more := g.More
			ag.More = &more
		}
		if g.NextCursor != "" {
			c := g.NextCursor
			ag.NextCursor = &c
		}
		if g.LimitReached {
			t := true
			ag.LimitReached = &t
		}
		out.Groups = append(out.Groups, ag)
	}
	return out, nil
}

func searchHit(h search.Hit) (api.DirectorySearchHit, error) {
	oid, err := apitypes.ParseUUID(h.Object)
	if err != nil {
		// The index returns canonical GUIDs; a malformed one is a fault, not data to show.
		return api.DirectorySearchHit{}, err
	}
	out := api.DirectorySearchHit{Type: api.DirectorySearchObjectType(search.TypeName(h.Type)), ObjectID: oid, DisplayName: h.DisplayName,
		MatchClass: api.DirectorySearchMatchClass(h.Class.String()), DistinguishedName: h.DN, Domain: h.Domain,
		Highlights: make([]api.DirectorySearchHighlight, 0, len(h.Highlights)), Status: []api.DirectorySearchChip{}}
	for _, hl := range h.Highlights {
		out.Highlights = append(out.Highlights, api.DirectorySearchHighlight{Field: api.DirectorySearchHighlightField(hl.Field), Start: int64(hl.Start), Length: int64(hl.Length)})
	}
	for _, f := range []struct {
		dst **string
		v   string
	}{{&out.SamAccountName, h.SAMAccountName}, {&out.UserPrincipalName, h.UserPrincipalName}, {&out.Mail, h.Mail}} {
		if f.v != "" {
			v := f.v
			*f.dst = &v
		}
	}
	for _, c := range h.Status {
		chip := api.DirectorySearchChip{Kind: api.DirectorySearchChipKind(c.Kind), Days: c.Days}
		if !c.At.IsZero() {
			ts := apitypes.NewTimestamp(c.At)
			chip.At = &ts
		}
		out.Status = append(out.Status, chip)
	}
	if h.Title != "" || h.Office != "" || h.Department != "" {
		d := api.DirectorySearchDisambiguator{}
		for _, f := range []struct {
			dst **string
			v   string
		}{{&d.Title, h.Title}, {&d.Office, h.Office}, {&d.Department, h.Department}} {
			if f.v != "" {
				v := f.v
				*f.dst = &v
			}
		}
		out.Disambiguator = &d
	}
	return out, nil
}
