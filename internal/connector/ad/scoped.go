package ad

import (
	"context"

	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
	"github.com/skenzeriq/activediq/internal/directory/dn"
	"github.com/skenzeriq/activediq/internal/directory/ldapfilter"
)

// Controls the connector itself attaches to a general search (safe-primitives §3.6). The list is
// closed: a caller never names a control. Escape controls (ASQ, show-deleted, ...) live only in
// named operations and their OIDs are never written in this package (FF-SP2, LF-30).
const (
	oidPaged      = "1.2.840.113556.1.4.319"
	oidExtendedDN = "1.2.840.113556.1.4.529"
	oidSDFlags    = "1.2.840.113556.1.4.801"
)

var generalSearchControls = map[string]struct{}{
	oidPaged: {}, oidDomainScope: {}, oidExtendedDN: {}, oidSDFlags: {},
}

// CheckControls validates the controls a caller (a saved search, an imported definition) asks a
// general search to carry. Any OID outside the closed set — show-deleted and show-recycled among
// them — is CONTROL_NOT_ALLOWED (LF-40); only the named operation that owns such a control sets it.
func CheckControls(oids ...string) error {
	for _, o := range oids {
		if _, ok := generalSearchControls[o]; !ok {
			return fail(CodeControlNotAllowed, "", nil) // the OID is not echoed
		}
	}
	return nil
}

// ScopedRequest is a search bounded by delegation roots.
type ScopedRequest struct {
	// Roots are the delegation roots: GUID references only (a DN follows renames badly and a deleted
	// root must fail, not widen). Several roots run one search each, results de-duplicated by objectGUID.
	Roots []dn.ObjectRef
	// Depth is ScopeOneLevel or ScopeSubtree; the search never reaches above a root.
	Depth      Scope
	Filter     ldapfilter.Filter
	Attributes []string // explicit names; secrets, "*" and "+" are refused. objectGUID is always added.
	PageSize   uint32
	// Authorize is the per-object authorisation (LF-39). Entries it denies are withheld and counted
	// in ScopedResult.Denied; nil means the caller authorises later on what it receives.
	Authorize func(*Entry) (bool, error)
}

// ScopedResult counts what the caller was handed. There is no DC-side estimate anywhere in it.
type ScopedResult struct {
	Returned       int // entries passed to fn: after de-duplication and authorisation
	Denied         int // entries withheld by Authorize
	RootsCompleted int
}

// ScopedSearch streams the matches under each root to fn. A root that no longer resolves fails the
// call with DELEGATION_ROOT_GONE and never falls back to a wider root (LF-31); a moved root works
// because the GUID follows the object. Referrals fail the call (LF-32) and the Global Catalog was
// refused at Open (LF-33), so a returned stream is complete or an error.
func (s *Session) ScopedSearch(ctx context.Context, req ScopedRequest, fn func(*Entry) error) (ScopedResult, error) {
	var res ScopedResult
	if fn == nil || len(req.Roots) == 0 || req.Filter == nil {
		return res, fail(CodeInvalidArgument, "roots, filter and callback required", nil)
	}
	if req.Depth != ScopeOneLevel && req.Depth != ScopeSubtree {
		return res, fail(CodeInvalidArgument, "depth", nil)
	}
	for _, r := range req.Roots {
		if _, ok := r.GUID(); !ok {
			return res, fail(CodeInvalidArgument, "roots must be GUID references", nil)
		}
	}
	attrs := append([]string{"objectGUID"}, req.Attributes...)
	seen := map[guid.GUID]struct{}{}
	for _, root := range req.Roots {
		err := s.Search(ctx, SearchRequest{Base: root, Scope: req.Depth, Filter: req.Filter, Attributes: attrs, PageSize: req.PageSize},
			func(e *Entry) error {
				g, err := e.GUID()
				if err != nil {
					return err
				}
				if _, dup := seen[g]; dup {
					return nil
				}
				seen[g] = struct{}{}
				if req.Authorize != nil {
					ok, err := req.Authorize(e)
					if err != nil {
						return err
					}
					if !ok {
						res.Denied++
						return nil
					}
				}
				res.Returned++
				return fn(e)
			})
		if err != nil {
			if CodeOf(err) == CodeObjectNotFound {
				return res, fail(CodeDelegationRootGone, "", err)
			}
			return res, err
		}
		res.RootsCompleted++
	}
	return res, nil
}
