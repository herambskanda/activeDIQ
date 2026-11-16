package ad

import (
	"context"
	"errors"

	"github.com/skenzeriq/activediq/internal/directory/dn"
	"github.com/skenzeriq/activediq/internal/directory/ldapfilter"
)

// errCountDone stops the paged count once the cap is exceeded; it never leaves this file.
var errCountDone = errors.New("ad: child count complete")

// CountChildren counts the immediate children of base that this session can see, with one paged
// ONE_LEVEL search asking for objectGUID only (connector-contract §5.3a). It stops as soon as it has
// seen more than limit children and then reports limit with capped = true, so the read of a huge
// container is bounded and a container with exactly limit children is not reported as capped.
// An object the identity cannot read is not counted: the result proves nothing about leaf-ness.
func (s *Session) CountChildren(ctx context.Context, base dn.ObjectRef, limit uint32) (n uint32, capped bool, err error) {
	if limit == 0 {
		return 0, false, fail(CodeInvalidArgument, "limit", nil)
	}
	a, err := ldapfilter.ParseAttrName("objectClass", s.schema)
	if err != nil {
		return 0, false, fail(CodeInvalidArgument, "objectClass", err)
	}
	var seen uint32
	err = s.SearchPages(ctx, SearchRequest{Base: base, Scope: ScopeOneLevel, Filter: ldapfilter.Present(a),
		Attributes: []string{"objectGUID"}}, func(page []*Entry) error {
		seen += uint32(len(page))
		if seen > limit {
			return errCountDone
		}
		return nil
	})
	switch {
	case errors.Is(err, errCountDone):
		return limit, true, nil
	case err != nil:
		return 0, false, err
	}
	return seen, false, nil
}
