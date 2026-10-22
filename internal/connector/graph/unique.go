package graph

import (
	"context"
	"strings"

	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
	"github.com/skenzeriq/activediq/internal/directory/odata"
)

// Identity is a directory object resolved to its object id. Every later step of an operation (a
// write, an approval, an RBAC decision, a Tier-0 classification) uses ID and never the UPN, mail or
// display name the lookup started from (domain-model X3).
type Identity struct {
	ID     guid.GUID
	Object DirectoryObject
}

// FieldUPN and FieldDisplayName select the property Unique re-checks.
func FieldUPN(d DirectoryObject) string         { return d.UserPrincipalName }
func FieldDisplayName(d DirectoryObject) string { return d.DisplayName }

// Unique runs a lookup that must identify exactly one object (safe-primitives-odata §2, C1). It
// returns CodeNotFound for zero results and CodeNotUnique for more than one, and never the first of
// several. It then compares want with field(object) under strings.EqualFold: Graph is the authority
// on matching, and this catches server-side folding the filter did not intend. A mismatch is
// CodeIdentityMismatch. The caller should ask for a page size of 2 and select the field it checks.
func (c *Client) Unique(ctx context.Context, req odata.Request, field func(DirectoryObject) string, want string) (Identity, error) {
	var p page[DirectoryObject]
	if err := c.read(ctx, req, &p); err != nil {
		return Identity{}, err
	}
	switch {
	case len(p.Value) == 0 && p.NextLink == "":
		return Identity{}, newErr(CodeNotFound, 0, "no object matches the lookup", nil)
	case len(p.Value) > 1 || p.NextLink != "":
		return Identity{}, newErr(CodeNotUnique, 0, "more than one object matches the lookup", nil)
	}
	obj := p.Value[0]
	if field == nil || want == "" || !strings.EqualFold(field(obj), want) {
		return Identity{}, newErr(CodeIdentityMismatch, 0, "the matched object does not carry the requested value", nil)
	}
	id, err := guid.Parse(obj.ID)
	if err != nil {
		return Identity{}, newErr(CodeProviderFailure, 0, "Graph returned an object id that is not a GUID", nil)
	}
	return Identity{ID: id, Object: obj}, nil
}
