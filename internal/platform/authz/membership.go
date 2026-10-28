package authz

import "context"

// Group names a directory group by connection and objectGUID (never by DN) that a console account
// is a member of. Via is non-nil when the membership reaches the account through a correlation
// (DM-36.I2 correlation-derived grants); the resolver sets it, and leaving it nil on a derived
// membership is a bypass.
type Group struct {
	Connection string
	GUID       string
	Via        *Derivation
	// Path names how the account reaches the group, for the audit and the role page: the GUIDs from
	// the first object the walk started at (the account's own object, or the matched peer it was
	// derived from) up to this group. A nested membership lists every group on the way. It decides
	// nothing: Via, not Path, marks a correlation-derived grant.
	Path []string
}

// Groups is the answer of Membership. Complete is true only when every source was read in full;
// an incomplete answer grants nothing through groups (direct grants are unaffected).
type Groups struct {
	Groups   []Group
	Complete bool
}

// Membership resolves the groups whose grants reach an account (DM-36.I2). It is the port
// directory/inventory implements (ADR-0003 F6); authz and rbac never read the directory themselves.
//
// An implementation returns directory membership, resolved transitively including primary-group
// edges, and ONLY groups that may grant: security groups (AD) or securityEnabled groups that are not
// public (Entra), not flagged for a DACL that lets a broad principal change membership, with
// deactivated links left out. A member reaches the account only through its directory_ref (DM-30.I5)
// or a matched correlation, and an sso account's correlation-derived memberships are returned only
// for a session that verified the authority factor (DM-30.I6). Anything it cannot establish is
// omitted and Complete is false.
type Membership interface {
	GroupsOf(ctx context.Context, tenant, account string) (Groups, error)
}
