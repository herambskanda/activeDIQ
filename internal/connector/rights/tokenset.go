package rights

import (
	"sort"

	adguid "github.com/skenzeriq/activediq/internal/directory/attr/guid"
	"github.com/skenzeriq/activediq/internal/directory/attr/sid"
	"github.com/skenzeriq/activediq/internal/directory/sd"
)

// TokenSet is the access-token SID set the rights check evaluated as the connector identity
// (contract §5.9.4, T-1741): the identity's objectSid, every tokenGroups SID, the four
// implicitNetworkLogonSIDs and every sIDHistory value, all from the one identity read of the check.
// It is the principal an access check sees, so the userParameters readability proof evaluates
// READ_PROPERTY with exactly this set.
//
// It is read-only: SIDs is a private copy and every accessor returns a copy. The zero value is not a
// usable set (Complete is false).
type TokenSet struct {
	// IdentityGUID is the objectGUID of the identity the set belongs to.
	IdentityGUID adguid.GUID
	// DomainSID is the domain part of the identity's objectSid. tokenGroups holds domain-local
	// groups of this domain only, so the set says nothing about a target in another domain.
	DomainSID sid.SID
	// Epoch is the verification_id of the run that recorded the set. The verification epoch starts
	// when that run completes (contract §8.3a).
	Epoch string
	// SIDs is sorted by SID text and holds no duplicates.
	SIDs []sid.SID
	// Complete is true only when the set can be trusted as the whole token: the domain SID was
	// derived, tokenGroups came back non-empty (every real token has a primary group) and every
	// sIDHistory value decoded. An incomplete set makes sd.Grants answer with Incomplete set.
	Complete bool
}

// Has reports whether the set holds s.
func (t TokenSet) Has(s sid.SID) bool {
	for _, v := range t.SIDs {
		if v == s {
			return true
		}
	}
	return false
}

// Clone returns a copy that shares no memory with t.
func (t TokenSet) Clone() TokenSet {
	t.SIDs = append([]sid.SID(nil), t.SIDs...)
	return t
}

// PrincipalFromTokenSet builds the sd.Principal for t. The principal is Incomplete unless the set is.
// Callers that evaluate SELF ACEs add WithObjectSID(target objectSid) themselves.
func PrincipalFromTokenSet(t TokenSet) sd.Principal {
	return sd.PrincipalFromSIDSet(t.SIDs, t.Complete)
}

// newTokenSet orders and de-duplicates sids.
func newTokenSet(ident adguid.GUID, dom sid.SID, sids []sid.SID, complete bool) TokenSet {
	seen := map[sid.SID]bool{}
	out := make([]sid.SID, 0, len(sids))
	for _, s := range sids {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return TokenSet{IdentityGUID: ident, DomainSID: dom, SIDs: out, Complete: complete}
}
