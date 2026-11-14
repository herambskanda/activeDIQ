package ad

import (
	"context"
	"strconv"
	"strings"

	"github.com/go-ldap/ldap/v3"

	"github.com/skenzeriq/activediq/internal/connector/ad/scope"
	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
	"github.com/skenzeriq/activediq/internal/directory/dn"
)

// The two show-deleted reads of connector-contract §8.10.3 kind 6 step 7 (TM-D33, TM §6.3 R15 (b),
// TM-F-RIGHTS (b1) and (b2)). They are separate functions on purpose: each has a fixed shape and
// a CI check allow-lists its callers (T-1737). Nothing else reads a deleted object's descriptor.

// WKGUIDDeletedObjects is GUID_DELETED_OBJECTS_CONTAINER_W, the well-known GUID of
// CN=Deleted Objects in a domain head's wellKnownObjects
// (https://learn.microsoft.com/en-us/windows/win32/ad/binding-to-well-known-objects-using-wkguid).
const WKGUIDDeletedObjects = "18e2ea80684f11d2b9aa00c04f79f805"

// DeletedTargetMustBePresent are the attributes a deleted target must come back with whatever its
// class (the class-dependent ones are added by the classifier); an absent one is unreadable, not unset.
var DeletedTargetMustBePresent = []string{"objectGUID", "objectClass", "isDeleted", "lastKnownParent", "msDS-LastKnownRDN", "nTSecurityDescriptor"}

// DeletedTargetOptional are read when present; an absent one is unreadable unless the retained
// descriptor proves Read Property on it (the classifier decides).
var DeletedTargetOptional = []string{"sIDHistory", "memberOf", "adminCount", "msDS-AllowedToDelegateTo",
	"msDS-AllowedToActOnBehalfOfOtherIdentity", "msDS-SecondaryKrbTgtNumber", "isCriticalSystemObject"}

// deletedTargetAttrs is the fixed R2 attribute list of the target read (objectGUID is added by Read).
// objectSid, userAccountControl and primaryGroupID are must-be-present by class.
var deletedTargetAttrs = append(append([]string{"objectSid", "userAccountControl", "primaryGroupID", "isRecycled"},
	DeletedTargetMustBePresent...), DeletedTargetOptional...)

// ReadDeletedTarget is the deleted-target read (TM-F-RIGHTS (b1); its only caller is the kind 6
// step 7 classification, after the grant on CN=Deleted Objects was proven from the container's
// descriptor). One base-scope search on <GUID=…> with the critical show-deleted control, the
// show-deactivated-link control (without it memberOf is empty for every caller, T-1633), SD_FLAGS
// owner+group+DACL (never the SACL) and the extended-DN control, for the fixed attribute list only.
// noSuchObject is CodeObjectNotFound.
func (s *Session) ReadDeletedTarget(ctx context.Context, id guid.GUID) (*Entry, error) {
	return s.Read(ctx, dn.GUIDRef(id), deletedTargetAttrs, ReadOptions{
		showDeleted:         true,
		ShowDeactivatedLink: true,
		ExtendedDN:          true,
		SD:                  DefaultSDFlags(),
	})
}

// DeletedContainerDescriptor is the container descriptor read (TM-F-RIGHTS (b2)): the owner and
// DACL of CN=Deleted Objects of the domain, resolved through the domain head's wellKnownObjects by
// WKGUID, read with SD_FLAGS owner+DACL (0x5) and the show-deleted control, base scope, the
// attribute list exactly nTSecurityDescriptor and no paged-results control. Callers: the kind 6
// step 7 grant check and VerifyConnection (T-1735). It returns the container's DN and the raw
// descriptor for the typed security-descriptor primitive; a missing well-known entry or a missing
// descriptor is an error, never an empty answer.
func (s *Session) DeletedContainerDescriptor(ctx context.Context, domain dn.DN) (dn.DN, []byte, error) {
	if domain.Len() == 0 {
		return dn.DN{}, nil, fail(CodeInvalidArgument, "domain head required", nil)
	}
	head, err := s.Read(ctx, dn.DNRef(domain), []string{"wellKnownObjects"}, ReadOptions{})
	if err != nil {
		return dn.DN{}, nil, err
	}
	container, ok, err := wellKnownDN(head.Strings("wellKnownObjects"), WKGUIDDeletedObjects)
	if err != nil {
		return dn.DN{}, nil, fail(CodeProtocol, "wellKnownObjects value", err)
	}
	if !ok {
		return dn.DN{}, nil, fail(CodeObjectNotFound, "no Deleted Objects entry in wellKnownObjects", nil)
	}
	// The container must be the domain head's own child; a wellKnownObjects value naming anything
	// else is not trusted to be the container of this domain.
	if container.Len() != domain.Len()+1 || !dn.IsDescendantOf(container, domain) {
		return dn.DN{}, nil, fail(CodeProtocol, "Deleted Objects container is not a child of the domain head", nil)
	}
	flags, err := NewSDFlags(SDOwner, SDDACL)
	if err != nil {
		return dn.DN{}, nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn == nil {
		return dn.DN{}, nil, fail(CodeUnreachable, "session closed", nil)
	}
	stop := s.watch(ctx, s.conn)
	defer stop()
	res, err := s.searchOnceLocked(ctx, container.String(), ldap.ScopeBaseObject, objectClassPresent,
		[]string{"nTSecurityDescriptor"}, []ldap.Control{flags.control(), scope.ShowDeleted()})
	if err != nil {
		return dn.DN{}, nil, err
	}
	if len(res.Entries) != 1 {
		return dn.DN{}, nil, fail(CodeObjectNotFound, "", nil)
	}
	raw := res.Entries[0].GetRawAttributeValue("nTSecurityDescriptor")
	if len(raw) == 0 {
		return dn.DN{}, nil, fail(CodeProtocol, "container descriptor not returned", nil)
	}
	if sdHasSACL(raw) {
		return dn.DN{}, nil, fail(CodeInvalidArgument, "security descriptor contains a SACL", nil)
	}
	return container, raw, nil
}

// wellKnownDN returns the DN a wellKnownObjects value of the given WKGUID (hex, any case) names. The
// syntax is DN-with-binary: "B:<hex digits>:<hex guid>:<dn>" (MS-ADTS 3.1.1.1.4).
func wellKnownDN(values []string, hexGUID string) (dn.DN, bool, error) {
	for _, v := range values {
		parts := strings.SplitN(v, ":", 4)
		if len(parts) != 4 || parts[0] != "B" {
			continue
		}
		if n, err := strconv.Atoi(parts[1]); err != nil || n != len(parts[2]) {
			continue
		}
		if !strings.EqualFold(parts[2], hexGUID) {
			continue
		}
		d, err := dn.Parse(parts[3], dn.Strict)
		if err != nil {
			return dn.DN{}, false, err
		}
		return d, true, nil
	}
	return dn.DN{}, false, nil
}

// DeletedObjectState is the deleted-state read of kind 6 Plan and Apply: base scope on <GUID=…>,
// the fixed state attributes only, the critical show-deleted control and nothing else. The object
// may come back live (restored meanwhile or never deleted): Deleted is then false. It is not a
// classification read; it returns no descriptor, no link value and no security attribute.
func (s *Session) DeletedObjectState(ctx context.Context, id guid.GUID) (ObjectState, error) {
	e, err := s.Read(ctx, dn.GUIDRef(id), stateAttrs, ReadOptions{showDeleted: true})
	if err != nil {
		return ObjectState{}, err
	}
	return s.stateOf(ctx, id, e)
}

// readDeletedLocked is the show-deleted read inside the restore write, under the held session lock,
// that re-checks the object is still deleted immediately before the one Modify.
func (s *Session) readDeletedLocked(ctx context.Context, id guid.GUID) (lockedObject, error) {
	return s.lockedRead(ctx, dn.GUIDRef(id), []ldap.Control{scope.ShowDeleted()})
}

// groupMemberOptions is the read of a live group's member values: show-deactivated-link (so a
// deleted member's value is visible; 2065 alone shows deactivated link values, TM-D33 measured) and
// extended-DN, without show-deleted: the group is live.
var groupMemberOptions = ReadOptions{ShowDeactivatedLink: true, ExtendedDN: true, MaxValues: DefaultMaxValues}

// GroupMembers reads a live group's member values ranged to the end, with the extended DN and the
// deactivated link values. truncated reports a cut at the value ceiling.
func (s *Session) GroupMembers(ctx context.Context, group guid.GUID) (members []string, truncated bool, err error) {
	e, err := s.Read(ctx, dn.GUIDRef(group), []string{"member"}, groupMemberOptions)
	if err != nil {
		return nil, false, err
	}
	for _, n := range e.Truncated {
		if strings.EqualFold(n, "member") {
			truncated = true
		}
	}
	return e.Strings("member"), truncated, nil
}
