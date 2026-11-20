package client

import (
	"context"

	"github.com/skenzeriq/activediq/internal/platform/authority"
)

// LinkValue is one link value (memberOf, manager) a deleted object kept, read with the
// show-deactivated-link control: the attribute and the GUID of the object at the other end. With the
// Recycle Bin on a restore re-grants it, unless the other end is itself still deleted (Dormant): it
// then returns only when that object is restored (MS-ADTS 3.1.1.1.6).
type LinkValue struct {
	Attribute string
	Object    string
	Dormant   bool
}

// ObjectState is what one live read of a directory object shows, on the pinned DC. Values are raw
// directory text. Nothing here is a secret.
type ObjectState struct {
	Exists bool
	// Class is the live object class label ("user", "organizationalUnit", "container", ...).
	Class string
	// Tier0 is the connector's Tier-0 verdict for the object, read on the same DC.
	Tier0 bool
	// Parent is the objectGUID of the parent container; empty for a naming-context head and for a
	// deleted object (see LastKnownParent).
	Parent string
	// RDN is the value of the naming attribute (cn or ou).
	RDN string
	// Attrs holds the attributes asked for, as raw text values.
	Attrs map[string][]string
	// Deleted is true for an object in the Deleted Objects container (isDeleted). The fields below
	// are read only for a deleted object.
	Deleted         bool
	LastKnownParent string
	LastKnownRDN    string
	// ChildCount is the OU/container's direct-child count, set only when the read asked for it
	//: the OU delete preview. nil otherwise.
	ChildCount *ChildCount
	// Links are the deactivated link values the object held when it was deleted.
	Links []LinkValue
}

// ObjectReader reads a directory object live on the operation's pins (rule 5) for the user lifecycle
// Actions. A read error is an error, never a zero state. ShowDeleted asks for a deleted object in the
// Deleted Objects container (restore); without it a deleted object does not exist.
type ObjectReader interface {
	Object(ctx context.Context, pins authority.Pins, target authority.TargetRef, attrs []string, showDeleted bool) (ObjectState, error)
	// ObjectWithChildCount is Object for an OU or container plus the bounded direct-child count
	// (connector contract §5.3a): the OU delete preview. The count is what the connector's identity can
	// read, so zero does not prove a leaf; the DC decides at delete.
	ObjectWithChildCount(ctx context.Context, pins authority.Pins, target authority.TargetRef) (ObjectState, error)
	// DirectMember reports whether member is a direct value of group's member attribute, read on the
	// pins (the group's side of the link: `memberOf` of the member, GUID-matched, for a group too large
	// to read in full). A read error is an error, never false.
	DirectMember(ctx context.Context, pins authority.Pins, group, member authority.TargetRef) (bool, error)
	// RecycleBin reports whether the AD Recycle Bin is enabled for the forest of the naming context.
	RecycleBin(ctx context.Context, pins authority.Pins, nc authority.NamingContextID) (bool, error)
}

// ObjectGUID is the canonical lower-case GUID text of the object a completed write acted on (for a
// create, the new object), or "" when the response carries none.
func (r Result) ObjectGUID() string {
	if v := r.Apply.GetTarget().GetObject().GetValue(); len(v) == 16 {
		return formatUUID(v)
	}
	return ""
}
