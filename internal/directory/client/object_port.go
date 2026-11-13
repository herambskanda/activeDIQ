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
	// Links are the deactivated link values the object held when it was deleted.
	Links []LinkValue
}

// ObjectReader reads a directory object live on the operation's pins (rule 5) for the user lifecycle
// Actions. A read error is an error, never a zero state. ShowDeleted asks for a deleted object in the
// Deleted Objects container (restore); without it a deleted object does not exist.
type ObjectReader interface {
	Object(ctx context.Context, pins authority.Pins, target authority.TargetRef, attrs []string, showDeleted bool) (ObjectState, error)
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
