package objects

import "github.com/skenzeriq/activediq/internal/directory/objectdef"

// The definition model lives in internal/directory/objectdef so that other modules read it without
// importing this module (blueprint §2.4). The store here names it through these aliases.
type (
	State        = objectdef.State
	Template     = objectdef.Template
	NamingFormat = objectdef.NamingFormat
	ObjectKind   = objectdef.ObjectKind
	NamePurpose  = objectdef.NamePurpose
)

const (
	StateDraft     = objectdef.StateDraft
	StatePublished = objectdef.StatePublished
	StateActive    = objectdef.StateActive
	StateArchived  = objectdef.StateArchived
)

// Stored is one stored version of a definition.
type Stored[T any] = objectdef.Stored[T]
