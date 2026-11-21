package objectdef

import (
	"errors"
	"time"
)

// ErrNotFound is returned when a definition or version does not exist. It carries no content.
var ErrNotFound = errors.New("objects: definition or version not found")

// State is a version's lifecycle state. A template's live state is published; a naming format's is active.
type State string

// Version states.
const (
	StateDraft     State = "draft"
	StatePublished State = "published"
	StateActive    State = "active"
	StateArchived  State = "archived"
)

// Stored is one stored version of a definition.
type Stored[T any] struct {
	ID        string
	Version   int
	State     State
	Def       T
	UpdatedAt time.Time
}
