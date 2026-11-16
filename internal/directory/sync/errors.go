package sync

import (
	"errors"
)

// ErrMalformed is the class of every *Error: an entry whose value cannot be mapped faithfully.
var ErrMalformed = errors.New("sync: malformed entry")

// ErrNotAllowed: a request named an attribute that is not on the closed list, or is a secret.
var ErrNotAllowed = errors.New("sync: attribute not allowed")

// ErrConfig: the Mapper's configuration is unusable.
var ErrConfig = errors.New("sync: invalid mapper configuration")

// Code says why a value was refused. It is a fixed vocabulary: nothing from the directory enters it.
type Code string

// The reasons.
const (
	CodeMissing        Code = "missing"         // a required attribute or identity is absent
	CodeType           Code = "type"            // the value is of another type than the attribute's
	CodeMultiValued    Code = "multi_valued"    // several values on a single-valued attribute
	CodeBadGUID        Code = "bad_guid"        // not 16 bytes, or nil
	CodeBadSID         Code = "bad_sid"         // not a well-formed binary SID
	CodeBadDN          Code = "bad_dn"          // not an RFC 4514 DN
	CodeBadTime        Code = "bad_time"        // a time outside the FILETIME domain
	CodeRange          Code = "range"           // a number outside the attribute's domain
	CodeBadText        Code = "bad_text"        // NUL in text
	CodeTooLong        Code = "too_long"        // longer than the store accepts
	CodeTooMany        Code = "too_many"        // more values than the store accepts
	CodeDuplicate      Code = "duplicate"       // the same attribute twice in one entry
	CodeNCHead         Code = "nc_head"         // no parent, but not the naming context's head
	CodeAttributesSize Code = "attributes_size" // the attribute bag would exceed the store's bound
)

// Error refuses one entry. Attr is one of this package's own constant names (an attribute of the closed
// list, or "objectGUID", "dn", "parentGuid", "attributes"), never text from the directory, and Code is
// from the fixed vocabulary, so the error is safe to log and to count by (Attr, Code).
type Error struct {
	Attr string
	Code Code
}

func (e *Error) Error() string { return "sync: malformed " + e.Attr + ": " + string(e.Code) }

// Is makes errors.Is(err, ErrMalformed) true for every *Error.
func (e *Error) Is(target error) bool { return target == ErrMalformed }

func refuse(attr string, c Code) error { return &Error{Attr: attr, Code: c} }
