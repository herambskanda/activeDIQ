package dn

import "strconv"

// Kind classifies a DN or object-reference failure. Messages never echo the input: DN text is
// attacker-influenced and may carry names we must not log.
type Kind string

const (
	TooLong                 Kind = "TooLong"
	EmptyRDN                Kind = "EmptyRDN"
	EmptyRDNValue           Kind = "EmptyRDNValue"
	DanglingEscape          Kind = "DanglingEscape"
	InvalidEscape           Kind = "InvalidEscape"
	InvalidUTF8             Kind = "InvalidUTF8"
	NulInString             Kind = "NulInString"
	MultiValuedRDN          Kind = "MultiValuedRDN"
	UnexpectedSpace         Kind = "UnexpectedSpace"
	UnescapedSpecial        Kind = "UnescapedSpecial"
	QuotedValueNotSupported Kind = "QuotedValueNotSupported"
	MissingEquals           Kind = "MissingEquals"
	UnknownRDNType          Kind = "UnknownRDNType"
	HexValueForbidden       Kind = "HexValueForbidden"
	UseObjectRef            Kind = "UseObjectRef"
	InvalidObjectRef        Kind = "InvalidObjectRef"
	InvalidExtendedDN       Kind = "InvalidExtendedDN"
	ValueTooLong            Kind = "ValueTooLong"
	NotRequestable          Kind = "NotRequestable"
)

// Error is the single error type of the package. Pos is the byte offset in the input, or -1.
type Error struct {
	Kind Kind
	Pos  int
}

func (e *Error) Error() string {
	if e.Pos < 0 {
		return "dn: " + string(e.Kind)
	}
	return "dn: " + string(e.Kind) + " at byte " + strconv.Itoa(e.Pos)
}

// Is lets callers match with errors.Is(err, &dn.Error{Kind: dn.InvalidEscape}).
func (e *Error) Is(target error) bool {
	t, ok := target.(*Error)
	return ok && t.Kind == e.Kind
}

// KindOf returns the Kind of err, or "" if it is not a dn error.
func KindOf(err error) Kind {
	for err != nil {
		if e, ok := err.(*Error); ok {
			return e.Kind
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return ""
		}
		err = u.Unwrap()
	}
	return ""
}

func fail(k Kind, pos int) error { return &Error{Kind: k, Pos: pos} }
