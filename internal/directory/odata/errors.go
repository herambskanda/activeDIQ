package odata

// Kind classifies a refusal. Messages never echo the input: it is attacker-influenced text.
type Kind string

const (
	PercentTriplet Kind = "PercentTriplet" // V3: a string value holding %XX
	InvalidUTF8    Kind = "InvalidUTF8"    // V4
	ControlChar    Kind = "ControlChar"    // V4: NUL, C0, DEL, C1
	TooLong        Kind = "TooLong"        // V5: string or rendered URL over its cap
	TooMany        Kind = "TooMany"        // V5: In or And over its cap
	TooFew         Kind = "TooFew"         // And with fewer than two operands
	Empty          Kind = "Empty"          // In with no values
	TooDeep        Kind = "TooDeep"        // V5: And nesting over MaxDepth
	SlashInKey     Kind = "SlashInKey"     // V10
	InvalidName    Kind = "InvalidName"    // a Name outside the identifier grammar
	InvalidValue   Kind = "InvalidValue"   // a zero or out-of-range typed value
	InvalidOption  Kind = "InvalidOption"  // $top out of range and the like
)

// Error is the single error type of the package.
type Error struct{ Kind Kind }

func (e *Error) Error() string { return "odata: " + string(e.Kind) }

// Is lets callers match with errors.Is(err, &odata.Error{Kind: odata.TooLong}).
func (e *Error) Is(target error) bool {
	t, ok := target.(*Error)
	return ok && t.Kind == e.Kind
}

// KindOf returns the Kind of err, or "" if it is not an odata error.
func KindOf(err error) Kind {
	if e, ok := err.(*Error); ok {
		return e.Kind
	}
	return ""
}

func fail(k Kind) error { return &Error{Kind: k} }
