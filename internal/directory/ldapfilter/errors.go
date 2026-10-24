package ldapfilter

import "errors"

// Error is a filter failure with a stable code (safe-primitives §3.4). Nothing was sent anywhere.
type Error struct{ Code string }

func (e *Error) Error() string { return "ldapfilter: " + e.Code }

func fail(code string) error { return &Error{Code: code} }

// Code returns the stable code of err, or "" when err is not a filter error.
func Code(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}

// The error codes of §3.4, and the limits and schema checks of §3.3.
const (
	NulInString                = "NulInString"
	InvalidUTF8                = "InvalidUTF8"
	ValueKindMismatch          = "ValueKindMismatch"
	EmptyAssertion             = "EmptyAssertion"
	EmptySubstring             = "EmptySubstring"
	SubstringOnDN              = "SubstringOnDN"
	InvalidAttributeName       = "InvalidAttributeName"
	AttributeOptionsNotAllowed = "AttributeOptionsNotAllowed"
	ConstructedNotFilterable   = "ConstructedNotFilterable"
	UnknownAttribute           = "UnknownAttribute"
	SecretAttribute            = "SecretAttribute"
	ValueTooLong               = "ValueTooLong"
	FilterTooLong              = "FilterTooLong"
	TooDeep                    = "TooDeep"
	TooManyNodes               = "TooManyNodes"
	TooWide                    = "TooWide"
	EmptyComposite             = "EmptyComposite"
	InvalidValue               = "InvalidValue"
	InvalidFilter              = "InvalidFilter"

	// Codes only the parsers (parse.go, ast.go) produce.
	SyntaxError                 = "SyntaxError"
	TrailingInput               = "TrailingInput"
	InvalidEscape               = "InvalidEscape"
	UnsupportedMatchingRule     = "UnsupportedMatchingRule"
	ForbiddenAttribute          = "ForbiddenAttribute"
	ReferencedObjectNotReadable = "ReferencedObjectNotReadable"
	ReferenceCheckFailed        = "ReferenceCheckFailed"
)

// Limits are the provisional bounds of §3.3 rule 9.
const (
	MaxValueBytes  = 16 << 10
	MaxFilterBytes = 64 << 10
	MaxDepth       = 32
	MaxNodes       = 512
	MaxFanOut      = 256
)
