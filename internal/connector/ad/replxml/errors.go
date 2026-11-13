package replxml

// Code is a fixed, input-independent failure code (connector-contract §5.6 rule 4: the raw text is
// never copied into a response or a log).
type Code string

// The codes. Each is a constant string; none embeds anything from the input.
const (
	CodeTooLarge           Code = "too_large"           // input over the X2 cap, refused before parsing
	CodeBadEncoding        Code = "bad_encoding"        // UTF-16 or a declared encoding other than UTF-8
	CodeBadText            Code = "bad_text"            // NUL, a C0 control other than TAB/LF/CR, or invalid UTF-8
	CodeMalformed          Code = "malformed"           // not well-formed XML (includes an undeclared entity, truncation)
	CodeForbiddenDirective Code = "forbidden_directive" // DOCTYPE, ENTITY or any other <! directive
	CodeForbiddenPI        Code = "forbidden_pi"        // a processing instruction other than the leading XML declaration
	CodeBadRoot            Code = "bad_root"            // the root element is not the structure asked for
	CodeBadStructure       Code = "bad_structure"       // text or elements where a field holds only text
	CodeTrailingContent    Code = "trailing_content"    // anything but whitespace and comments after the root
	CodeTooDeep            Code = "too_deep"            // element depth over 8
	CodeTooManyElements    Code = "too_many_elements"   // more than 20,000 elements
	CodeTooManyAttrs       Code = "too_many_attrs"      // more than 16 attributes on one element
	CodeTextTooLong        Code = "text_too_long"       // a text node or attribute value over 1,024 bytes
	CodeDuplicateElement   Code = "duplicate_element"   // a known field appears twice
	CodeMissingField       Code = "missing_field"       // a field the structure cannot do without
	CodeBadTime            Code = "bad_time"            // a time that is not the strict format
	CodeBadGUID            Code = "bad_guid"            // a GUID that is not the canonical dashed form
	CodeBadNumber          Code = "bad_number"          // not an unsigned decimal in range
)

// DecodeError is the only error the package returns.
type DecodeError struct{ Code Code }

// Error returns fixed text.
func (e *DecodeError) Error() string {
	if e == nil {
		return "replxml: <nil>"
	}
	return "replxml: " + string(e.Code)
}

func fail(c Code) *DecodeError { return &DecodeError{Code: c} }
