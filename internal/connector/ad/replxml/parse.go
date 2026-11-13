package replxml

import (
	"bytes"
	"encoding/xml"
	"io"
	"strings"
	"unicode/utf8"
)

// Limits (connector-contract §5.7 X2, X3).
const (
	// MaxValueBytes is the largest single value accepted (X2).
	MaxValueBytes = 64 << 10
	// MaxCallBytes is the most a caller may feed the decoder for one DC in one call (X2); see Budget.
	MaxCallBytes = 8 << 20
	// MaxElements is the most elements in one value, known or skipped (X3).
	MaxElements = 20000
	// MaxDepth is the deepest element nesting, the root being depth 1 (X3).
	MaxDepth = 8
	// MaxAttrs is the most attributes on one element (X3).
	MaxAttrs = 16
	// MaxText is the longest text node or attribute value, in bytes (X3).
	MaxText = 1024
)

// X6 bounds allocation at 8 x the input. encoding/xml allocates up to about 200 bytes per element
// (name strings, the boxed token, the element stack), so a document of tiny elements would break
// the bound long before the X3 element count. The effective element limit is therefore
// min(MaxElements, (8 x len + allocSlack) / allocPerElement): a DS_REPL_* value averages tens of
// bytes per element, a hostile one 4. Attributes are charged against the same budget (scan.go).
const (
	allocPerElement = 256
	allocSlack      = 8 << 10 // fixed cost of the decoder, reader and result, not input-proportional
)

func elementLimit(n int, hard int) int {
	if e := (8*n + allocSlack) / allocPerElement; e < hard {
		return e
	}
	return hard
}

type limits struct {
	input, elements, depth, attrs, text int
}

var defaultLimits = limits{MaxValueBytes, MaxElements, MaxDepth, MaxAttrs, MaxText}

type kind uint8

const (
	kText    kind = iota // bounded display string
	kGUID                // canonical dashed GUID
	kTime                // strict UTC time
	kU32                 // unsigned decimal, 32 bit
	kU64                 // unsigned decimal, 64 bit
	kDrop                // recognised, validated, never exposed (X7)
	kDropBig             // as kDrop, but allowed to be as long as a value (opaque value bytes)
)

// spec is the allowlist of one structure: the root element and its field names (X4).
type spec struct {
	root   string
	fields map[string]kind
}

// parsed is the structurally valid document: the raw text of each exposed field, and the number
// of unknown elements skipped. Typed conversion happens afterwards, so an error never leaves a
// half-populated result.
type parsed struct {
	text    map[string]string
	unknown int
}

func allowed(c byte) bool { return c >= 0x20 || c == '\t' || c == '\n' || c == '\r' }

// precheck refuses what must never reach the XML decoder: UTF-16, NUL, C0 controls, invalid UTF-8.
func precheck(b []byte) *DecodeError {
	if len(b) >= 2 {
		if (b[0] == 0xFF && b[1] == 0xFE) || (b[0] == 0xFE && b[1] == 0xFF) || b[0] == 0 && b[1] != 0 {
			return fail(CodeBadEncoding)
		}
		if b[1] == 0 && b[0] == '<' {
			return fail(CodeBadEncoding) // UTF-16LE without a BOM
		}
	}
	for _, c := range b {
		if !allowed(c) {
			return fail(CodeBadText)
		}
	}
	if !utf8.Valid(b) {
		return fail(CodeBadText)
	}
	return nil
}

func isSpace(b []byte) bool {
	for _, c := range b {
		if c != ' ' && c != '\t' && c != '\r' && c != '\n' {
			return false
		}
	}
	return true
}

// parse drives xml.Decoder.Token itself (X1). Strict is true, Entity and CharsetReader are nil.
func parse(data []byte, sp *spec, lim limits) (*parsed, *DecodeError) {
	if len(data) > lim.input {
		return nil, fail(CodeTooLarge)
	}
	if e := precheck(data); e != nil {
		return nil, e
	}
	if e := scanTags(data, lim); e != nil {
		return nil, e
	}
	maxElems := elementLimit(len(data), lim.elements)
	d := xml.NewDecoder(bytes.NewReader(data))
	d.Strict = true // Entity and CharsetReader stay nil: no entity resolution, no transcoding (X1)

	out := &parsed{text: make(map[string]string, len(sp.fields))}
	var (
		tokens     int
		depth      int
		elements   int
		rootClosed bool
		field      string // the known field being read at depth 2, "" if none
		fieldKind  kind
		buf        []byte
		fieldLen   int
		skipFrom   int // depth of the unknown element being skipped, 0 if none
		seen       = make(map[string]bool, len(sp.fields))
	)
	for {
		tok, err := d.Token()
		if err != nil {
			if err == io.EOF && rootClosed {
				return out, nil
			}
			if strings.Contains(err.Error(), "CharsetReader") {
				return nil, fail(CodeBadEncoding)
			}
			return nil, fail(CodeMalformed)
		}
		first := tokens == 0
		tokens++
		switch t := tok.(type) {
		case xml.Directive:
			return nil, fail(CodeForbiddenDirective)
		case xml.ProcInst:
			if !(first && t.Target == "xml") {
				return nil, fail(CodeForbiddenPI)
			}
		case xml.Comment:
			// skipped
		case xml.CharData:
			if len(t) > lim.text && !(field != "" && fieldKind == kDropBig && skipFrom == 0) {
				return nil, fail(CodeTextTooLong)
			}
			switch {
			case depth == 0:
				if !isSpace(t) {
					if rootClosed {
						return nil, fail(CodeTrailingContent)
					}
					return nil, fail(CodeMalformed)
				}
			case skipFrom != 0:
			case field != "":
				limit := lim.text
				if fieldKind == kDropBig {
					limit = lim.input
				}
				fieldLen += len(t)
				if fieldLen > limit {
					return nil, fail(CodeTextTooLong)
				}
				if fieldKind != kDrop && fieldKind != kDropBig {
					buf = append(buf, t...)
				}
			default: // directly inside the root, between fields
				if !isSpace(t) {
					return nil, fail(CodeBadStructure)
				}
			}
		case xml.StartElement:
			if rootClosed {
				return nil, fail(CodeTrailingContent)
			}
			depth++
			elements++
			if depth > lim.depth {
				return nil, fail(CodeTooDeep)
			}
			if elements > maxElems {
				return nil, fail(CodeTooManyElements)
			}
			if len(t.Attr) > lim.attrs {
				return nil, fail(CodeTooManyAttrs)
			}
			for _, a := range t.Attr {
				if len(a.Value) > lim.text || len(a.Name.Local) > lim.text {
					return nil, fail(CodeTextTooLong)
				}
			}
			switch {
			case depth == 1:
				if t.Name.Space != "" || t.Name.Local != sp.root {
					return nil, fail(CodeBadRoot)
				}
			case skipFrom != 0:
				// inside an unknown subtree: counted, bounded, skipped
			case field != "":
				return nil, fail(CodeBadStructure) // a child inside a text field
			default: // depth 2
				k, known := sp.fields[t.Name.Local]
				if !known || t.Name.Space != "" {
					out.unknown++
					skipFrom = depth
					break
				}
				if seen[t.Name.Local] {
					return nil, fail(CodeDuplicateElement)
				}
				seen[t.Name.Local] = true
				field, fieldKind, buf, fieldLen = t.Name.Local, k, buf[:0], 0
			}
		case xml.EndElement:
			if skipFrom == depth {
				skipFrom = 0
			} else if field != "" && depth == 2 {
				if fieldKind != kDrop && fieldKind != kDropBig {
					out.text[field] = string(buf)
				}
				field = ""
			}
			depth--
			if depth == 0 {
				rootClosed = true
			}
		}
	}
}
