package replxml

import "bytes"

// X6 allocation accounting for attributes.
//
// encoding/xml builds every attribute (an Attr, its name strings, the namespace translation) inside
// the one Token call that returns the start tag, so a check made on the returned token comes after
// the allocation: an element with 10,000 attributes in 64 KiB has already cost 1 MiB. scanTags
// therefore reads the raw bytes first, counts start tags and attributes without allocating, and
// refuses what would break the bound before the XML decoder sees a byte.
//
// The scan is conservative, not a parser: it only ever refuses, and only with depth, element or
// attribute codes. Anything it cannot follow (an unterminated tag, '<' inside a quoted value) it leaves to the
// XML decoder, which reports it as malformed.
const (
	allocPerAttr = 128 // measured ~115 B for an attribute and its name, plus the namespace translation
)

var (
	tagCommentOpen = []byte("<!--")
	tagCommentEnd  = []byte("-->")
	tagCDataOpen   = []byte("<![CDATA[")
	tagCDataEnd    = []byte("]]>")
	tagPIOpen      = []byte("<?")
	tagPIEnd       = []byte("?>")
)

// scanTags returns nil, or the DecodeError for a document that carries more attributes on one start
// tag than maxAttrs, or whose elements and attributes together would allocate more than the X6
// budget (8 x len + allocSlack).
func scanTags(b []byte, lim limits) *DecodeError {
	budget := 8*len(b) + allocSlack
	starts, attrs, depth := 0, 0, 0
	for i := 0; i < len(b); {
		j := bytes.IndexByte(b[i:], '<')
		if j < 0 {
			break
		}
		i += j
		rest := b[i:]
		switch {
		case bytes.HasPrefix(rest, tagCommentOpen):
			i = skipPast(b, i+len(tagCommentOpen), tagCommentEnd)
		case bytes.HasPrefix(rest, tagCDataOpen):
			i = skipPast(b, i+len(tagCDataOpen), tagCDataEnd)
		case bytes.HasPrefix(rest, tagPIOpen):
			i = skipPast(b, i+len(tagPIOpen), tagPIEnd)
		case len(rest) > 1 && rest[1] == '!':
			return nil // a directive: the decoder refuses it
		default:
			end, n, ok := scanTag(b, i+1)
			isEnd := len(rest) > 1 && rest[1] == '/'
			if !isEnd && len(rest) > 1 {
				// Charged even when the tag does not close: encoding/xml allocates the attributes
				// it has read before it reports the error (unquoted value, '<' in a value, EOF).
				starts++
				attrs += n
				if n > lim.attrs {
					return fail(CodeTooManyAttrs)
				}
				if cost := starts*allocPerElement + attrs*allocPerAttr; cost > budget || starts > lim.elements {
					if starts*allocPerElement > budget || starts > lim.elements {
						return fail(CodeTooManyElements)
					}
					return fail(CodeTooManyAttrs)
				}
			}
			if !ok {
				return nil // the decoder reports it as malformed
			}
			selfClosing := end >= 2 && b[end-2] == '/'
			switch {
			case isEnd:
				depth--
			case len(rest) > 1:
				if !selfClosing {
					depth++
				}
				if depth > lim.depth || (selfClosing && depth+1 > lim.depth) {
					return fail(CodeTooDeep)
				}
			}
			i = end
		}
		if i < 0 {
			return nil
		}
	}
	return nil
}

// skipPast returns the index after the next occurrence of end at or after from, or -1 if none.
func skipPast(b []byte, from int, end []byte) int {
	k := bytes.Index(b[from:], end)
	if k < 0 {
		return -1
	}
	return from + k + len(end)
}

// scanTag reads one tag body from i (just after '<') to its closing '>', counting the '=' that sit
// outside quotes (one per attribute). ok is false if the tag does not close or a '<' appears in a
// quoted value.
func scanTag(b []byte, i int) (end, attrs int, ok bool) {
	var quote byte
	for ; i < len(b); i++ {
		c := b[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			} else if c == '<' {
				return 0, attrs, false
			}
		case c == '"' || c == '\'':
			quote = c
		case c == '=':
			attrs++
		case c == '>':
			return i + 1, attrs, true
		}
	}
	return 0, attrs, false
}
