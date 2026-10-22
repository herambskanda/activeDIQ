// Package odatatest is the strict parser for exactly the OData subset package odata emits (spec V7
// to V9). It decodes the URL once, as Graph does, and rejects everything the real primitive would
// not produce, including non-canonical encodings. It is the round-trip oracle for the corpus and
// fuzz targets, and the fake Graph's request parser. It shares no code with package odata, so a
// renderer defect cannot hide behind the same defect in the oracle. Not shipped: tests import it.
package odatatest

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Lit kinds.
const (
	LitString = "string"
	LitGUID   = "guid"
	LitBool   = "bool"
	LitInt    = "int"
	LitTime   = "time"
)

// Lit is a decoded literal. Text is the unquoted, un-doubled value for strings.
type Lit struct{ Kind, Text string }

// Node is a parsed $filter. Op is "eq", "in" or "and".
type Node struct {
	Op   string
	Prop string
	Lits []Lit
	Kids []Node
}

// Segment kinds.
const (
	SegName   = "name"
	SegCast   = "cast"
	SegKey    = "key"
	SegKeyStr = "keystr"
	SegAlt    = "altkey"
)

// Segment is one parsed path segment. Set is the entity set of a keyed segment; Prop the alternate
// key property.
type Segment struct {
	Kind string
	Name string // name, cast; or the set of a keyed segment
	Prop string
	Val  Lit // key, keystr, altkey
}

// Expand is one $expand item.
type Expand struct {
	Nav    string
	Select []string
}

// Request is a parsed request. Filter is nil when there is no $filter; Top is 0 when absent.
type Request struct {
	Segments []Segment
	Select   []string
	Filter   *Node
	Expand   []Expand
	Top      int
	Count    bool
	OrderBy  string
	Desc     bool
}

var (
	errSyntax = errors.New("odatatest: not in the emitted OData subset")
	nameRE    = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)
	castRE    = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)+$`)
	guidRE    = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)
	timeRE    = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?Z`)
	intRE     = regexp.MustCompile(`^-?[0-9]+`)
)

func bad(format string, a ...any) error {
	return fmt.Errorf("%w: %s", errSyntax, fmt.Sprintf(format, a...))
}

// ParseRequest parses the request target (path and query, as sent: r.RequestURI) of a request made
// under basePath (for example "/v1.0").
func ParseRequest(requestURI, basePath string) (Request, error) {
	var r Request
	if strings.Contains(requestURI, "#") {
		return r, bad("fragment")
	}
	rawPath, rawQuery, _ := strings.Cut(requestURI, "?")
	rest, ok := strings.CutPrefix(rawPath, strings.TrimRight(basePath, "/")+"/")
	if !ok || rest == "" {
		return r, bad("path is outside %s", basePath)
	}
	for _, seg := range strings.Split(rest, "/") {
		s, err := parseSegment(seg)
		if err != nil {
			return r, err
		}
		r.Segments = append(r.Segments, s)
	}
	if err := parseQuery(rawQuery, &r); err != nil {
		return r, err
	}
	return r, nil
}

// ---- percent-coding: decode exactly once, canonical (upper-case hex) only ----

func unreservedKey(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte("-._~@'", c) >= 0
}

func unreservedQuery(c byte) bool { return unreservedKey(c) && c != '@' && c != '\'' }

// decode percent-decodes s once. Every byte of s must be allowed by ok or be a %XX with upper-case hex.
func decode(s string, ok func(byte) bool) (string, error) {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '%':
			if i+2 >= len(s) {
				return "", bad("truncated percent escape")
			}
			h := s[i+1 : i+3]
			v, err := strconv.ParseUint(h, 16, 8)
			if err != nil || h != strings.ToUpper(h) {
				return "", bad("bad percent escape")
			}
			b.WriteByte(byte(v))
			i += 2
		case ok(c):
			b.WriteByte(c)
		default:
			return "", bad("byte %#x must be percent-encoded", c)
		}
	}
	return b.String(), nil
}

// ---- literals ----

// parseLit reads one literal at s[pos:] and returns it with the new position.
func parseLit(s string, pos int) (Lit, int, error) {
	rest := s[pos:]
	switch {
	case strings.HasPrefix(rest, "'"):
		var b strings.Builder
		for i := 1; i < len(rest); i++ {
			if rest[i] != '\'' {
				b.WriteByte(rest[i])
				continue
			}
			if i+1 < len(rest) && rest[i+1] == '\'' {
				b.WriteByte('\'')
				i++
				continue
			}
			return Lit{LitString, b.String()}, pos + i + 1, nil
		}
		return Lit{}, 0, bad("unterminated string literal")
	case strings.HasPrefix(rest, "true"):
		return Lit{LitBool, "true"}, pos + 4, nil
	case strings.HasPrefix(rest, "false"):
		return Lit{LitBool, "false"}, pos + 5, nil
	}
	if m := guidRE.FindString(rest); m != "" && len(m) == 36 {
		return Lit{LitGUID, m}, pos + 36, nil
	}
	if m := timeRE.FindString(rest); m != "" {
		return Lit{LitTime, m}, pos + len(m), nil
	}
	if m := intRE.FindString(rest); m != "" {
		if _, err := strconv.ParseInt(m, 10, 64); err != nil || (len(m) > 1 && m[0] == '0') {
			return Lit{}, 0, bad("bad integer")
		}
		return Lit{LitInt, m}, pos + len(m), nil
	}
	return Lit{}, 0, bad("not a literal")
}

func quote(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

func litText(l Lit) string {
	if l.Kind == LitString {
		return quote(l.Text)
	}
	return l.Text
}

// ---- path ----

func encodeKey(s string) string {
	const hexd = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if unreservedKey(s[i]) {
			b.WriteByte(s[i])
		} else {
			b.WriteByte('%')
			b.WriteByte(hexd[s[i]>>4])
			b.WriteByte(hexd[s[i]&15])
		}
	}
	return b.String()
}

func parseSegment(seg string) (Segment, error) {
	open := strings.IndexByte(seg, '(')
	if open < 0 {
		switch {
		case len(seg) == 36 && guidRE.MatchString(seg):
			return Segment{Kind: SegKey, Val: Lit{LitGUID, seg}}, nil
		case nameRE.MatchString(seg):
			return Segment{Kind: SegName, Name: seg}, nil
		case castRE.MatchString(seg):
			return Segment{Kind: SegCast, Name: seg}, nil
		}
		return Segment{}, bad("segment is not a name, cast or GUID key")
	}
	set := seg[:open]
	if !nameRE.MatchString(set) || !strings.HasSuffix(seg, ")") {
		return Segment{}, bad("keyed segment")
	}
	inner := seg[open+1 : len(seg)-1]
	out := Segment{Kind: SegKeyStr, Name: set}
	prefix := ""
	if !strings.HasPrefix(inner, "'") {
		eqAt := strings.IndexByte(inner, '=')
		if eqAt < 0 || !nameRE.MatchString(inner[:eqAt]) {
			return Segment{}, bad("alternate key")
		}
		out.Kind, out.Prop = SegAlt, inner[:eqAt]
		prefix = inner[:eqAt+1]
		inner = inner[eqAt+1:]
	}
	dec, err := decode(inner, unreservedKey)
	if err != nil {
		return Segment{}, err
	}
	lit, end, err := parseLit(dec, 0)
	if err != nil {
		return Segment{}, err
	}
	if end != len(dec) {
		return Segment{}, bad("trailing text after key literal")
	}
	if out.Kind == SegKeyStr && lit.Kind != LitString {
		return Segment{}, bad("string key is not a string literal")
	}
	if strings.ContainsAny(lit.Text, "/\\") {
		return Segment{}, bad("slash in key")
	}
	if canon := set + "(" + prefix + encodeKey(litText(lit)) + ")"; canon != seg {
		return Segment{}, bad("segment is not in canonical encoding")
	}
	out.Val = lit
	return out, nil
}

// ---- query ----

func parseQuery(raw string, r *Request) error {
	if raw == "" {
		return nil
	}
	seen := map[string]bool{}
	for _, part := range strings.Split(raw, "&") {
		name, val, ok := strings.Cut(part, "=")
		if !ok {
			return bad("query option without a value")
		}
		if seen[name] {
			return bad("option %s given twice", name)
		}
		seen[name] = true
		v, err := decode(val, unreservedQuery)
		if err != nil {
			return err
		}
		switch name {
		case "$filter":
			n, end, err := parseFilter(v, 0, 0)
			if err != nil {
				return err
			}
			if end != len(v) {
				return bad("trailing text after $filter")
			}
			r.Filter = &n
		case "$select":
			ns, err := nameList(v)
			if err != nil {
				return err
			}
			r.Select = ns
		case "$expand":
			if r.Expand, err = parseExpand(v); err != nil {
				return err
			}
		case "$top":
			n, err := strconv.Atoi(v)
			if err != nil || n < 1 || n > 999 || strconv.Itoa(n) != v {
				return bad("bad $top")
			}
			r.Top = n
		case "$count":
			if v != "true" {
				return bad("bad $count")
			}
			r.Count = true
		case "$orderby":
			p, desc := strings.CutSuffix(v, " desc")
			if !nameRE.MatchString(p) {
				return bad("bad $orderby")
			}
			r.OrderBy, r.Desc = p, desc
		default:
			return bad("unknown query option")
		}
	}
	return nil
}

func nameList(s string) ([]string, error) {
	ns := strings.Split(s, ",")
	for _, n := range ns {
		if !nameRE.MatchString(n) {
			return nil, bad("bad name in list")
		}
	}
	return ns, nil
}

func parseExpand(s string) ([]Expand, error) {
	var out []Expand
	for pos := 0; ; {
		end := pos
		for end < len(s) && s[end] != ',' && s[end] != '(' {
			end++
		}
		e := Expand{Nav: s[pos:end]}
		if !nameRE.MatchString(e.Nav) {
			return nil, bad("bad $expand navigation")
		}
		pos = end
		if pos < len(s) && s[pos] == '(' {
			const pre = "($select="
			if !strings.HasPrefix(s[pos:], pre) {
				return nil, bad("bad $expand options")
			}
			close := strings.IndexByte(s[pos:], ')')
			if close < 0 {
				return nil, bad("unterminated $expand options")
			}
			ns, err := nameList(s[pos+len(pre) : pos+close])
			if err != nil {
				return nil, err
			}
			e.Select = ns
			pos += close + 1
		}
		out = append(out, e)
		if pos == len(s) {
			return out, nil
		}
		if s[pos] != ',' {
			return nil, bad("bad $expand separator")
		}
		pos++
	}
}

// ---- filter ----

func parseFilter(s string, pos, depth int) (Node, int, error) {
	if depth > 16 {
		return Node{}, 0, bad("filter nested too deep")
	}
	if pos < len(s) && s[pos] == '(' {
		n := Node{Op: "and"}
		for {
			if pos >= len(s) || s[pos] != '(' {
				return Node{}, 0, bad("expected (")
			}
			kid, end, err := parseFilter(s, pos+1, depth+1)
			if err != nil {
				return Node{}, 0, err
			}
			if end >= len(s) || s[end] != ')' {
				return Node{}, 0, bad("expected )")
			}
			n.Kids = append(n.Kids, kid)
			pos = end + 1
			if strings.HasPrefix(s[pos:], " and ") {
				pos += len(" and ")
				continue
			}
			break
		}
		if len(n.Kids) < 2 {
			return Node{}, 0, bad("and needs two operands")
		}
		return n, pos, nil
	}
	end := pos
	for end < len(s) && s[end] != ' ' {
		end++
	}
	prop := s[pos:end]
	if !nameRE.MatchString(prop) {
		return Node{}, 0, bad("bad property name")
	}
	pos = end
	switch {
	case strings.HasPrefix(s[pos:], " eq "):
		l, e, err := parseLit(s, pos+4)
		if err != nil {
			return Node{}, 0, err
		}
		return Node{Op: "eq", Prop: prop, Lits: []Lit{l}}, e, nil
	case strings.HasPrefix(s[pos:], " in ("):
		n := Node{Op: "in", Prop: prop}
		pos += len(" in (")
		for {
			l, e, err := parseLit(s, pos)
			if err != nil {
				return Node{}, 0, err
			}
			n.Lits = append(n.Lits, l)
			pos = e
			if strings.HasPrefix(s[pos:], ", ") {
				pos += 2
				continue
			}
			if pos < len(s) && s[pos] == ')' {
				return n, pos + 1, nil
			}
			return Node{}, 0, bad("bad in list")
		}
	}
	return Node{}, 0, bad("expected eq or in")
}
