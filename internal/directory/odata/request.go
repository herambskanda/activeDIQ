package odata

import (
	"net/url"
	"strconv"
	"strings"

	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
)

// Query holds the typed query options. The zero value is an empty query. Methods return copies.
type Query struct {
	sel     []Name
	filter  Filter
	expand  []expand
	top     int
	count   bool
	orderBy Name
	desc    bool
	err     error
}

type expand struct {
	nav Name
	sel []Name
}

func names(ps []AnyProp) []Name {
	out := make([]Name, len(ps))
	for i, p := range ps {
		if p == nil {
			return nil
		}
		out[i] = p.propName()
	}
	return out
}

func (q Query) Select(ps ...AnyProp) Query {
	q.sel = names(ps)
	if len(ps) > 0 && q.sel == nil {
		q.err = fail(InvalidName)
	}
	return q
}

func (q Query) Filter(f Filter) Query { q.filter = f; return q }

// Expand adds a navigation property, with a nested $select when sel is given.
func (q Query) Expand(nav Name, sel ...AnyProp) Query {
	ns := names(sel)
	if len(sel) > 0 && ns == nil {
		q.err = fail(InvalidName)
	}
	q.expand = append(append([]expand(nil), q.expand...), expand{nav, ns})
	return q
}

// Top sets $top, 1 to 999.
func (q Query) Top(n int) Query {
	if n < 1 || n > 999 {
		q.err = fail(InvalidOption)
	}
	q.top = n
	return q
}

func (q Query) Count() Query { q.count = true; return q }

func (q Query) OrderBy(p AnyProp, desc bool) Query {
	if p == nil {
		q.err = fail(InvalidName)
		return q
	}
	q.orderBy, q.desc = p.propName(), desc
	return q
}

func joinNames(ns []Name) string {
	ss := make([]string, len(ns))
	for i, n := range ns {
		ss[i] = string(n)
	}
	return strings.Join(ss, ",")
}

func (q Query) validate() error {
	if q.err != nil {
		return q.err
	}
	for _, n := range q.sel {
		if !n.valid(false) {
			return fail(InvalidName)
		}
	}
	for _, e := range q.expand {
		if !e.nav.valid(false) {
			return fail(InvalidName)
		}
		for _, n := range e.sel {
			if !n.valid(false) {
				return fail(InvalidName)
			}
		}
	}
	if q.orderBy != "" && !q.orderBy.valid(false) {
		return fail(InvalidName)
	}
	if q.filter != nil {
		return q.filter.check()
	}
	return nil
}

// encodeValue is V8: url.QueryEscape, with the + it makes for a space written as %20.
func encodeValue(s string) string { return strings.ReplaceAll(url.QueryEscape(s), "+", "%20") }

// raw renders the options in a fixed order, each name at most once (V8).
func (q Query) raw() string {
	var parts []string
	add := func(name, v string) { parts = append(parts, name+"="+encodeValue(v)) }
	if q.count {
		add("$count", "true")
	}
	if len(q.expand) > 0 {
		es := make([]string, len(q.expand))
		for i, e := range q.expand {
			es[i] = string(e.nav)
			if len(e.sel) > 0 {
				es[i] += "($select=" + joinNames(e.sel) + ")"
			}
		}
		add("$expand", strings.Join(es, ","))
	}
	if q.filter != nil {
		add("$filter", Text(q.filter))
	}
	if q.orderBy != "" {
		o := string(q.orderBy)
		if q.desc {
			o += " desc"
		}
		add("$orderby", o)
	}
	if len(q.sel) > 0 {
		add("$select", joinNames(q.sel))
	}
	if q.top > 0 {
		add("$top", strconv.Itoa(q.top))
	}
	return strings.Join(parts, "&")
}

// Segment is one path segment. Its constructors validate; an invalid one is carried to URL.
type Segment struct {
	raw string // percent-encoded as sent
	dec string // decoded, for url.URL.Path
	err error
}

// Seg is an entity set or navigation property: /groups, /members.
func Seg(n Name) Segment {
	if !n.valid(false) {
		return Segment{err: fail(InvalidName)}
	}
	return Segment{raw: string(n), dec: string(n)}
}

// Cast is a type-cast segment: /microsoft.graph.user.
func Cast(n Name) Segment {
	if !n.valid(true) {
		return Segment{err: fail(InvalidName)}
	}
	return Segment{raw: string(n), dec: string(n)}
}

// Key is key-as-segment: /<lower-case guid>.
// The nil GUID is never an object identity and is refused at URL.
func Key(id GUID) Segment {
	if id.g == (guid.GUID{}) {
		return Segment{err: fail(InvalidValue)}
	}
	s := id.g.String()
	return Segment{raw: s, dec: s}
}

// KeyStr is `set('value')`: a string key such as a UPN on /users.
func KeyStr(set Name, v String) (Segment, error) { return keyed(set, "", v.s) }

// AltKey is `set(prop='value')` / `set(prop=literal)`: servicePrincipals(appId='…').
func AltKey[V Value](set Name, p Prop[V], v V) (Segment, error) {
	if !p.name.valid(false) {
		return Segment{}, fail(InvalidName)
	}
	// Same refusals as KeyStr (empty) and Key (nil GUID): an empty or all-zero key is never an
	// object identity and must not reach the wire.
	switch x := any(v).(type) {
	case String:
		if x.s == "" {
			return Segment{}, fail(InvalidValue)
		}
	case GUIDText:
		if x.g == (guid.GUID{}) {
			return Segment{}, fail(InvalidValue)
		}
	case GUID:
		if x.g == (guid.GUID{}) {
			return Segment{}, fail(InvalidValue)
		}
	}
	return keyedLit(set, string(p.name)+"=", v)
}

func keyed(set Name, prefix, v string) (Segment, error) {
	if !set.valid(false) {
		return Segment{}, fail(InvalidName)
	}
	if v == "" {
		return Segment{}, fail(InvalidValue)
	}
	if strings.ContainsAny(v, "/\\") { // V10
		return Segment{}, fail(SlashInKey)
	}
	dec := string(set) + "(" + prefix + quote(v) + ")"
	return Segment{raw: string(set) + "(" + prefix + encodeKey(quote(v)) + ")", dec: dec}, nil
}

func keyedLit[V Value](set Name, prefix string, v V) (Segment, error) {
	if !set.valid(false) {
		return Segment{}, fail(InvalidName)
	}
	lit := v.literal()
	if strings.ContainsAny(lit, "/\\") { // V10
		return Segment{}, fail(SlashInKey)
	}
	return Segment{raw: string(set) + "(" + prefix + encodeKey(lit) + ")", dec: string(set) + "(" + prefix + lit + ")"}, nil
}

// encodeKey is V9: every byte outside A-Z a-z 0-9 - . _ ~ @ ' is percent-encoded, upper-case hex.
func encodeKey(s string) string {
	const hexd = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
			c == '-' || c == '.' || c == '_' || c == '~' || c == '@' || c == '\'' {
			b.WriteByte(c)
			continue
		}
		b.WriteByte('%')
		b.WriteByte(hexd[c>>4])
		b.WriteByte(hexd[c&15])
	}
	return b.String()
}

// Request is a GET of a path with query options.
type Request struct {
	segs []Segment
	q    Query
}

func Get(segs ...Segment) Request { return Request{segs: append([]Segment(nil), segs...)} }

func (r Request) With(q Query) Request { r.q = q; return r }

// URL resolves the request against the pinned Graph base (scheme, host and version path). It sets
// Path, RawPath and RawQuery itself; no caller touches them (V8, V9, V11, V12).
func (r Request) URL(base *url.URL) (*url.URL, error) {
	if err := r.q.validate(); err != nil {
		return nil, err
	}
	u := *base
	u.Fragment, u.RawFragment, u.ForceQuery = "", "", false
	path := strings.TrimRight(base.Path, "/")
	esc := strings.TrimRight(base.EscapedPath(), "/")
	for _, s := range r.segs {
		if s.err != nil {
			return nil, s.err
		}
		if s.raw == "" {
			return nil, fail(InvalidName)
		}
		path += "/" + s.dec
		esc += "/" + s.raw
	}
	u.Path, u.RawPath, u.RawQuery = path, esc, r.q.raw()
	if len(u.String()) > MaxURL {
		return nil, fail(TooLong)
	}
	return &u, nil
}
