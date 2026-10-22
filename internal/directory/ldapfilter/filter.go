package ldapfilter

// Filter is a node of the filter AST. The interface is sealed: only this package makes nodes.
type Filter interface {
	render(r *renderer, depth int) error
	expensive(depth int) bool
}

type composite struct {
	op   byte // '&' or '|'
	kids []Filter
}

type not struct{ kid Filter }

type cmp struct {
	op   string // "=", ">=", "<=", "~="
	attr AttrName
	val  Value
}

type present struct{ attr AttrName }

type substr struct {
	attr    AttrName
	initial string
	any     []string
	final   string
}

type ext struct {
	oid   string
	attr  AttrName
	val   Value
	chain bool
}

// And matches when every child does. It needs at least one child.
func And(f ...Filter) Filter { return &composite{'&', append([]Filter(nil), f...)} }

// Or matches when any child does. It needs at least one child: "(|)" is RFC 4526 absolute false and is never emitted.
func Or(f ...Filter) Filter { return &composite{'|', append([]Filter(nil), f...)} }

// Not negates its child.
func Not(f Filter) Filter { return &not{f} }

// Eq asserts attribute equality.
func Eq(a AttrName, v Value) Filter { return &cmp{"=", a, v} }

// Ge asserts attribute >= value.
func Ge(a AttrName, v Value) Filter { return &cmp{">=", a, v} }

// Le asserts attribute <= value.
func Le(a AttrName, v Value) Filter { return &cmp{"<=", a, v} }

// Approx asserts approximate match.
func Approx(a AttrName, v Value) Filter { return &cmp{"~=", a, v} }

// Present asserts that the attribute has a value. Absence is Not(Present(a)).
func Present(a AttrName) Filter { return &present{a} }

// Substring asserts initial*any*...*final. An empty initial or final is absent; at least one part
// must be non-empty and no element of any may be empty.
func Substring(a AttrName, initial string, any []string, final string) Filter {
	return &substr{a, initial, append([]string(nil), any...), final}
}

// Prefix asserts the attribute starts with s. A star in s is data.
func Prefix(a AttrName, s string) Filter { return Substring(a, s, nil, "") }

// Contains asserts the attribute contains s.
func Contains(a AttrName, s string) Filter { return Substring(a, "", []string{s}, "") }

// BitAnd asserts (attribute & mask) == mask ([ms-filter] 1.2.840.113556.1.4.803). The attribute must be an Integer.
func BitAnd(a AttrName, mask uint32) Filter { return &ext{oidBitAnd, a, uintValue(mask), false} }

// BitOr asserts (attribute & mask) != 0 (1.2.840.113556.1.4.804).
func BitOr(a AttrName, mask uint32) Filter { return &ext{oidBitOr, a, uintValue(mask), false} }

// InChain asserts the DN-syntax attribute links to d through any depth of nesting
// (LDAP_MATCHING_RULE_IN_CHAIN). It is expensive on large estates (gotcha 9): callers check
// IsExpensive and opt in.
func InChain(a AttrName, d DN) Filter { return &ext{oidInChain, a, DNValue(d), true} }

// IsExpensive reports whether f contains an InChain assertion.
func IsExpensive(f Filter) bool { return f != nil && f.expensive(MaxDepth) }

func uintValue(m uint32) Value { return Int64(int64(m)) } // unsigned decimal ([ms-filter]); 0x80000000 is 2147483648

// expensive takes the remaining depth budget; past it the answer is true (fail towards "expensive"),
// so an untrusted deeply nested AST cannot exhaust the stack here before Render refuses it.
func (c *composite) expensive(d int) bool {
	if d <= 0 {
		return true
	}
	for _, k := range c.kids {
		if k != nil && k.expensive(d-1) {
			return true
		}
	}
	return false
}
func (n *not) expensive(d int) bool {
	return d <= 0 || n.kid != nil && n.kid.expensive(d-1)
}
func (*cmp) expensive(int) bool     { return false }
func (*present) expensive(int) bool { return false }
func (*substr) expensive(int) bool  { return false }
func (e *ext) expensive(int) bool   { return e.chain }

func (c *composite) render(r *renderer, depth int) error {
	if len(c.kids) == 0 {
		return fail(EmptyComposite)
	}
	if len(c.kids) > MaxFanOut {
		return fail(TooWide)
	}
	r.out.WriteByte('(')
	r.out.WriteByte(c.op)
	for _, k := range c.kids {
		if k == nil {
			return fail(InvalidFilter)
		}
		if err := r.node(k, depth+1); err != nil {
			return err
		}
	}
	r.out.WriteByte(')')
	return nil
}

func (n *not) render(r *renderer, depth int) error {
	if n.kid == nil {
		return fail(InvalidFilter)
	}
	r.out.WriteString("(!")
	if err := r.node(n.kid, depth+1); err != nil {
		return err
	}
	r.out.WriteByte(')')
	return nil
}

func (c *cmp) render(r *renderer, _ int) error {
	info, err := r.attr(c.attr)
	if err != nil {
		return err
	}
	if err := c.val.check(); err != nil {
		return err
	}
	if !c.val.accepts(info.Syntax) {
		return fail(ValueKindMismatch)
	}
	r.out.WriteByte('(')
	r.out.WriteString(c.attr.name)
	r.out.WriteString(c.op)
	writeValue(&r.out, c.val)
	r.out.WriteByte(')')
	return nil
}

func (p *present) render(r *renderer, _ int) error {
	if _, err := r.attr(p.attr); err != nil {
		return err
	}
	r.out.WriteByte('(')
	r.out.WriteString(p.attr.name)
	r.out.WriteString("=*)")
	return nil
}

func (s *substr) render(r *renderer, _ int) error {
	info, err := r.attr(s.attr)
	if err != nil {
		return err
	}
	switch info.Syntax {
	case SynDN:
		return fail(SubstringOnDN)
	case SynString:
	default:
		return fail(ValueKindMismatch)
	}
	if s.initial == "" && s.final == "" && len(s.any) == 0 {
		return fail(EmptySubstring)
	}
	parts := make([]string, 0, len(s.any)+2)
	if s.initial != "" {
		parts = append(parts, s.initial)
	}
	for _, a := range s.any {
		if a == "" {
			return fail(EmptySubstring)
		}
		parts = append(parts, a)
	}
	if s.final != "" {
		parts = append(parts, s.final)
	}
	for _, p := range parts {
		if len(p) > MaxValueBytes {
			return fail(ValueTooLong)
		}
		if err := checkText([]byte(p)); err != nil {
			return err
		}
	}
	r.out.WriteByte('(')
	r.out.WriteString(s.attr.name)
	r.out.WriteByte('=')
	if s.initial != "" {
		escape(&r.out, []byte(s.initial))
	}
	r.out.WriteByte('*')
	for _, a := range s.any {
		escape(&r.out, []byte(a))
		r.out.WriteByte('*')
	}
	if s.final != "" {
		escape(&r.out, []byte(s.final))
	}
	r.out.WriteByte(')')
	return nil
}

func (e *ext) render(r *renderer, _ int) error {
	info, err := r.attr(e.attr)
	if err != nil {
		return err
	}
	if err := e.val.check(); err != nil {
		return err
	}
	want := SynInt32
	if e.chain {
		want = SynDN
	}
	if info.Syntax != want {
		return fail(ValueKindMismatch)
	}
	r.out.WriteByte('(')
	r.out.WriteString(e.attr.name)
	r.out.WriteByte(':')
	r.out.WriteString(e.oid)
	r.out.WriteString(":=")
	writeValue(&r.out, e.val)
	r.out.WriteByte(')')
	return nil
}
