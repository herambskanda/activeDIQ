package odata

import "strings"

// Filter is the sealed AST: Eq, In, And (V7).
type Filter interface {
	render(b *strings.Builder)
	depth() int
	check() error
}

type eq struct {
	prop Name
	lit  string
}

type in struct {
	prop Name
	lits []string
}

type and struct {
	kids []Filter
	d    int
}

// Eq is `prop eq literal`.
func Eq[V Value](p Prop[V], v V) Filter { return eq{p.name, v.literal()} }

// In is `prop in (l1, l2, …)`: one to MaxIn values.
func In[V Value](p Prop[V], vs ...V) (Filter, error) {
	switch {
	case len(vs) == 0:
		return nil, fail(Empty)
	case len(vs) > MaxIn:
		return nil, fail(TooMany)
	}
	lits := make([]string, len(vs))
	for i, v := range vs {
		lits[i] = v.literal()
	}
	return in{p.name, lits}, nil
}

// And joins two to MaxAnd operands, nested at most MaxDepth deep.
func And(fs ...Filter) (Filter, error) {
	switch {
	case len(fs) < 2:
		return nil, fail(TooFew)
	case len(fs) > MaxAnd:
		return nil, fail(TooMany)
	}
	d := 0
	for _, f := range fs {
		if f == nil {
			return nil, fail(InvalidValue)
		}
		d = max(d, f.depth())
	}
	if d+1 > MaxDepth {
		return nil, fail(TooDeep)
	}
	return and{append([]Filter(nil), fs...), d + 1}, nil
}

func (e eq) depth() int  { return 0 }
func (in) depth() int    { return 0 }
func (a and) depth() int { return a.d }

func (e eq) check() error {
	if !Name(e.prop).valid(false) {
		return fail(InvalidName)
	}
	return nil
}
func (i in) check() error {
	if !i.prop.valid(false) {
		return fail(InvalidName)
	}
	return nil
}
func (a and) check() error {
	for _, k := range a.kids {
		if err := k.check(); err != nil {
			return err
		}
	}
	return nil
}

func (e eq) render(b *strings.Builder) { b.WriteString(string(e.prop) + " eq " + e.lit) }
func (i in) render(b *strings.Builder) {
	b.WriteString(string(i.prop) + " in (" + strings.Join(i.lits, ", ") + ")")
}
func (a and) render(b *strings.Builder) {
	for n, k := range a.kids {
		if n > 0 {
			b.WriteString(" and ")
		}
		b.WriteByte('(')
		k.render(b)
		b.WriteByte(')')
	}
}

// Text returns the canonical decoded $filter text (V7).
func Text(f Filter) string {
	var b strings.Builder
	f.render(&b)
	return b.String()
}
