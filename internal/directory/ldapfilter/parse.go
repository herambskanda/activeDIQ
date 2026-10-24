package ldapfilter

import (
	"strconv"
	"strings"

	"github.com/skenzeriq/activediq/internal/directory/attr/gentime"
	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
	"github.com/skenzeriq/activediq/internal/directory/attr/sid"
	"github.com/skenzeriq/activediq/internal/directory/dn"
)

// ParseAdminFilter reads an administrator's RFC 4515 filter (custom reports, saved searches). The
// grammar is strict: the whole input must be one filter (no surrounding whitespace, no second
// filter), escapes must be complete, and only the closed matching-rule set of §3.3 rule 6 is
// accepted. The result is an AST: callers send Render's canonical text, never the input. Secret
// attributes are refused outright (ForbiddenAttribute), and every DN-valued assertion must name an
// object the Caller can read.
func ParseAdminFilter(s string, sc *Schema, caller Caller, lim Limits) (Filter, error) {
	g := newGuard(sc, caller, lim)
	if len(s) > g.lim.MaxFilterBytes {
		return nil, fail(FilterTooLong)
	}
	p := &textParser{guard: g, s: s}
	f, err := p.filter(1)
	if err != nil {
		return nil, err
	}
	if p.i != len(s) {
		return nil, fail(TrailingInput)
	}
	return g.finish(f)
}

type textParser struct {
	*guard
	s string
	i int
}

func (p *textParser) peek() byte {
	if p.i < len(p.s) {
		return p.s[p.i]
	}
	return 0
}

func (p *textParser) eat(c byte) error {
	if p.i >= len(p.s) || p.s[p.i] != c {
		return fail(SyntaxError)
	}
	p.i++
	return nil
}

func (p *textParser) filter(depth int) (Filter, error) {
	if err := p.eat('('); err != nil {
		return nil, err
	}
	if err := p.enter(depth); err != nil {
		return nil, err
	}
	var f Filter
	var err error
	switch p.peek() {
	case '&', '|':
		f, err = p.composite(depth)
	case '!':
		p.i++
		var k Filter
		if k, err = p.filter(depth + 1); err == nil {
			f = Not(k)
		}
	default:
		f, err = p.item()
	}
	if err != nil {
		return nil, err
	}
	if err := p.eat(')'); err != nil {
		return nil, err
	}
	return f, nil
}

func (p *textParser) composite(depth int) (Filter, error) {
	op := p.s[p.i]
	p.i++
	var kids []Filter
	for p.peek() == '(' {
		if len(kids) >= p.lim.MaxFanOut {
			return nil, fail(TooWide)
		}
		k, err := p.filter(depth + 1)
		if err != nil {
			return nil, err
		}
		kids = append(kids, k)
	}
	if len(kids) == 0 {
		if p.peek() == ')' {
			return nil, fail(EmptyComposite)
		}
		return nil, fail(SyntaxError)
	}
	if op == '&' {
		return And(kids...), nil
	}
	return Or(kids...), nil
}

func isAttrByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '.' || c == ';'
}

// item parses one assertion; the opening parenthesis is already consumed.
func (p *textParser) item() (Filter, error) {
	start := p.i
	for p.i < len(p.s) && isAttrByte(p.s[p.i]) {
		p.i++
	}
	name := p.s[start:p.i]
	op := ""
	switch c := p.peek(); {
	case c == '=':
		op = "="
		p.i++
	case (c == '~' || c == '>' || c == '<') && p.i+1 < len(p.s) && p.s[p.i+1] == '=':
		op = string(c) + "="
		p.i += 2
	case c == ':':
		return p.extensible(name)
	default:
		return nil, fail(SyntaxError)
	}
	a, info, err := p.attr(name)
	if err != nil {
		return nil, err
	}
	segs, err := p.value()
	if err != nil {
		return nil, err
	}
	if len(segs) > 1 { // unescaped stars
		if op != "=" {
			return nil, fail(SyntaxError)
		}
		if len(segs) == 2 && len(segs[0]) == 0 && len(segs[1]) == 0 {
			return Present(a), nil
		}
		return p.substring(a, segs)
	}
	v, err := p.typed(info, segs[0])
	if err != nil {
		return nil, err
	}
	switch op {
	case "~=":
		return Approx(a, v), nil
	case ">=":
		return Ge(a, v), nil
	case "<=":
		return Le(a, v), nil
	}
	return Eq(a, v), nil
}

func (p *textParser) substring(a AttrName, segs [][]byte) (Filter, error) {
	initial, final := string(segs[0]), string(segs[len(segs)-1])
	var any []string
	for _, m := range segs[1 : len(segs)-1] {
		any = append(any, string(m))
	}
	return Substring(a, initial, any, final), nil
}

// extensible parses the part after the attribute: [":dn"][":" rule]":=" value. Only a bare rule
// from the closed set passes; the dn flag and every other rule are refused (rule 6).
func (p *textParser) extensible(name string) (Filter, error) {
	var toks []string
	for {
		if err := p.eat(':'); err != nil {
			return nil, err
		}
		if p.peek() == '=' {
			p.i++
			break
		}
		start := p.i
		for p.i < len(p.s) && (p.s[p.i] >= '0' && p.s[p.i] <= '9' || p.s[p.i] >= 'a' && p.s[p.i] <= 'z' || p.s[p.i] >= 'A' && p.s[p.i] <= 'Z' || p.s[p.i] == '.' || p.s[p.i] == '-') {
			p.i++
		}
		if p.i == start || len(toks) >= 2 {
			return nil, fail(SyntaxError)
		}
		toks = append(toks, p.s[start:p.i])
	}
	a, info, err := p.attr(name)
	if err != nil {
		return nil, err
	}
	if len(toks) != 1 {
		return nil, fail(UnsupportedMatchingRule)
	}
	rule := toks[0]
	if rule != oidBitAnd && rule != oidBitOr && rule != oidInChain {
		return nil, fail(UnsupportedMatchingRule)
	}
	segs, err := p.value()
	if err != nil {
		return nil, err
	}
	if len(segs) > 1 {
		return nil, fail(SyntaxError)
	}
	raw := segs[0]
	if len(raw) == 0 {
		return nil, fail(EmptyAssertion)
	}
	if rule == oidInChain {
		d, err := p.dnText(raw)
		if err != nil {
			return nil, err
		}
		return InChain(a, d), nil
	}
	m, err := strconv.ParseUint(string(raw), 10, 32)
	if err != nil {
		return nil, fail(InvalidValue)
	}
	_ = info // syntax (Integer) is enforced by Render
	if rule == oidBitAnd {
		return BitAnd(a, uint32(m)), nil
	}
	return BitOr(a, uint32(m)), nil
}

// value reads an assertion value up to its closing parenthesis, which it leaves unread. It returns
// the decoded octets split at each unescaped '*'; a value without stars is one segment.
func (p *textParser) value() ([][]byte, error) {
	segs := [][]byte{nil}
	total := 0
	for {
		if p.i >= len(p.s) {
			return nil, fail(SyntaxError)
		}
		c := p.s[p.i]
		switch {
		case c == ')':
			return segs, nil
		case c == '(':
			return nil, fail(SyntaxError)
		case c == 0:
			return nil, fail(NulInString)
		case c == '*':
			segs = append(segs, nil)
			p.i++
			continue
		case c == '\\':
			if p.i+2 >= len(p.s) {
				return nil, fail(InvalidEscape)
			}
			h, l := unhex(p.s[p.i+1]), unhex(p.s[p.i+2])
			if h < 0 || l < 0 {
				return nil, fail(InvalidEscape)
			}
			c = byte(h<<4 | l)
			p.i += 3
		default:
			p.i++
		}
		if total++; total > p.lim.MaxValueBytes {
			return nil, fail(ValueTooLong)
		}
		segs[len(segs)-1] = append(segs[len(segs)-1], c)
	}
}

func unhex(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10
	}
	return -1
}

// dnText parses admin-typed DN text (after filter unescaping) and checks the caller may read it.
func (p *textParser) dnText(raw []byte) (dn.DN, error) {
	d, err := dn.Parse(string(raw), dn.Lenient)
	if err != nil {
		return dn.DN{}, fail(InvalidValue)
	}
	return p.readable(d)
}

// typed turns decoded octets into the Value kind the attribute's syntax takes.
func (p *textParser) typed(info AttrInfo, raw []byte) (Value, error) {
	if len(raw) == 0 {
		return Value{}, fail(EmptyAssertion)
	}
	bad := fail(InvalidValue)
	switch info.Syntax {
	case SynString:
		return String(string(raw)), nil
	case SynOctet:
		return Bytes(raw), nil
	case SynGUID:
		g, err := guid.FromBytes(raw)
		if err != nil {
			return Value{}, bad
		}
		return GUID(g), nil
	case SynSID:
		s, err := sid.FromBytes(raw)
		if err != nil {
			return Value{}, bad
		}
		return SID(s), nil
	case SynDN:
		d, err := p.dnText(raw)
		if err != nil {
			return Value{}, err
		}
		return DNValue(d), nil
	case SynInt32:
		n, err := strconv.ParseInt(string(raw), 10, 32)
		if err != nil {
			return Value{}, bad
		}
		return Int32(int32(n)), nil
	case SynInt64:
		n, err := strconv.ParseInt(string(raw), 10, 64)
		if err != nil {
			return Value{}, bad
		}
		return Int64(n), nil
	case SynGenTime:
		t, err := gentime.Parse(string(raw))
		if err != nil {
			return Value{}, bad
		}
		return GeneralizedTime(t), nil
	case SynBool:
		switch {
		case strings.EqualFold(string(raw), "TRUE"):
			return Bool(true), nil
		case strings.EqualFold(string(raw), "FALSE"):
			return Bool(false), nil
		}
	}
	return Value{}, bad
}
