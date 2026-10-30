package ldapfilter

import (
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
	"github.com/skenzeriq/activediq/internal/directory/attr/sid"
	"github.com/skenzeriq/activediq/internal/directory/dn"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// ParseFilterASTJSON reads the protobuf-JSON form of the wire filter (safe-primitives §2.1) and
// validates it as ParseFilterAST does. Unknown fields are refused.
func ParseFilterASTJSON(data []byte, sc *Schema, caller Caller, lim Limits) (Filter, error) {
	if len(data) > 4*clampLimit(lim.MaxFilterBytes, MaxFilterBytes) { // JSON is wordier than RFC 4515
		return nil, fail(FilterTooLong)
	}
	var m connectorv1.Filter
	if err := (protojson.UnmarshalOptions{}).Unmarshal(data, &m); err != nil {
		return nil, fail(SyntaxError)
	}
	return ParseFilterAST(&m, sc, caller, lim)
}

// ParseFilterAST validates a wire-form filter under the same rules as ParseAdminFilter: schema
// allowlist, no secret or constructed attributes, closed matching rules, §3.3 rule 9 limits, and
// readability of every DN a node names. The connector calls it on whatever the server sent, because
// a compromised server is in the threat model (TM-TB6-T4); nothing here trusts the sender's kinds.
func ParseFilterAST(m *connectorv1.Filter, sc *Schema, caller Caller, lim Limits) (Filter, error) {
	g := newGuard(sc, caller, lim)
	f, err := (&astParser{g}).node(m, 1)
	if err != nil {
		return nil, err
	}
	return g.finish(f)
}

type astParser struct{ *guard }

func (p *astParser) node(m *connectorv1.Filter, depth int) (Filter, error) {
	if m == nil || m.GetNode() == nil {
		return nil, fail(InvalidFilter)
	}
	if err := p.enter(depth); err != nil {
		return nil, err
	}
	switch n := m.GetNode().(type) {
	case *connectorv1.Filter_And:
		return p.list(n.And, '&', depth)
	case *connectorv1.Filter_Or:
		return p.list(n.Or, '|', depth)
	case *connectorv1.Filter_Not:
		k, err := p.node(n.Not, depth+1)
		if err != nil {
			return nil, err
		}
		return Not(k), nil
	case *connectorv1.Filter_Equal:
		return p.cmp(n.Equal, Eq)
	case *connectorv1.Filter_GreaterOrEqual:
		return p.cmp(n.GreaterOrEqual, Ge)
	case *connectorv1.Filter_LessOrEqual:
		return p.cmp(n.LessOrEqual, Le)
	case *connectorv1.Filter_Approx:
		return p.cmp(n.Approx, Approx)
	case *connectorv1.Filter_Present:
		a, _, err := p.attr(n.Present)
		if err != nil {
			return nil, err
		}
		return Present(a), nil
	case *connectorv1.Filter_Substring:
		s := n.Substring
		a, _, err := p.attr(s.GetAttribute())
		if err != nil {
			return nil, err
		}
		total := len(s.GetInitial()) + len(s.GetFinal())
		for _, x := range s.GetAny() {
			total += len(x)
		}
		if total > p.lim.MaxValueBytes { // same total-across-segments rule as the text parser
			return nil, fail(ValueTooLong)
		}
		return Substring(a, s.GetInitial(), s.GetAny(), s.GetFinal()), nil
	case *connectorv1.Filter_BitAnd:
		a, _, err := p.attr(n.BitAnd.GetAttribute())
		if err != nil {
			return nil, err
		}
		return BitAnd(a, n.BitAnd.GetMask()), nil
	case *connectorv1.Filter_BitOr:
		a, _, err := p.attr(n.BitOr.GetAttribute())
		if err != nil {
			return nil, err
		}
		return BitOr(a, n.BitOr.GetMask()), nil
	case *connectorv1.Filter_InChain:
		a, _, err := p.attr(n.InChain.GetAttribute())
		if err != nil {
			return nil, err
		}
		d, err := p.dnOf(n.InChain.GetDn())
		if err != nil {
			return nil, err
		}
		return InChain(a, d), nil
	}
	return nil, fail(InvalidFilter)
}

func (p *astParser) list(l *connectorv1.FilterList, op byte, depth int) (Filter, error) {
	kids := l.GetChildren()
	if len(kids) == 0 {
		return nil, fail(EmptyComposite)
	}
	if len(kids) > p.lim.MaxFanOut {
		return nil, fail(TooWide)
	}
	out := make([]Filter, 0, len(kids))
	for _, k := range kids {
		f, err := p.node(k, depth+1)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	if op == '&' {
		return And(out...), nil
	}
	return Or(out...), nil
}

func (p *astParser) cmp(c *connectorv1.Comparison, mk func(AttrName, Value) Filter) (Filter, error) {
	a, _, err := p.attr(c.GetAttribute())
	if err != nil {
		return nil, err
	}
	v, err := p.value(c.GetValue())
	if err != nil {
		return nil, err
	}
	return mk(a, v), nil
}

func (p *astParser) value(m *connectorv1.FilterValue) (Value, error) {
	var v Value
	switch x := m.GetValue().(type) {
	case *connectorv1.FilterValue_Text:
		if len(x.Text) > p.lim.MaxValueBytes {
			return Value{}, fail(ValueTooLong)
		}
		v = String(x.Text)
	case *connectorv1.FilterValue_Octets:
		if len(x.Octets) > p.lim.MaxValueBytes {
			return Value{}, fail(ValueTooLong)
		}
		v = Bytes(x.Octets)
	case *connectorv1.FilterValue_Guid:
		g, err := guid.FromBytes(x.Guid.GetValue())
		if err != nil {
			return Value{}, fail(InvalidValue)
		}
		v = GUID(g)
	case *connectorv1.FilterValue_Sid:
		s, err := sid.FromBytes(x.Sid.GetValue())
		if err != nil {
			return Value{}, fail(InvalidValue)
		}
		v = SID(s)
	case *connectorv1.FilterValue_Dn:
		d, err := p.dnOf(x.Dn)
		if err != nil {
			return Value{}, err
		}
		v = DNValue(d)
	case *connectorv1.FilterValue_Int32Value:
		v = Int32(x.Int32Value)
	case *connectorv1.FilterValue_Int64Value:
		v = Int64(x.Int64Value)
	case *connectorv1.FilterValue_FileTime:
		t, err := checkedTime(x.FileTime)
		if err != nil {
			return Value{}, err
		}
		if x.FileTime.GetNanos()%100 != 0 { // sub-100 ns precision is rejected, not rounded
			return Value{}, fail(InvalidValue)
		}
		v = FileTime(t)
	case *connectorv1.FilterValue_GeneralizedTime:
		t, err := checkedTime(x.GeneralizedTime)
		if err != nil {
			return Value{}, err
		}
		v = GeneralizedTime(t)
	default:
		return Value{}, fail(InvalidValue)
	}
	return v, nil
}

func checkedTime(ts *timestamppb.Timestamp) (t time.Time, err error) {
	if ts.CheckValid() != nil {
		return t, fail(InvalidValue)
	}
	return ts.AsTime(), nil
}

// dnOf builds a DN from the wire RDN list (leaf first) through the P2 builder, so every value is
// escaped on render, then requires the caller to be able to read the object.
func (p *astParser) dnOf(m *connectorv1.Dn) (dn.DN, error) {
	rdns := m.GetRdns()
	if len(rdns) == 0 || len(rdns) > dn.MaxRDNs {
		return dn.DN{}, fail(InvalidValue)
	}
	var d dn.DN
	for i := len(rdns) - 1; i >= 0; i-- {
		t, err := dn.ParseRDNType(rdns[i].GetType())
		if err != nil {
			return dn.DN{}, fail(InvalidValue)
		}
		text, ok := rdns[i].GetValue().(*connectorv1.Rdn_Text)
		if !ok {
			return dn.DN{}, fail(InvalidValue)
		}
		if d, err = dn.Child(d, t, text.Text); err != nil {
			return dn.DN{}, fail(InvalidValue)
		}
	}
	// The rendered form is what Render emits, so it is bounded by the same narrowed limit the text
	// parser applies to DN assertion values (checked before asking the Caller to read the object).
	if len(d.String()) > p.lim.MaxValueBytes {
		return dn.DN{}, fail(ValueTooLong)
	}
	return p.readable(d)
}
