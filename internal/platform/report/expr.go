package report

import (
	"bytes"
	"encoding/json"
)

// Limits on a filter expression.
const (
	MaxExprTerms  = 32
	MaxExprDepth  = 8
	MaxExprNodes  = 64
	MaxInValues   = 1000
	MaxSortKeys   = 4
	MaxQueryCols  = 64
	maxDaysNumber = 3660
)

// Expr is a sealed tagged union: And, Or, Not or Cmp. JSON: {"and":[…]}, {"or":[…]}, {"not":…},
// {"cmp":{"col":"status","op":"eq","value":{"enum":"enabled"}}}, with {"param":"days"} in place of
// a value.
type Expr interface{ expr() }

// And is true when every term is.
type And struct{ Terms []Expr }

// Or is true when any term is.
type Or struct{ Terms []Expr }

// Not negates its term.
type Not struct{ Term Expr }

// Cmp compares one column with a value. Exactly one of Value, Values (OpIn only) and Param is set
// for an operator that takes a value; none is set for OpPresent and OpAbsent. Param names a
// definition parameter, and Resolve replaces it with its value, so a Query never holds one.
type Cmp struct {
	Column ColumnID
	Op     Op
	Value  Value
	Values []Value
	Param  string
}

func (And) expr() {}
func (Or) expr()  {}
func (Not) expr() {}
func (Cmp) expr() {}

// ---- JSON ---------------------------------------------------------------------------------------

type cmpJSON struct {
	Col    ColumnID `json:"col"`
	Op     string   `json:"op"`
	Value  *Value   `json:"value,omitempty"`
	Values []Value  `json:"values,omitempty"`
	Param  string   `json:"param,omitempty"`
}

// MarshalJSON writes the canonical form.
func (a And) MarshalJSON() ([]byte, error) { return json.Marshal(map[string][]Expr{"and": a.Terms}) }

// MarshalJSON writes the canonical form.
func (o Or) MarshalJSON() ([]byte, error) { return json.Marshal(map[string][]Expr{"or": o.Terms}) }

// MarshalJSON writes the canonical form.
func (n Not) MarshalJSON() ([]byte, error) { return json.Marshal(map[string]Expr{"not": n.Term}) }

// MarshalJSON writes the canonical form.
func (c Cmp) MarshalJSON() ([]byte, error) {
	j := cmpJSON{Col: c.Column, Op: c.Op.String(), Values: c.Values, Param: c.Param}
	if c.Value.Type() != TypeInvalid {
		v := c.Value
		j.Value = &v
	}
	return json.Marshal(map[string]cmpJSON{"cmp": j})
}

// UnmarshalExpr decodes an Expr strictly: unknown fields, several node kinds in one object, an
// unknown operator and trailing data are all refused. It checks shape only; Resolve checks names.
func UnmarshalExpr(data []byte) (Expr, error) {
	e, err := decodeExpr(data, 0, new(int))
	if err != nil {
		return nil, err
	}
	return e, nil
}

func decodeExpr(data []byte, depth int, nodes *int) (Expr, error) {
	if depth > MaxExprDepth {
		return nil, verr(CodeTooComplex, "expr")
	}
	if *nodes++; *nodes > MaxExprNodes {
		return nil, verr(CodeTooComplex, "expr")
	}
	var m map[string]json.RawMessage
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&m); err != nil || len(m) != 1 || dec.More() {
		return nil, verr(CodeInvalidQuery, "expr")
	}
	for k, raw := range m {
		switch k {
		case "and", "or":
			var parts []json.RawMessage
			if err := json.Unmarshal(raw, &parts); err != nil || len(parts) == 0 {
				return nil, verr(CodeInvalidQuery, "expr."+k)
			}
			if len(parts) > MaxExprTerms {
				return nil, verr(CodeTooComplex, "expr."+k)
			}
			terms := make([]Expr, 0, len(parts))
			for _, p := range parts {
				t, err := decodeExpr(p, depth+1, nodes)
				if err != nil {
					return nil, err
				}
				terms = append(terms, t)
			}
			if k == "and" {
				return And{terms}, nil
			}
			return Or{terms}, nil
		case "not":
			t, err := decodeExpr(raw, depth+1, nodes)
			if err != nil {
				return nil, err
			}
			return Not{t}, nil
		case "cmp":
			var j cmpJSON
			d := json.NewDecoder(bytes.NewReader(raw))
			d.DisallowUnknownFields()
			if err := d.Decode(&j); err != nil {
				return nil, verr(CodeInvalidQuery, "expr.cmp")
			}
			op, ok := ParseOp(j.Op)
			if !ok {
				return nil, verr(CodeUnknownOperator, "expr.cmp.op")
			}
			c := Cmp{Column: j.Col, Op: op, Values: j.Values, Param: j.Param}
			if j.Value != nil {
				c.Value = *j.Value
			}
			return c, nil
		}
		return nil, verr(CodeInvalidQuery, "expr")
	}
	return nil, verr(CodeInvalidQuery, "expr")
}

// UnmarshalJSON lets an Expr-typed field decode through UnmarshalExpr when held in a wrapper.
type exprSlot struct{ e Expr }

func (s *exprSlot) UnmarshalJSON(b []byte) error {
	e, err := UnmarshalExpr(b)
	if err != nil {
		return err
	}
	s.e = e
	return nil
}

// columns appends every column an expression names, in order.
func columns(e Expr, out []ColumnID) []ColumnID {
	switch x := e.(type) {
	case And:
		for _, t := range x.Terms {
			out = columns(t, out)
		}
	case Or:
		for _, t := range x.Terms {
			out = columns(t, out)
		}
	case Not:
		out = columns(x.Term, out)
	case Cmp:
		out = append(out, x.Column)
	}
	return out
}
