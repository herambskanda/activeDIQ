package report

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/authz"
)

// PerDCPart says which part of a per-DC read a column shows (reports.md §6.5).
type PerDCPart uint8

const (
	PartValue     PerDCPart = iota // the zero value: the aggregate of Attr over the DCs that answered
	PartFromDC                     // the DC that gave that aggregate
	PartCoverage                   // "2 of 3 DCs"
	PartAtWinner                   // Attr's value at the DC that gave the aggregate of Of (the count is never summed)
	PartDaysSince                  // whole days from the aggregate (a time attribute) to the read time
	perDCPartEnd
)

// Valid reports whether p is a defined part.
func (p PerDCPart) Valid() bool { return p < perDCPartEnd }

// IsTime reports whether the attribute is a time (lastLogon, badPasswordTime, lockoutTime); the others are counts.
func (a PerDCAttr) IsTime() bool {
	return a == PerDCLastLogon || a == PerDCBadPasswordTime || a == PerDCLockoutTime
}

// check validates a per-DC column source against the column's type: the part fixes the type.
func (s PerDC) check(t ValueType) error {
	if !s.Attr.Valid() || !s.Agg.Valid() || !s.Part.Valid() {
		return errors.New("invalid per-DC source")
	}
	want := TypeInt
	switch s.Part {
	case PartValue:
		if s.Attr.IsTime() {
			want = TypeTime
		}
	case PartFromDC, PartCoverage:
		want = TypeText
	case PartAtWinner:
		if !s.Of.Valid() {
			return errors.New("a value at the winning DC names the attribute that picks the DC")
		}
		if s.Attr.IsTime() {
			want = TypeTime
		}
	case PartDaysSince:
		if !s.Attr.IsTime() {
			return errors.New("days since needs a time attribute")
		}
	}
	if s.Part != PartAtWinner && s.Of != 0 {
		return errors.New("only a value at the winning DC names a picking attribute")
	}
	if t != want {
		return fmt.Errorf("a per-DC column of this kind is %s, not %s", want, t)
	}
	return nil
}

// NotConfirmedText is what a time cell reads when coverage is partial and no answering DC holds a value:
// the account may have logged on at a DC that did not answer, so "never" would be a claim we cannot make
// (spec §6.5, AC-40).
const NotConfirmedText = "Not confirmed"

// AtLeastSuffix is appended to the label of a per-DC aggregate column when coverage is partial: the value
// is a lower bound.
const AtLeastSuffix = " (at least)"

// CoverageText is the per-row coverage cell: "2 of 3 DCs".
func CoverageText(answered, inScope int) string {
	return fmt.Sprintf("%d of %d DCs", answered, inScope)
}

// PerDCFold is one object's per-DC answers reduced to what the aggregates need: the DCs that answered,
// in DC-name order, and how many were asked. It never sums.
type PerDCFold struct {
	InScope  int
	Answered []PerDCResult
}

// FoldPerDC reduces an object's results. A DC whose result carries Err did not answer.
func FoldPerDC(o PerDCObject) PerDCFold {
	f := PerDCFold{InScope: len(o.Results)}
	for _, r := range o.Results {
		if r.Err == "" {
			f.Answered = append(f.Answered, r)
		}
	}
	slices.SortStableFunc(f.Answered, func(a, b PerDCResult) int { return strings.Compare(a.DC, b.DC) })
	return f
}

// Complete reports whether every DC in scope answered (and at least one was asked).
func (f PerDCFold) Complete() bool { return f.InScope > 0 && len(f.Answered) == f.InScope }

// PerDCAggregate is the combined value of one attribute and the DC it came from.
type PerDCAggregate struct {
	Time time.Time
	Int  int64
	DC   string
}

// Aggregate combines the attribute over the DCs that answered. A time of zero means "unset on that DC"
// and takes no part (a minimum over unset values is not a date); a count of zero is a real count. The
// second result is false when no answering DC holds a value. Ties go to the first DC by name.
func (f PerDCFold) Aggregate(a PerDCAttr, g PerDCAgg) (PerDCAggregate, bool) {
	var out PerDCAggregate
	found := false
	for _, r := range f.Answered {
		for _, v := range r.Values {
			if v.Attr != a {
				continue
			}
			if a.IsTime() && v.Time.IsZero() {
				continue
			}
			better := !found
			if found {
				switch {
				case a.IsTime() && g == AggMax:
					better = v.Time.After(out.Time)
				case a.IsTime():
					better = v.Time.Before(out.Time)
				case g == AggMax:
					better = v.Int > out.Int
				default:
					better = v.Int < out.Int
				}
			}
			if better {
				out, found = PerDCAggregate{Time: v.Time, Int: v.Int, DC: r.DC}, true
			}
		}
	}
	return out, found
}

// valueAt is attr's value at one DC.
func (f PerDCFold) valueAt(dc string, a PerDCAttr) (PerDCValue, bool) {
	for _, r := range f.Answered {
		if r.DC != dc {
			continue
		}
		for _, v := range r.Values {
			if v.Attr == a {
				return v, true
			}
		}
	}
	return PerDCValue{}, false
}

// PerDCCells are one row's per-DC cells. Stored is what the run keeps and shows; Eval is what PerDCWhere
// is judged on, where "Not confirmed" is Unknown (no value, and not "absent" either), so a filter can
// never match a value nobody confirmed.
type PerDCCells struct {
	Stored map[ColumnID]Cell
	Eval   map[ColumnID]Cell
}

// Cells builds the per-DC cells of one row for the given per-DC columns. now is the read time (UTC).
func (f PerDCFold) Cells(cols []Column, now time.Time) PerDCCells {
	out := PerDCCells{Stored: make(map[ColumnID]Cell, len(cols)), Eval: make(map[ColumnID]Cell, len(cols))}
	set := func(id ColumnID, stored, eval Cell) { out.Stored[id], out.Eval[id] = stored, eval }
	for _, c := range cols {
		src, ok := c.Source.(PerDC)
		if !ok {
			continue
		}
		if src.Part == PartCoverage {
			cell := TextCell(CoverageText(len(f.Answered), f.InScope))
			set(c.ID, cell, cell)
			continue
		}
		pick := src.Attr
		if src.Part == PartAtWinner {
			pick = src.Of
		}
		agg, ok := f.Aggregate(pick, src.Agg)
		if !ok {
			// No answering DC holds a value. With every DC answering that is a fact (the attribute is unset
			// everywhere: "never" for a time); with some silent it is only "not confirmed".
			switch {
			case src.Part == PartValue && c.Type == TypeTime && f.Complete():
				set(c.ID, Never(), Never())
			case src.Part == PartValue && c.Type == TypeTime:
				set(c.ID, TextCell(NotConfirmedText), Unknown())
			case f.Complete():
				set(c.ID, Absent(), Absent())
			default:
				set(c.ID, Absent(), Unknown())
			}
			continue
		}
		switch src.Part {
		case PartValue:
			if c.Type == TypeTime {
				set(c.ID, TimeCell(agg.Time), TimeCell(agg.Time))
			} else {
				set(c.ID, IntCell(agg.Int), IntCell(agg.Int))
			}
		case PartFromDC:
			set(c.ID, TextCell(agg.DC), TextCell(agg.DC))
		case PartAtWinner:
			v, ok := f.valueAt(agg.DC, src.Attr)
			switch {
			case !ok:
				set(c.ID, Absent(), Absent())
			case c.Type == TypeTime:
				if v.Time.IsZero() {
					set(c.ID, Absent(), Absent())
				} else {
					set(c.ID, TimeCell(v.Time), TimeCell(v.Time))
				}
			default:
				set(c.ID, IntCell(v.Int), IntCell(v.Int))
			}
		case PartDaysSince:
			d := int64(now.UTC().Sub(agg.Time) / (24 * time.Hour))
			d = max(d, 0)
			set(c.ID, IntCell(d), IntCell(d))
		}
	}
	return out
}

// EvalPerDC judges the per-DC part of a query (Query.PerDCWhere) over one row's per-DC cells (Eval). It is
// the one predicate evaluated outside SQL (reports.md §6.5), and it touches only values SQL cannot see.
// A nil expression is true. Operators mirror the compiler's: a relative operator compares with now (UTC);
// a comparison on a cell that holds no value (absent, never, unknown) is false, and `absent` is true only
// for absent and never, never for unknown.
func EvalPerDC(e Expr, row map[ColumnID]Cell, now time.Time) (bool, error) {
	return evalPerDC(e, row, now.UTC(), 0)
}

func evalPerDC(e Expr, row map[ColumnID]Cell, now time.Time, depth int) (bool, error) {
	if depth > MaxExprDepth {
		return false, verr(CodeTooComplex, "perDCWhere")
	}
	switch x := e.(type) {
	case nil:
		return true, nil
	case And:
		for _, t := range x.Terms {
			ok, err := evalPerDC(t, row, now, depth+1)
			if err != nil || !ok {
				return false, err
			}
		}
		return true, nil
	case Or:
		for _, t := range x.Terms {
			ok, err := evalPerDC(t, row, now, depth+1)
			if err != nil {
				return false, err
			}
			if ok {
				return true, nil
			}
		}
		return false, nil
	case Not:
		// NOT of a comparison on an unknown cell stays false: an unconfirmed value matches neither side.
		if unknownIn(x.Term, row) {
			return false, nil
		}
		ok, err := evalPerDC(x.Term, row, now, depth+1)
		return !ok && err == nil, err
	case Cmp:
		return cmpPerDC(x, row, now)
	}
	return false, verr(CodeInvalidQuery, "perDCWhere")
}

func unknownIn(e Expr, row map[ColumnID]Cell) bool {
	for _, id := range columns(e, nil) {
		if row[id].IsUnknown() {
			return true
		}
	}
	return false
}

func cmpPerDC(c Cmp, row map[ColumnID]Cell, now time.Time) (bool, error) {
	cell, ok := row[c.Column]
	if !ok {
		return false, verr(CodeUnknownColumn, "perDCWhere")
	}
	valued := cell.Kind() == CellTime || cell.Kind() == CellInt || cell.Kind() == CellText || cell.Kind() == CellBool
	switch c.Op {
	case OpPresent:
		return valued, nil
	case OpAbsent:
		return !valued && !cell.IsUnknown(), nil
	}
	if !valued {
		return false, nil
	}
	if c.Op.relative() {
		if cell.Kind() != CellTime || c.Value.Type() != TypeInt || c.Value.Int() < 0 || c.Value.Int() > maxDaysNumber {
			return false, verr(CodeBadValue, "perDCWhere")
		}
		span := time.Duration(c.Value.Int()) * 24 * time.Hour
		t := cell.Time()
		switch c.Op {
		case OpWithinLastDays:
			return t.After(now.Add(-span)) && !t.After(now), nil
		case OpOlderThanDays:
			return !t.After(now.Add(-span)), nil
		default:
			return t.After(now) && !t.After(now.Add(span)), nil
		}
	}
	if c.Op == OpIn {
		for _, v := range c.Values {
			if eq, err := equalCell(cell, v); err != nil {
				return false, err
			} else if eq {
				return true, nil
			}
		}
		return false, nil
	}
	switch c.Op {
	case OpEq, OpNe:
		eq, err := equalCell(cell, c.Value)
		if err != nil {
			return false, err
		}
		return eq == (c.Op == OpEq), nil
	case OpContains:
		return cell.Kind() == CellText && c.Value.Type() == TypeText && strings.Contains(strings.ToLower(cell.Text()), strings.ToLower(c.Value.Text())), nil
	case OpPrefix:
		return cell.Kind() == CellText && c.Value.Type() == TypeText && strings.HasPrefix(strings.ToLower(cell.Text()), strings.ToLower(c.Value.Text())), nil
	case OpLt, OpLe, OpGt, OpGe:
		var cmp int
		switch {
		case cell.Kind() == CellInt && c.Value.Type() == TypeInt:
			cmp = compare(cell.Int(), c.Value.Int())
		case cell.Kind() == CellTime && c.Value.Type() == TypeTime:
			cmp = cell.Time().Compare(c.Value.Time())
		default:
			return false, verr(CodeBadValue, "perDCWhere")
		}
		switch c.Op {
		case OpLt:
			return cmp < 0, nil
		case OpLe:
			return cmp <= 0, nil
		case OpGt:
			return cmp > 0, nil
		}
		return cmp >= 0, nil
	}
	return false, verr(CodeUnknownOperator, "perDCWhere")
}

func compare(a, b int64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

func equalCell(c Cell, v Value) (bool, error) {
	switch {
	case c.Kind() == CellInt && v.Type() == TypeInt:
		return c.Int() == v.Int(), nil
	case c.Kind() == CellTime && v.Type() == TypeTime:
		return c.Time().Equal(v.Time()), nil
	case c.Kind() == CellText && v.Type() == TypeText:
		return strings.EqualFold(c.Text(), v.Text()), nil
	case c.Kind() == CellBool && v.Type() == TypeBool:
		return c.Bool() == v.Bool(), nil
	}
	return false, verr(CodeBadValue, "perDCWhere")
}

// ---- the read cap ------------------------------------------------------------------------------

// DefaultPerDCReadCap is the most per-object-per-DC reads one run may make (spec §6.5, [PROPOSED]; B13
// calibrates it).
const DefaultPerDCReadCap = 250_000

// PerDCBatchSize is how many objects one read-and-store round carries (reports.md §6.5 stage 3).
const PerDCBatchSize = 200

// PerDCReads is the estimate of a run's reads: candidates × DCs in scope, saturating.
func PerDCReads(candidates, dcs uint64) uint64 {
	if candidates != 0 && dcs > ^uint64(0)/candidates {
		return ^uint64(0)
	}
	return candidates * dcs
}

// DCCounter says how many DCs a read of a naming context would ask, before any read is made. A count that
// cannot be had is an error, never a guess: the cap refuses on a number, not on a hope.
type DCCounter interface {
	DCsInScope(ctx context.Context, conn, nc authz.ObjectID, scope PerDCScope) (int, error)
}

// ---- the run tally -----------------------------------------------------------------------------

// MaxUnreachable bounds how many unreachable DCs a run record names.
const MaxUnreachable = 50

// DCFault is a DC that did not answer, and the fixed code it gave.
type DCFault struct {
	DC  string
	Err string
}

// PerDCTally accumulates a run's coverage over its objects: the most DCs any object saw, the fewest that
// answered, and every DC that failed to answer, named once with its code.
type PerDCTally struct {
	InScope     int
	Answered    int
	Partial     bool
	Objects     int
	Unreachable []DCFault
	seen        map[string]bool
}

// Add folds one object's answers into the tally.
func (t *PerDCTally) Add(o PerDCObject) {
	f := FoldPerDC(o)
	if t.Objects == 0 {
		t.Answered = len(f.Answered)
	}
	t.Objects++
	t.InScope = max(t.InScope, f.InScope)
	t.Answered = min(t.Answered, len(f.Answered))
	if !f.Complete() {
		t.Partial = true
	}
	for _, r := range o.Results {
		if r.Err == "" || t.seen[r.DC] {
			continue
		}
		if t.seen == nil {
			t.seen = map[string]bool{}
		}
		t.seen[r.DC] = true
		if len(t.Unreachable) < MaxUnreachable {
			t.Unreachable = append(t.Unreachable, DCFault{DC: r.DC, Err: r.Err})
		}
	}
}

// Merge folds the summary the reader gave for a batch: it may know of DCs no object result named.
func (t *PerDCTally) Merge(s PerDCSummary) {
	t.InScope = max(t.InScope, int(s.DCsInScope))
	if s.Coverage != CoverageComplete {
		t.Partial = true
	}
}

// Complete reports whether every DC in scope answered every object read.
func (t PerDCTally) Complete() bool {
	return t.Objects > 0 && !t.Partial && t.Answered == t.InScope && t.InScope > 0
}

// Sorted returns the unreachable DCs in name order.
func (t PerDCTally) Sorted() []DCFault {
	out := slices.Clone(t.Unreachable)
	slices.SortFunc(out, func(a, b DCFault) int { return strings.Compare(a.DC, b.DC) })
	return out
}

// ExprColumns lists the columns an expression compares, each once, in first-use order.
func ExprColumns(e Expr) []ColumnID {
	var out []ColumnID
	for _, c := range columns(e, nil) {
		if !slices.Contains(out, c) {
			out = append(out, c)
		}
	}
	return out
}
