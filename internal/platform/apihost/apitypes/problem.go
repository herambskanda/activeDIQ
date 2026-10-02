package apitypes

import "fmt"

func newProblem(typ, title string, status int, detail string) *Problem {
	p := &Problem{Type: typ, Title: title, Status: int64(status)}
	if detail != "" {
		p.Detail = &detail
	}
	return p
}

// Error makes a Problem a Go error, so a handler returns a problem constructor as its error. The
// text carries only the stable type and status: never a detail that could leak.
func (p *Problem) Error() string { return fmt.Sprintf("problem %s (%d)", p.Type, p.Status) }

// WithErrors attaches the per-item violations (validation, bulk).
func (p *Problem) WithErrors(e *Errors) *Problem {
	for _, v := range e.All() {
		item := ProblemError{In: ProblemErrorIn(v.In), Pointer: string(v.Pointer), Code: v.Code, Detail: v.Detail}
		p.Errors = append(p.Errors, item)
	}
	return p
}
