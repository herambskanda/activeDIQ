package m

import "internal/platform/operation/step"

func smuggle(s step.Step) {
	var kept step.Step
	//fitness:allow-step-escape proves the runner revokes a smuggled copy
	f := func() { kept = s }
	f()
	//fitness:allow-step-escape
	g := func() { _ = s } // want `captured by a closure`
	g()
	_ = kept
}
