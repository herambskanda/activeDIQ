package m

import (
	"fmt"

	"internal/platform/operation/step"
)

type iface interface{ Do(x any) }

func ok(s step.Step) error {
	if err := s.Valid(); err != nil {
		return err
	}
	step.Use(s)
	helper(s, 1)
	f := func(t step.Step) { _ = t.Valid() }
	f(s)
	g := func() { var local step.Step; _ = local.Valid() }
	g()
	return nil
}

func helper(s step.Step, n int) { _ = n; _ = s }

func captured(s step.Step) {
	go func() { _ = s.Valid() }() // want `captured by a closure`
}

func capturedPtr(s *step.Step) {
	h := func() { _ = s } // want `captured by a closure`
	h()
}

func leak(s step.Step, i iface) {
	fmt.Println(s)  // want `no step.Step parameter`
	i.Do(s)         // want `no step.Step parameter`
	_ = any(s)      // want `converted to any`
	sink(s.Valid()) // the error, not the Step, is passed
	sink2(s)        // want `no step.Step parameter`
}

func sink(error) {}
func sink2(any)  {}

func directiveIgnoredOutsideTests(s step.Step) {
	//fitness:allow-step-escape not honoured in product code
	f := func() { _ = s } // want `captured by a closure`
	f()
}
