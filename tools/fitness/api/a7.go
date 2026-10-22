package main

// checkA7 is ADR-0004 A7 (strict JSON): rule 7's static bans, then the runtime parts over the
// router apihost.Build makes: the type closure, the corpus and the ajv cross-check.
func checkA7(t *tree) []Violation {
	return append(goStaticJSON(t.root), checkA7Runtime(t)...)
}
