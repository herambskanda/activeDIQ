package main

// checkA7 is the static half of ADR-0004 A7 (strict JSON): rule 7's bans. The type-closure,
// corpus and ajv cross-check parts need the apihost route table and stay inactive until
// apihost.Build exists.
func checkA7(t *tree) []Violation { return goStaticJSON(t.root) }
