package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/skenzeriq/activediq/tools/fitness/internal/boundtest"
)

// binding ties an SE check to the Go test that proves the behaviour (as in fitness-reports). The build
// ticket that writes the test flips Landed in this table, a review-visible edit. A landed binding fails
// when its test is missing, failed or skipped, or when a listed subtest did not run, so deleting or
// skipping the test, or running it on one PostgreSQL version, cannot weaken the check. A binding that is
// not landed is listed as pending on every run, never as a pass, and fails if its test is already
// declared: someone landed it without flipping the flag.
type binding struct {
	Check string
	What  string
	Name  string
	Pkg   string // "./<dir>"
	// Subtests are the subtests that must each have run and passed.
	Subtests []string
	// Nightly bindings run only under -nightly (the large-dataset switch) and are listed pending until
	// they land.
	Nightly bool
	Landed  bool
	Owner   string
}

// pg is the subtest set of a test that runs on every PostgreSQL version of storetest.EachVersion, with
// the named inner subtests below each.
func pg(inner ...string) []string {
	out := []string{"pg16", "pg18"}
	for _, v := range []string{"pg16", "pg18"} {
		for _, i := range inner {
			out = append(out, v+"/"+i)
		}
	}
	return out
}

const (
	inv = "./internal/directory/inventory"
	key = "./internal/platform/searchkey"
	srv = "./internal/modules/search"
)

var defaultBindings = []binding{
	{Check: "SE3", Name: "Test_search_scope_matches_read_oracle", Pkg: inv, Landed: true, Owner: "T-1095",
		Subtests: pg("oracle", "invariance_M4", "above_ceiling", "gated_kinds", "empty_scope"),
		What:     "the hits and counts of a search equal the AuthorizeRead oracle over trees written by the inventory writer; hidden matches change nothing below the ceiling (M4); above it every caller of the world gets the same refine state; an empty scope reads nothing (ADR-0011 SE3)"},
	{Check: "SE3", Name: "Test_cursor_is_bound_and_verified_before_anything_is_read", Pkg: srv, Owner: "T-1096",
		What: "a cursor replayed with another query, facet or scope fingerprint is refused (400) before any read (ADR-0011 SE3)"},
	{Check: "SE3", Name: "Test_search_template_outer_query_reads_only_hits_and_ceiling_hit", Pkg: "./internal/platform/store/reportsql", Owner: "follow-up of T-1126",
		What: "the search template's outer SELECT, ORDER BY, window and LIMIT clauses reference only the hits and ceiling_hit relations (ADR-0011 SE3 'the template itself')"},
	{Check: "SE3", Name: "Test_search_template_never_outputs_key_id", Pkg: "./internal/platform/store/reportsql", Landed: true, Owner: "T-1335",
		What: "the posting table's key_id appears only inside the template's m_fuzzy stage: it is no output column of the statement, no part of a hit and no part of the cursor (ADR-0011 SE3 'the template itself', rule 5a)"},
	{Check: "SE4", Name: "Test_search_text_is_a_bound_parameter", Pkg: inv, Landed: true, Owner: "T-1095", Subtests: pg(),
		What: "%, _, backslash, quotes, $1, '; -- and NUL-shaped text match literally or not at all (ADR-0011 SE4 hostile text)"},
	{Check: "SE4", Name: "Test_Prepare_refusals_in_order", Pkg: key, Landed: true, Owner: "T-1095",
		What: "NUL, invalid UTF-8, more than 4 KiB and 257 NFKC runes are refused, and a 48-digit recovery password in ASCII, full-width and other-script digits, with or without dashes, is refused without echoing it (ADR-0011 SE4 refusals, recovery passwords)"},
	{Check: "SE4", Name: "Test_NormName_vectors", Pkg: key, Landed: true, Owner: "T-1095",
		What: "every row of rule 7's vector table folds the same way, including Ł/ł, Ø/ø, İ/i and ẞ (ADR-0011 SE4 folding)"},
	{Check: "SE4", Name: "Test_PrefixUpper_edges", Pkg: key, Landed: true, Owner: "T-1095",
		What: "the U+D7FF and U+10FFFF edges give the bounds rule 8 states (ADR-0011 SE4 PrefixUpper)"},
	{Check: "SE4", Name: "Test_search_stores_no_secret_attribute", Pkg: inv, Landed: true, Owner: "T-1095", Subtests: pg(),
		What: "no value of a secret attribute (ms-Mcs-AdmPwd, msLAPS-*, msDS-ManagedPassword, msFVE-RecoveryPassword, searchFlags 0x80) reaches inventory_search_keys (ADR-0011 SE4 secret attributes)"},
	{Check: "SE4", Name: "Test_recovery_password_shaped_text_is_refused_unechoed_and_unlogged", Pkg: srv, Owner: "T-1096",
		What: "a recovery-password-shaped query is refused, not echoed, and in no log, trace or access-log line (ADR-0011 SE4 recovery passwords)"},
	{Check: "SE4", Name: "Test_a_served_query_is_logged_as_length_and_class_only", Pkg: srv, Owner: "T-1096",
		What: "q appears in no access-log or trace line, only its length and class (ADR-0011 SE4 search text, rule 15)"},
	{Check: "SE4", Name: "Test_search_route_logs_no_query_text", Pkg: "./internal/compose/server", Owner: "follow-up of T-1126",
		What: "the console's /search route puts q in no access-log or trace line (ADR-0011 SE4 search text, rule 15)"},
	{Check: "SE5", Name: "Test_search_work_is_bounded", Pkg: inv, Landed: true, Owner: "T-1095", Subtests: pg("fuzzy_plan", "fuzzy_longest"),
		What: "the scan nodes of the compiled statement examine W+1 rows or fewer however much the scope hides, there is no Seq Scan on the key or object table, and the answers equal the H=0 and the unscoped refine responses; the fuzzy class reads the posting index and rechecks per candidate (a Bitmap Index Scan is accepted, a Hash or Merge Join onto the keys is not), and a 32-rune query keeps that shape (ADR-0011 SE5, rule 5a)"},
	{Check: "SE6", Name: "TestSearchLatency50k", Pkg: "./internal/modules/search/latency", Nightly: true, Owner: "T-1102",
		Subtests: []string{"pg16", "pg18"},
		What:     "universal search answers within rule 14's budget per class, scoped and unscoped, over 50,000 objects on PostgreSQL 16 and 18 (ADR-0011 SE6)"},
}

// runBindings runs the landed bindings of the selected kind and lists the others as pending.
func runBindings(ctx context.Context, root string, bs []binding, nightly bool, run boundtest.Runner) (vs []Violation, pending, ran []string, err error) {
	declared, err := boundtest.Declared(root)
	if err != nil {
		return nil, nil, nil, err
	}
	var tests []boundtest.Test
	for _, b := range bs {
		pkgs := declared[b.Name]
		if !b.Landed {
			if len(pkgs) > 0 {
				vs = append(vs, Violation{b.Check, "binding-not-landed", strings.Join(pkgs, ", ") + " " + b.Name,
					"the bound test is declared but its binding is not marked Landed in tools/fitness/search/bindings.go: flip it so the job runs it"})
			}
			if b.Nightly == nightly || !nightly {
				pending = append(pending, fmt.Sprintf("%s %s (%s has not landed it)", b.Check, b.Name, b.Owner))
			}
			continue
		}
		if b.Nightly != nightly {
			continue // landed, but runs in the other job
		}
		tests = append(tests, boundtest.Test{Check: b.Check, What: b.What, Name: b.Name, Pkgs: []string{b.Pkg}, Subtests: b.Subtests})
		ran = append(ran, b.Check+" "+b.Name+" ("+b.Pkg+")")
	}
	if len(tests) == 0 {
		return vs, pending, ran, nil
	}
	fails, err := boundtest.Run(ctx, root, tests, run)
	if err != nil {
		return nil, nil, nil, err
	}
	for _, f := range fails {
		vs = append(vs, Violation{f.Check, f.Kind, f.Where, f.Msg})
	}
	return vs, pending, ran, nil
}
