// Command fleetca is the fitness-fleet-ca-scope job: ADR-0008 fitness items 1-6 and the threat-model
// rows TM-TB6-T15..T18.
//
//	FCS-1  only SignServerLeaf (and server-CA creation) signs with the server CA key        (AST)
//	FCS-2  SignServerLeaf takes no key or CSR and never asks for a ClientAuth/any EKU         (AST + bound tests)
//	FCS-3  the server CA is never in the gateway client pool or TenantCAs                     (AST + bound tests)
//	FCS-4  dial never roots on a tenant CA; two tenants carry one pin                        (AST + bound tests)
//	FCS-5  fleet_server_ca has no tenant_id and a sealed_key CHECK                           (migration scan + bound tests)
//	FCS-6  the presented chain is exactly [leaf, server CA]                                   (AST + bound tests)
//
// A part whose code has not landed (no server CA yet: T-0715 and the build tickets of ADR-0008) is listed
// as pending on every run: that is not a pass, and the ADR stays out of `accepted` while any is pending.
// The part turns active by itself when its code appears, and a half-landed feature (a fleet_server_ca
// migration without SignServerLeaf, say) fails.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sort"
)

func main() {
	root := flag.String("root", ".", "repository root (the directory holding go.mod)")
	noTests := flag.Bool("static-only", false, "skip the bound tests (used by the gate proofs)")
	flag.Parse()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	fail := func(err error) { fmt.Fprintln(os.Stderr, "fitness-fleet-ca-scope:", err); os.Exit(2) }

	files, err := loadGo(*root)
	if err != nil {
		fail(err)
	}
	sql, psql, present, err := checkSchema(*root)
	if err != nil {
		fail(err)
	}
	vs, pending := checkAll(files, present)
	vs = append(vs, sql...)
	pending = append(pending, psql...)
	if !*noTests {
		bv, bp, err := runBindings(ctx, *root, files, defaultBindings, goTest)
		if err != nil {
			fail(err)
		}
		vs = append(vs, bv...)
		pending = append(pending, bp...)
	}
	sort.Strings(pending)
	for _, p := range pending {
		fmt.Printf("  pending   %s (not yet checked, not a pass)\n", p)
	}
	if len(vs) == 0 {
		fmt.Println("fitness-fleet-ca-scope: ok (FCS-1..6 as listed; pending parts above; ADR-0008 stays out of accepted until none is pending)")
		return
	}
	sort.SliceStable(vs, func(i, j int) bool {
		if vs[i].Check != vs[j].Check {
			return vs[i].Check < vs[j].Check
		}
		return vs[i].Where < vs[j].Where
	})
	for _, v := range vs {
		fmt.Fprintln(os.Stderr, v)
	}
	fmt.Fprintf(os.Stderr, "fitness-fleet-ca-scope: %d violation(s); rules: ADR-0008 fitness function\n", len(vs))
	os.Exit(1)
}
