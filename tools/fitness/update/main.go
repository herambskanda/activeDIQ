// Command update is the T-0139 fitness function TM-F-UPDATE (threat model section 10, ENH-07 AC-1..AC-8):
// it drives the one shared update verifier (internal/platform/updateverify) through both couriers, the
// online one over loopback HTTP and the offline bundle with no socket, with a signed fixture train built
// from throw-away keys, and fails unless every bad update is refused with its reason, nothing lands
// outside quarantine, a good release and a root rotation are accepted, and both couriers end identical.
//
//	go run ./tools/fitness/update [-courier both|online|offline] [-sabotage accept-all|mislabel|leak]
//
// -sabotage swaps in a deliberately broken verifier so `make ci-proof` can show the proof fails when the
// verifier does. Run with --network none through `make fitness-update-offline`.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/skenzeriq/activediq/internal/platform/updateverify"
)

func main() {
	which := flag.String("courier", "both", "both, online or offline")
	sabotage := flag.String("sabotage", "", "accept-all, mislabel or leak: run against a broken verifier (ci-proof only)")
	flag.Parse()

	var cs []courier
	switch *which {
	case "both":
		cs = []courier{onlineCourier, offlineCourier}
	case "online":
		cs = []courier{onlineCourier}
	case "offline":
		cs = []courier{offlineCourier}
	default:
		fmt.Fprintln(os.Stderr, "unknown -courier", *which)
		os.Exit(2)
	}
	verify, err := verifyFor(*sabotage)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	sc := scenarios()
	problems := Run(sc, cs, verify)
	for _, p := range problems {
		fmt.Fprintln(os.Stderr, p)
	}
	if len(problems) > 0 {
		fmt.Fprintf(os.Stderr, "fitness-update: FAIL: %d problem(s) across %d scenarios\n", len(problems), len(sc))
		os.Exit(1)
	}
	fmt.Printf("fitness-update: ok (%d scenarios x %d courier(s))\n", len(sc), len(cs))
}

func verifyFor(mode string) (verifyFunc, error) {
	switch mode {
	case "":
		return realVerify, nil
	case "accept-all": // a verifier whose checks are gone
		return func(ctx context.Context, v *updateverify.Verifier, in updateverify.Input, d string) (*updateverify.Result, error) {
			res, err := v.Verify(ctx, in)
			var ref *updateverify.Refusal
			if errors.As(err, &ref) {
				return &updateverify.Result{}, nil
			}
			return res, err
		}, nil
	case "mislabel": // refuses, but never says why
		return func(ctx context.Context, v *updateverify.Verifier, in updateverify.Input, d string) (*updateverify.Result, error) {
			res, err := v.Verify(ctx, in)
			var ref *updateverify.Refusal
			if errors.As(err, &ref) {
				c := *ref
				c.Reason = updateverify.ReasonTamper
				return nil, &c
			}
			return res, err
		}, nil
	case "leak": // extracts before it has finished deciding
		return func(ctx context.Context, v *updateverify.Verifier, in updateverify.Input, d string) (*updateverify.Result, error) {
			_ = os.WriteFile(filepath.Join(d, "unpacked.bin"), []byte("x"), 0o600)
			return v.Verify(ctx, in)
		}, nil
	}
	return nil, fmt.Errorf("unknown -sabotage %q", mode)
}
