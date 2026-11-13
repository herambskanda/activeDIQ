// Command host is the TM-F-HOST proof (threat-model §15). Modes:
//
//	host oci [-repo .]        build and boot the real server in a container and judge it (needs Docker)
//	host p2-oci [-repo .]     P2-oci: build the server image of linux-oci and saas for amd64 and arm64, boot
//	                          each against PostgreSQL 16 and 18, prove migrations, health and tenant count
//	host evaluate <file.json> judge an observation collected elsewhere (the Windows lab collector)
//	host cases                list the named cases
//
// A case fails the build, is INACTIVE (nothing observed), or is a KNOWN GAP: a failure that
// known-gaps.json names with the ticket that fixes it. A known gap that no longer fails is itself a
// failure, so the list can only shrink.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	host "github.com/skenzeriq/activediq/tools/fitness/host/hostcheck"
	"github.com/skenzeriq/activediq/tools/fitness/pgharness"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: host oci|p2-oci|evaluate|cases")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "cases":
		for _, c := range host.Cases {
			fmt.Println(c)
		}
	case "evaluate":
		fs := flag.NewFlagSet("evaluate", flag.ExitOnError)
		repo := fs.String("repo", ".", "repository root (for known-gaps.json)")
		_ = fs.Parse(os.Args[2:])
		if fs.NArg() != 1 {
			fmt.Fprintln(os.Stderr, "usage: host evaluate [-repo .] <observation.json>")
			os.Exit(2)
		}
		b, err := os.ReadFile(fs.Arg(0))
		if err != nil {
			fatal(err)
		}
		var o host.Observation
		if err := json.Unmarshal(b, &o); err != nil {
			fatal(err)
		}
		os.Exit(report(o, *repo))
	case "p2-oci":
		os.Exit(runP2OCI(os.Args[2:]))
	case "oci":
		fs := flag.NewFlagSet("oci", flag.ExitOnError)
		repo := fs.String("repo", ".", "repository root")
		out := fs.String("o", "", "also write the observation JSON here")
		_ = fs.Parse(os.Args[2:])
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
		defer cancel()
		if err := pgharness.DockerAvailable(ctx); err != nil {
			fatal(fmt.Errorf("fitness-host needs Docker: %w", err))
		}
		pg, err := pgharness.StartServer(ctx, "16", nil)
		if err != nil {
			fatal(err)
		}
		defer pg.Stop()
		o, err := host.CollectOCI(ctx, *repo, pg, func(f string, a ...any) { fmt.Printf("host: "+f+"\n", a...) })
		if err != nil {
			pg.Stop()
			fatal(err)
		}
		if *out != "" {
			b, _ := json.MarshalIndent(o, "", "  ")
			_ = os.WriteFile(*out, b, 0o600)
		}
		code := report(o, *repo)
		pg.Stop()
		os.Exit(code)
	default:
		fmt.Fprintln(os.Stderr, "unknown mode", os.Args[1])
		os.Exit(2)
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "fitness-host:", err)
	os.Exit(1)
}

func report(o host.Observation, repo string) int {
	gaps, err := host.LoadGaps(filepath.Join(repo, "tools/fitness/host/known-gaps.json"), o.Profile)
	if err != nil {
		fatal(err)
	}
	failed := false
	for _, r := range host.Judge(host.Evaluate(o), gaps) {
		fmt.Println(r.Line())
		failed = failed || r.Fails()
	}
	if failed {
		fmt.Fprintln(os.Stderr, "fitness-host: FAIL")
		return 1
	}
	fmt.Println("fitness-host: ok")
	return 0
}

// runP2OCI is the P2-oci check of the fitness-profiles activation table (ADR-0002 erratum E-3). The flags
// narrow the matrix for a fixture run; the defaults are the full one the gate runs.
func runP2OCI(args []string) int {
	fs := flag.NewFlagSet("p2-oci", flag.ExitOnError)
	repo := fs.String("repo", ".", "repository root")
	migs := fs.String("migrations", "", "migrations directory (default <repo>/migrations; a fixture points it at a broken one)")
	profiles := fs.String("profile", "", "comma-separated profiles (default linux-oci,saas)")
	arches := fs.String("arch", "", "comma-separated architectures (default amd64,arm64)")
	pgs := fs.String("pg", "", "comma-separated PostgreSQL majors (default 16,18)")
	_ = fs.Parse(args)
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Minute)
	defer cancel()
	if err := pgharness.DockerAvailable(ctx); err != nil {
		fatal(fmt.Errorf("P2-oci needs Docker: %w", err))
	}
	split := func(s string) []string {
		if s == "" {
			return nil
		}
		return strings.Split(s, ",")
	}
	fails := host.P2OCI(ctx, host.P2OCIOptions{
		Repo: *repo, MigrationsDir: *migs, Profiles: split(*profiles), Arches: split(*arches), PGVersions: split(*pgs),
		RequireBoot: os.Getenv("P2_OCI_REQUIRE_BOOT") == "1",
		Log:         func(f string, a ...any) { fmt.Printf(f+"\n", a...) },
	})
	if len(fails) > 0 {
		fmt.Fprintf(os.Stderr, "fitness-host p2-oci: FAIL (%d legs)\n", len(fails))
		for _, e := range fails {
			fmt.Fprintln(os.Stderr, "  "+strings.SplitN(e.Error(), "\n", 2)[0])
		}
		return 1
	}
	fmt.Println("fitness-host p2-oci: ok")
	return 0
}
