// Command auditverify (adq-audit-verify) checks an activeDIQ audit export offline (ADR-0005 rule 11).
// It needs no installation and no network, and links only the standard library plus the format packages
// platform/audit/canon and platform/audit/chain, which are themselves standard-library-only.
//
//	auditverify -bundle export.json [-pin <fingerprint>]... [-anchors anchors.json]
//
// Exit status: 0 OK, 1 verification FAILED, 2 UNANCHORED (internally consistent, but neither a pinned
// key fingerprint nor an external anchor was given or matched), 64 usage or unreadable input.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/skenzeriq/activediq/internal/platform/audit/chain"
)

type pinFlags []string

func (p *pinFlags) String() string { return strings.Join(*p, ",") }
func (p *pinFlags) Set(v string) error {
	*p = append(*p, strings.ToLower(strings.TrimSpace(v)))
	return nil
}

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("auditverify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	bundlePath := fs.String("bundle", "", "path of the adq-audit-export/1 file")
	anchorsPath := fs.String("anchors", "", "path of a JSON array of checkpoints received from a SIEM")
	var pins pinFlags
	fs.Var(&pins, "pin", "checkpoint key fingerprint recorded out of band (repeatable). Pin the CURRENT key after every rotation: "+
		"with only a retired key pinned and no newer external anchor, a leaked old seed can fork the log from that key's last legitimate point and nothing in the bundle can tell")
	if err := fs.Parse(args); err != nil {
		return 64
	}
	if *bundlePath == "" {
		fmt.Fprintln(stderr, "auditverify: -bundle is required")
		return 64
	}
	f, err := os.Open(*bundlePath)
	if err != nil {
		fmt.Fprintf(stderr, "auditverify: %v\n", err)
		return 64
	}
	defer f.Close()
	b, err := chain.ReadBundle(f)
	if err != nil {
		fmt.Fprintf(stderr, "auditverify: %v\n", err)
		return 64
	}
	opts := chain.Options{Pinned: pins}
	if *anchorsPath != "" {
		raw, err := os.ReadFile(*anchorsPath)
		if err != nil {
			fmt.Fprintf(stderr, "auditverify: %v\n", err)
			return 64
		}
		if err := json.Unmarshal(raw, &opts.Anchors); err != nil {
			fmt.Fprintf(stderr, "auditverify: anchors: %v\n", err)
			return 64
		}
	}
	r := chain.Verify(b, opts)
	switch r.Status {
	case chain.OK:
		fmt.Fprintf(stdout, "OK: %d events and %d checkpoints verified; %d events after the last checkpoint are not covered by a signature\n", r.Events, r.Checkpoints, r.TailUnsigned)
		return 0
	case chain.Unanchored:
		fmt.Fprintf(stdout, "UNANCHORED: %s\n", r.Detail)
		return 2
	default:
		fmt.Fprintf(stdout, "FAILED at seq %d: %s (%s)\n", r.Seq, r.Reason, r.Detail)
		return 1
	}
}
