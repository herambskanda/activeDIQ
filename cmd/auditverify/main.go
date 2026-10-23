// Command auditverify (adq-audit-verify) checks an activeDIQ audit export offline (ADR-0005 rule 11).
// It needs no installation and no network, and links only the standard library plus the format packages
// platform/audit/canon and platform/audit/chain, which are themselves standard-library-only.
//
//	auditverify -bundle export.json [-pin <fingerprint>[@created-retired]]... [-anchors anchors.json]
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

type pinFlags struct {
	ids     []string
	windows map[string]chain.PinWindow
}

func (p *pinFlags) String() string { return strings.Join(p.ids, ",") }
func (p *pinFlags) Set(v string) error {
	fp, w, err := chain.ParsePin(v)
	if err != nil {
		return err
	}
	p.ids = append(p.ids, fp)
	if w != nil {
		if p.windows == nil {
			p.windows = map[string]chain.PinWindow{}
		}
		p.windows[fp] = *w
	}
	return nil
}

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("auditverify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	bundlePath := fs.String("bundle", "", "path of the adq-audit-export/1 file")
	anchorsPath := fs.String("anchors", "", "path of a JSON array of checkpoints received from a SIEM")
	var pins pinFlags
	fs.Var(&pins, "pin", "checkpoint key fingerprint recorded out of band, optionally FINGERPRINT@created-retired (key window as sequence numbers; "+
		"@12- for a current key). After every rotation pin the CURRENT key and REMOVE the pins of retired keys: with a retired key still pinned, "+
		"a leaked old seed can sign a forked or truncated export that the bundle's own manifest describes as current. "+
		"An old pin may be kept only with its window (windows must not overlap, at most one open); several pins always need every pin windowed (the export cannot say which key is newest), "+
		"and with several pins the current key must have signed a checkpoint in the export")
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
	opts := chain.Options{Pinned: pins.ids, PinWindows: pins.windows}
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
