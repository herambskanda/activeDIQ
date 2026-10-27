// Command sbom writes the per-release CycloneDX 1.5 SBOM (T-0261, threat model §16 "SBOM and build
// provenance per release"). Standard library only, so the tool adds no dependency to the licence
// register. Components: every Go module that the product binaries under ./cmd import (not the whole
// module graph, so test and tool modules stay out), and every non-dev package in web/package-lock.json.
// The output is deterministic: same commit and same SOURCE_DATE_EPOCH give the same bytes.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"
)

type component struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Version string `json:"version"`
	PURL    string `json:"purl"`
	BOMRef  string `json:"bom-ref"`
	Hashes  []hash `json:"hashes,omitempty"`
}

type hash struct {
	Alg     string `json:"alg"`
	Content string `json:"content"`
}

// goMod is one shipped Go module.
type goMod struct{ Path, Version string }

// Build assembles the SBOM document. Pure: no clock, no network, no exec.
func Build(product, version string, ts time.Time, gomods []goMod, lock []byte) ([]byte, error) {
	var comps []component
	for _, m := range gomods {
		if m.Version == "" {
			continue // the main module itself, or the standard library
		}
		p := "pkg:golang/" + m.Path + "@" + url.PathEscape(m.Version)
		comps = append(comps, component{Type: "library", Name: m.Path, Version: m.Version, PURL: p, BOMRef: p})
	}
	if len(lock) > 0 {
		var l struct {
			Packages map[string]struct {
				Version   string `json:"version"`
				Integrity string `json:"integrity"`
				Dev       bool   `json:"dev"`
				Optional  bool   `json:"optional"`
			} `json:"packages"`
		}
		if err := json.Unmarshal(lock, &l); err != nil {
			return nil, fmt.Errorf("package-lock.json: %w", err)
		}
		for key, p := range l.Packages {
			i := strings.LastIndex(key, "node_modules/")
			if i < 0 || p.Dev || p.Version == "" {
				continue
			}
			name := key[i+len("node_modules/"):]
			purl := "pkg:npm/" + strings.Replace(name, "@", "%40", 1) + "@" + p.Version
			c := component{Type: "library", Name: name, Version: p.Version, PURL: purl, BOMRef: purl}
			if alg, b64, ok := strings.Cut(p.Integrity, "-"); ok && strings.HasPrefix(alg, "sha") {
				if raw, err := base64.StdEncoding.DecodeString(b64); err == nil {
					c.Hashes = []hash{{Alg: map[string]string{"sha512": "SHA-512", "sha256": "SHA-256", "sha384": "SHA-384", "sha1": "SHA-1"}[alg], Content: hex.EncodeToString(raw)}}
					if c.Hashes[0].Alg == "" {
						c.Hashes = nil
					}
				}
			}
			comps = append(comps, c)
		}
	}
	if len(comps) == 0 {
		return nil, fmt.Errorf("no components found; refusing to publish an empty SBOM")
	}
	sort.Slice(comps, func(i, j int) bool { return comps[i].BOMRef < comps[j].BOMRef })
	for i := 1; i < len(comps); i++ {
		if comps[i].BOMRef == comps[i-1].BOMRef {
			comps = append(comps[:i], comps[i+1:]...)
			i--
		}
	}
	h := sha256.New()
	fmt.Fprintf(h, "%s@%s\n", product, version)
	for _, c := range comps {
		fmt.Fprintln(h, c.BOMRef)
	}
	s := h.Sum(nil)
	serial := fmt.Sprintf("urn:uuid:%x-%x-%x-%x-%x", s[0:4], s[4:6], s[6:8], s[8:10], s[10:16])
	doc := map[string]any{
		"bomFormat":    "CycloneDX",
		"specVersion":  "1.5",
		"serialNumber": serial,
		"version":      1,
		"metadata": map[string]any{
			"timestamp": ts.UTC().Format(time.RFC3339),
			"component": map[string]any{"type": "application", "name": product, "version": version, "bom-ref": "pkg:generic/" + product + "@" + url.PathEscape(version)},
			"tools":     map[string]any{"components": []map[string]any{{"type": "application", "name": "tools/release/sbom", "version": "T-0261"}}},
		},
		"components": comps,
	}
	return json.MarshalIndent(doc, "", "  ")
}

func shippedGoModules(dir string) ([]goMod, error) {
	cmd := exec.Command("go", "list", "-deps", "-f", "{{with .Module}}{{.Path}} {{.Version}}{{end}}", "./cmd/...")
	cmd.Dir = dir
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("go list: %v: %s", err, stderr.String())
	}
	seen := map[goMod]bool{}
	var mods []goMod
	for _, l := range strings.Split(string(out), "\n") {
		f := strings.Fields(l)
		if len(f) == 2 && !seen[goMod{f[0], f[1]}] {
			seen[goMod{f[0], f[1]}] = true
			mods = append(mods, goMod{f[0], f[1]})
		}
	}
	return mods, nil
}

func main() {
	root := flag.String("root", ".", "repository root")
	product := flag.String("product", "activediq", "product name")
	version := flag.String("version", "", "release version, e.g. v1.0.0 (required)")
	out := flag.String("o", "", "output file (required)")
	flag.Parse()
	if *version == "" || *out == "" {
		fmt.Fprintln(os.Stderr, "sbom: -version and -o are required")
		os.Exit(2)
	}
	epoch, err := strconv.ParseInt(os.Getenv("SOURCE_DATE_EPOCH"), 10, 64)
	if err != nil {
		fmt.Fprintln(os.Stderr, "sbom: SOURCE_DATE_EPOCH must be set (the commit time) so the SBOM is reproducible")
		os.Exit(2)
	}
	mods, err := shippedGoModules(*root)
	if err != nil {
		fmt.Fprintln(os.Stderr, "sbom:", err)
		os.Exit(1)
	}
	lock, err := os.ReadFile(*root + "/web/package-lock.json")
	if err != nil && !os.IsNotExist(err) {
		fmt.Fprintln(os.Stderr, "sbom:", err)
		os.Exit(1)
	}
	doc, err := Build(*product, *version, time.Unix(epoch, 0), mods, lock)
	if err != nil {
		fmt.Fprintln(os.Stderr, "sbom:", err)
		os.Exit(1)
	}
	if err := os.WriteFile(*out, append(doc, '\n'), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "sbom:", err)
		os.Exit(1)
	}
	fmt.Printf("sbom: wrote %s\n", *out)
}
