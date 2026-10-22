package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// baseDoc is the committed bundle of one git ref.
type baseDoc struct {
	ref  string // main, or the release tag
	data []byte // nil: the ref has no bundle yet
}

// The seams the tests replace: where the base bundles come from and how oasdiff runs.
var (
	baseBundles = gitBaseBundles
	apitoolsDir = func(root string) string { return filepath.Join(root, "tools", "apitools") }
)

const bundlePath = "internal/platform/apihost/spec/openapi.gen.json"

var releaseTagRe = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+$`)

// latestReleaseTag is the newest v<major>.<minor>.<patch> tag reachable from HEAD, "" when none.
func latestReleaseTag(root string) string {
	out, err := exec.Command("git", "-C", root, "tag", "--list", "v*", "--merged", "HEAD", "--sort=-v:refname").Output()
	if err != nil {
		return ""
	}
	for _, l := range strings.Fields(string(out)) {
		if releaseTagRe.MatchString(l) {
			return l
		}
	}
	return ""
}

func isGitRepo(root string) bool {
	_, err := os.Stat(filepath.Join(root, ".git"))
	return err == nil
}

// gitBaseBundles returns the bundle at main and at the latest release tag. Outside a git
// repository (a test tree) there is nothing to diff against; inside one, an unreadable main is an
// error, never a silent pass.
func gitBaseBundles(root string) ([]baseDoc, error) {
	if !isGitRepo(root) {
		return nil, nil
	}
	refs := []string{"main"}
	if tag := latestReleaseTag(root); tag != "" {
		refs = append(refs, tag)
	}
	var out []baseDoc
	for _, ref := range refs {
		if err := exec.Command("git", "-C", root, "rev-parse", "--verify", "--quiet", ref+"^{commit}").Run(); err != nil {
			return nil, fmt.Errorf("cannot resolve git ref %q: A10 has nothing to diff against (a shallow clone needs `git fetch origin main --tags`)", ref)
		}
		b, err := exec.Command("git", "-C", root, "show", ref+":"+bundlePath).Output()
		if err != nil {
			b = nil // the bundle did not exist at that ref: every operation is new
		}
		out = append(out, baseDoc{ref, b})
	}
	return out, nil
}

type bundleOp struct {
	id, stability, sunset string
	deprecated            bool
}

func parseBundle(b []byte) (doc map[string]any, ops map[string]bundleOp, version string, err error) {
	if err = json.Unmarshal(b, &doc); err != nil {
		return
	}
	ops = map[string]bundleOp{}
	if info, ok := doc["info"].(map[string]any); ok {
		version, _ = info["version"].(string)
	}
	paths, _ := doc["paths"].(map[string]any)
	for _, item := range paths {
		m, _ := item.(map[string]any)
		for method, v := range m {
			if !httpMethods[method] {
				continue
			}
			o, _ := v.(map[string]any)
			id, _ := o["operationId"].(string)
			bo := bundleOp{id: id}
			bo.stability, _ = o["x-activediq-stability"].(string)
			bo.sunset, _ = o["x-activediq-sunset"].(string)
			bo.deprecated, _ = o["deprecated"].(bool)
			ops[id] = bo
		}
	}
	return
}

// dropOps removes the operations in drop (by operationId) from a bundle and returns the JSON.
func dropOps(doc map[string]any, drop map[string]bool) []byte {
	cp := map[string]any{}
	for k, v := range doc {
		cp[k] = v
	}
	paths := map[string]any{}
	src, _ := doc["paths"].(map[string]any)
	for p, item := range src {
		m, _ := item.(map[string]any)
		keep := map[string]any{}
		n := 0
		for k, v := range m {
			if httpMethods[k] {
				if o, _ := v.(map[string]any); drop[fmt.Sprint(o["operationId"])] {
					continue
				}
				n++
			}
			keep[k] = v
		}
		if n > 0 {
			paths[p] = keep
		}
	}
	cp["paths"] = paths
	b, _ := json.Marshal(cp)
	return b
}

// semverLess compares x.y[.z] versions; a missing or odd component reads as 0.
func semverLess(a, b string) bool {
	pa, pb := semParts(a), semParts(b)
	for i := range pa {
		if pa[i] != pb[i] {
			return pa[i] < pb[i]
		}
	}
	return false
}

func semParts(s string) [3]int {
	var out [3]int
	for i, p := range strings.SplitN(strings.TrimPrefix(s, "v"), ".", 3) {
		out[i], _ = strconv.Atoi(strings.SplitN(p, "-", 2)[0])
	}
	return out
}

var sunsetRe = regexp.MustCompile(`^[0-9]+\.[0-9]+(\.[0-9]+)?$`)

// oasdiffBreaking runs oasdiff (a pinned tool of tools/apitools) and returns its breaking-change texts.
func oasdiffBreaking(root string, base, cur []byte) ([]string, error) {
	dir, err := os.MkdirTemp("", "fitness-api-oasdiff")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	bp, cp := filepath.Join(dir, "base.json"), filepath.Join(dir, "current.json")
	if err := os.WriteFile(bp, base, 0o600); err != nil {
		return nil, err
	}
	if err := os.WriteFile(cp, cur, 0o600); err != nil {
		return nil, err
	}
	cmd := exec.Command("go", "tool", "oasdiff", "breaking", bp, cp, "--format", "json")
	cmd.Dir = apitoolsDir(root)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("oasdiff failed: %v: %s", err, strings.TrimSpace(stderr.String()))
	}
	var changes []struct {
		Text      string `json:"text"`
		Level     int    `json:"level"`
		Operation string `json:"operation"`
		Path      string `json:"path"`
	}
	if s := strings.TrimSpace(stdout.String()); s != "" && s != "null" {
		if err := json.Unmarshal(stdout.Bytes(), &changes); err != nil {
			return nil, fmt.Errorf("oasdiff output is not the expected JSON: %v", err)
		}
	}
	var out []string
	for _, c := range changes {
		if c.Level >= 3 { // ERR; WARN (2) and INFO (1) are not breaking
			out = append(out, strings.TrimSpace(c.Operation+" "+c.Path+": "+c.Text))
		}
	}
	sort.Strings(out)
	return out, nil
}

// checkA10 enforces rule 7: every operation states its stability; deprecated carries a sunset
// release; and against main and the latest release tag a stable operation is not demoted,
// removed before its sunset, or changed incompatibly (oasdiff, run on the stable operations).
func checkA10(t *tree) []Violation {
	var vs []Violation
	add := func(pos, f string, a ...any) { vs = append(vs, Violation{"A10", pos, fmt.Sprintf(f, a...)}) }

	for _, o := range t.ops {
		st := scalar(get(o.node, "x-activediq-stability"))
		if st != "preview" && st != "stable" {
			add(o.where(), "%s has x-activediq-stability %q: every operation is preview or stable (ADR-0004 rule 7, A10)", o.label(), st)
		}
		dep := scalar(get(o.node, "deprecated")) == "true"
		sun := scalar(get(o.node, "x-activediq-sunset"))
		switch {
		case dep && sun == "":
			add(o.where(), "%s is deprecated: true with no x-activediq-sunset, the first release that may remove it (ADR-0004 rule 7, A10)", o.label())
		case sun != "" && !dep:
			add(o.where(), "%s has x-activediq-sunset %s but is not deprecated: true (ADR-0004 rule 7, A10)", o.label(), sun)
		case sun != "" && !sunsetRe.MatchString(sun):
			add(o.where(), "%s has x-activediq-sunset %q, which is not a product release (major.minor[.patch]) (ADR-0004 rule 7, A10)", o.label(), sun)
		}
	}

	bases, err := baseBundles(t.root)
	if err != nil {
		return append(vs, Violation{"A10", bundlePath, err.Error()})
	}
	curBytes, rerr := os.ReadFile(filepath.Join(t.root, filepath.FromSlash(bundlePath)))
	if len(bases) > 0 && rerr != nil {
		return append(vs, Violation{"A10", bundlePath, "the committed bundle is missing, so there is nothing to diff (run make gen-api)"})
	}
	if len(bases) == 0 {
		return vs
	}
	curDoc, curOps, curVersion, err := parseBundle(curBytes)
	if err != nil {
		return append(vs, Violation{"A10", bundlePath, "cannot parse the bundle: " + err.Error()})
	}
	for _, b := range bases {
		if b.data == nil {
			continue
		}
		bdoc, baseOps, _, err := parseBundle(b.data)
		if err != nil {
			add(bundlePath, "cannot parse the bundle at %s: %v", b.ref, err)
			continue
		}
		drop := map[string]bool{}
		ids := make([]string, 0, len(baseOps))
		for id := range baseOps {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for _, id := range ids {
			bo := baseOps[id]
			co, present := curOps[id]
			if bo.stability != "stable" {
				drop[id] = true // a preview operation may change incompatibly
				continue
			}
			switch {
			case !present:
				drop[id] = true
				if !(bo.deprecated && bo.sunset != "" && !semverLess(curVersion, bo.sunset)) {
					add(bundlePath, "stable operation %s (at %s) is gone: a stable operation is removed only after it is deprecated and its sunset release %s has arrived (current %s) (ADR-0004 rule 7, A10)", id, b.ref, orDefault(bo.sunset, "(none declared)"), curVersion)
				}
			case co.stability != "stable":
				drop[id] = true
				add(bundlePath, "operation %s was stable at %s and is %q now: demoting a stable operation is a breaking change (ADR-0004 rule 7, A10)", id, b.ref, co.stability)
			}
		}
		// A new preview or new operation is additive; compare the stable operations only.
		for id, co := range curOps {
			if co.stability != "stable" {
				drop[id] = true
			}
		}
		if bytes.Equal(dropOps(bdoc, drop), dropOps(curDoc, drop)) {
			continue
		}
		breaking, err := oasdiffBreaking(t.root, dropOps(bdoc, drop), dropOps(curDoc, drop))
		if err != nil {
			add(bundlePath, "%v", err)
			continue
		}
		for _, c := range breaking {
			add(bundlePath, "breaking change against %s on a stable operation: %s: ship it as a new operation and deprecate the old one (ADR-0004 rule 7, A10)", b.ref, c)
		}
	}
	return vs
}
