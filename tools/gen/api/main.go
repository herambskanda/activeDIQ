// Command gen-api generates everything derived from the API contract (ADR-0004 rule 4): the bundle,
// the Go types, decoders, validators, handlers and route rows of every tag, and the TypeScript
// types. `gen-api` writes; `gen-api -check` regenerates in memory and fails on any difference.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// DefaultConfig is the real tree's configuration, rooted at the repository.
func DefaultConfig(repo string) *Config {
	const mod = "github.com/skenzeriq/activediq"
	return &Config{
		Root:           filepath.Join(repo, "api", "openapi"),
		Out:            repo,
		Module:         mod,
		ApitypesImport: mod + "/internal/platform/apihost/apitypes",
		ApihostImport:  mod + "/internal/platform/apihost",
		SharedDir:      "internal/platform/apihost/apitypes",
		BundlePath:     "internal/platform/apihost/spec/openapi.gen.json",
		TSOut:          "web/src/api/schema.gen.d.ts",
		EmitProblems:   true,
		Bindings: []Binding{
			{Schema: "SecretInput", Import: mod + "/internal/platform/secret", Type: "Secret", Secret: true},
			{Schema: "Int64String", Import: mod + "/internal/platform/apihost/apitypes", Type: "Int64String"},
			// The primitives below are not built yet; until their owners flip these, the schemas are
			// emitted as ordinary generated types (a binding is a security-sensitive change).
			{Schema: "GUIDRef", Import: mod + "/internal/directory/dn", Type: "GUIDRef", Pending: true, Owner: "P2 (internal/directory/dn)"},
			{Schema: "ObjectView", Import: mod + "/internal/directory/dn", Type: "ObjectView", Pending: true, Owner: "P2 (internal/directory/dn)"},
			{Schema: "FilterAst", Import: mod + "/internal/directory/ldapfilter", Type: "Filter", Pending: true, Owner: "P1 (internal/directory/ldapfilter)"},
			{Schema: "ReportAst", Import: mod + "/internal/platform/store/reportsql", Type: "Report", Pending: true, Owner: "P5 (internal/platform/store/reportsql)"},
		},
	}
}

// Result is everything a run produces, keyed by slash path relative to Config.Out.
type Result struct {
	Files  map[string][]byte
	Bundle *Bundle
}

// Generate runs the whole Go side in memory: bundle, dialect check, every generated file.
func Generate(cfg *Config) (*Result, error) {
	bundle, err := BuildBundle(cfg.Root)
	if err != nil {
		return nil, err
	}
	// The bundle is the one input of every generator: read it back from its own bytes.
	m, err := ParseModel(bundle.Doc)
	if err != nil {
		return nil, err
	}
	res := &Result{Files: map[string][]byte{cfg.BundlePath: bundle.JSON}, Bundle: bundle}
	el := &errList{}
	units := []*unit{newUnit(cfg, m, "", el)}
	for _, tag := range m.Tags {
		units = append(units, newUnit(cfg, m, tag, el))
	}
	for _, u := range units {
		files, err := u.emit()
		if err != nil {
			return nil, err
		}
		for k, v := range files {
			res.Files[k] = v
		}
	}
	if err := el.err(); err != nil {
		return nil, err
	}
	return res, nil
}

func newUnit(cfg *Config, m *Model, tag string, el *errList) *unit {
	u := &unit{cfg: cfg, m: m, tag: tag, names: map[string]string{}, pats: map[string]string{}, errs: el}
	if tag == "" {
		u.dir, u.imp, u.pkg = cfg.SharedDir, cfg.SharedImport(), filepath.Base(cfg.SharedDir)
	} else {
		u.dir, u.imp, u.pkg = TagDir(tag), cfg.TagImport(tag), "api"
	}
	return u
}

func (u *unit) emit() (map[string][]byte, error) {
	out := map[string][]byte{}
	models, err := u.emitModelsWithPatterns()
	if err != nil {
		return nil, err
	}
	if models != nil {
		out[u.dir+"/models.gen.go"] = models
	}
	if u.tag == "" {
		if u.cfg.EmitProblems && len(u.m.Problems) > 0 {
			b, err := u.emitProblems()
			if err != nil {
				return nil, err
			}
			out[u.dir+"/problems.gen.go"] = b
		}
		return out, nil
	}
	h, err := u.emitHandlers()
	if err != nil {
		return nil, err
	}
	out[u.dir+"/handlers.gen.go"] = h
	return out, nil
}

// emitModelsWithPatterns emits models.gen.go and appends the regexp variables its validators use.
func (u *unit) emitModelsWithPatterns() ([]byte, error) {
	f := u.newFile()
	for _, name := range sortedKeys(u.m.Schemas) {
		s := u.m.Schemas[name]
		if s.Tag != u.tag || u.binding(name) != nil {
			continue
		}
		u.claim(name, "schema "+name)
		u.emitSchema(f, s)
	}
	if f.buf.Len() == 0 {
		return nil, nil
	}
	u.emitPatterns(f)
	return f.bytes()
}

func (u *unit) emitProblems() ([]byte, error) {
	f := u.newFile()
	f.p("// The closed problem catalogue (ADR-0004 rule 8): one constructor per slug. A handler returns a\n// constructor's result, or a plain error, which renders as /problems/internal.\n\nconst (\n")
	for _, p := range u.m.Problems {
		u.claim("ProblemType"+goIdent(p.Slug), "problem "+p.Slug)
		f.p("\tProblemType%s = %q\n", goIdent(p.Slug), "/problems/"+p.Slug)
	}
	f.p(")\n\n")
	for _, p := range u.m.Problems {
		u.claim(goIdent(p.Slug), "problem constructor "+p.Slug)
		f.p("// %s builds a %d /problems/%s problem.\nfunc %s(detail string) *Problem {\n\treturn newProblem(ProblemType%s, %q, %d, detail)\n}\n\n", goIdent(p.Slug), p.Status, p.Slug, goIdent(p.Slug), goIdent(p.Slug), p.Title, p.Status)
	}
	return f.bytes()
}

// managedDirs lists the directories the generator owns, for stale-file detection.
func managedDirs(cfg *Config) []string {
	dirs := []string{cfg.SharedDir}
	for _, pat := range []string{"internal/modules/*/api", "internal/platform/*/api"} {
		ms, _ := filepath.Glob(filepath.Join(cfg.Out, filepath.FromSlash(pat)))
		for _, m := range ms {
			rel, _ := filepath.Rel(cfg.Out, m)
			dirs = append(dirs, filepath.ToSlash(rel))
		}
	}
	return dirs
}

// Diff compares a result with the tree and reports every missing, stale and orphaned generated file.
func Diff(cfg *Config, res *Result) []string {
	var out []string
	for _, rel := range sortedKeys(res.Files) {
		have, err := os.ReadFile(filepath.Join(cfg.Out, filepath.FromSlash(rel)))
		switch {
		case err != nil:
			out = append(out, rel+": missing (run make gen-api)")
		case !bytes.Equal(have, res.Files[rel]):
			out = append(out, rel+": stale (run make gen-api)")
		}
	}
	for _, d := range managedDirs(cfg) {
		ents, _ := os.ReadDir(filepath.Join(cfg.Out, filepath.FromSlash(d)))
		for _, e := range ents {
			rel := d + "/" + e.Name()
			if strings.HasSuffix(e.Name(), ".gen.go") {
				if _, ok := res.Files[rel]; !ok {
					out = append(out, rel+": generated file with no source (run make gen-api)")
				}
			}
		}
	}
	return out
}

// Write writes the result, removing orphaned generated files.
func Write(cfg *Config, res *Result) error {
	for _, rel := range sortedKeys(res.Files) {
		if err := writeFile(filepath.Join(cfg.Out, filepath.FromSlash(rel)), res.Files[rel]); err != nil {
			return err
		}
	}
	for _, d := range managedDirs(cfg) {
		ents, _ := os.ReadDir(filepath.Join(cfg.Out, filepath.FromSlash(d)))
		for _, e := range ents {
			rel := d + "/" + e.Name()
			if _, ok := res.Files[rel]; !ok && strings.HasSuffix(e.Name(), ".gen.go") {
				if err := os.Remove(filepath.Join(cfg.Out, filepath.FromSlash(rel))); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func main() {
	repo := flag.String("repo", ".", "repository root")
	check := flag.Bool("check", false, "regenerate in memory and fail when any generated file differs")
	noTS := flag.Bool("skip-ts", false, "do not run openapi-typescript")
	flag.Parse()
	cfg := DefaultConfig(mustAbs(*repo))
	if *noTS {
		cfg.TSOut = ""
	}
	if err := run(cfg, *check); err != nil {
		fmt.Fprintln(os.Stderr, "gen-api:", err)
		os.Exit(1)
	}
}

func mustAbs(p string) string {
	a, err := filepath.Abs(p)
	if err != nil {
		panic(err)
	}
	return a
}

func run(cfg *Config, check bool) error {
	res, err := Generate(cfg)
	if err != nil {
		return err
	}
	if cfg.TSOut != "" {
		ts, err := GenerateTS(cfg, res.Bundle.JSON)
		if err != nil {
			return err
		}
		res.Files[cfg.TSOut] = ts
	}
	if check {
		diffs := Diff(cfg, res)
		if len(diffs) > 0 {
			sort.Strings(diffs)
			return fmt.Errorf("generated files are out of date:\n  %s", strings.Join(diffs, "\n  "))
		}
		return nil
	}
	return Write(cfg, res)
}
