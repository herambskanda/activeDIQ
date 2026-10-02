package main

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

// Violation is one failed check. Every message names the file, the check (F1–F5) and the ADR-0001
// rule number, so the fixing agent knows where the change belongs.
type Violation struct {
	Check string
	File  string
	Msg   string
}

var checkRule = map[string]int{"F1": 1, "F2": 2, "F3": 3, "F4": 6, "F5": 5}

func (v Violation) String() string {
	return fmt.Sprintf("%s: %s (ADR-0001 rule %d): %s", v.File, v.Check, checkRule[v.Check], v.Msg)
}

func sortViolations(vs []Violation) {
	sort.SliceStable(vs, func(i, j int) bool {
		if vs[i].Check != vs[j].Check {
			return vs[i].Check < vs[j].Check
		}
		if vs[i].File != vs[j].File {
			return vs[i].File < vs[j].File
		}
		return vs[i].Msg < vs[j].Msg
	})
}

// underAny reports whether p is one of the prefixes or beneath one.
func underAny(p string, prefixes []string) bool {
	for _, pre := range prefixes {
		pre = strings.TrimSuffix(pre, "/")
		if p == pre || strings.HasPrefix(p, pre+"/") {
			return true
		}
	}
	return false
}

func exceptionPaths(es []Exception) []string {
	var out []string
	for _, e := range es {
		out = append(out, e.Path)
	}
	return out
}

var skipDirs = map[string]bool{".git": true, "node_modules": true, "target": true}

// listFiles returns the repository's files (slash paths relative to root): tracked plus untracked
// but not ignored when root is a git checkout, so a new file is seen before it is committed; a
// plain walk otherwise. Exempt zones are dropped.
func listFiles(root string, exempt []string) ([]string, error) {
	var all []string
	if _, err := os.Stat(filepath.Join(root, ".git")); err == nil {
		cmd := exec.Command("git", "-C", root, "ls-files", "-z", "--cached", "--others", "--exclude-standard")
		if b, err := cmd.Output(); err == nil {
			for _, p := range bytes.Split(b, []byte{0}) {
				if len(p) > 0 {
					all = append(all, string(p))
				}
			}
		}
	}
	if all == nil {
		err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if p != root && skipDirs[d.Name()] {
					return filepath.SkipDir
				}
				return nil
			}
			rel, _ := filepath.Rel(root, p)
			all = append(all, filepath.ToSlash(rel))
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	var out []string
	for _, p := range all {
		if underAny(p, exempt) {
			continue
		}
		if fi, err := os.Lstat(filepath.Join(root, filepath.FromSlash(p))); err != nil || !fi.Mode().IsRegular() {
			continue // deleted in the working tree, a symlink or a submodule
		}
		out = append(out, path.Clean(p))
	}
	sort.Strings(out)
	return out, nil
}

// Ctx is what every check shares.
type Ctx struct {
	Root         string
	M            *Manifest
	ManifestPath string
	Files        []string
	SkipBuild    bool
	deps         *depCache
}

func (c *Ctx) abs(rel string) string { return filepath.Join(c.Root, filepath.FromSlash(rel)) }

func (c *Ctx) read(rel string) ([]byte, error) { return os.ReadFile(c.abs(rel)) }

// goModules lists the directories of every go.mod the tree may hold: the root and the declared extras.
func (c *Ctx) goModules() []string {
	mods := []string{"."}
	for _, e := range c.M.Exceptions.ExtraGoModules {
		mods = append(mods, e.Path)
	}
	return mods
}

func (c *Ctx) hasFile(rel string) bool {
	for _, f := range c.Files {
		if f == rel {
			return true
		}
	}
	return false
}
