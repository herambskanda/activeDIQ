package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

const (
	libraryDir  = "internal/modules/reports/library"
	lockFile    = libraryDir + "/LOCK"
	lockBaseMsg = "RP7 lock history"
)

var lockLine = regexp.MustCompile(`^([0-9a-f]{64})  (\S.*)$`)

// parseLock reads sha256sum-style lines: 64 hex digits, two spaces, a path relative to the library
// directory. Blank lines and lines starting with # are comments.
func parseLock(r *bufio.Scanner, where string) (map[string]string, []Violation) {
	entries := map[string]string{}
	var vs []Violation
	n := 0
	for r.Scan() {
		n++
		line := strings.TrimRight(r.Text(), "\r")
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "#") {
			continue
		}
		at := fmt.Sprintf("%s:%d", where, n)
		m := lockLine.FindStringSubmatch(line)
		if m == nil {
			vs = append(vs, Violation{"RP7", "lock-format", at, "not `<sha256 hex>  <path>`"})
			continue
		}
		p := m[2]
		if p != path.Clean(p) || path.IsAbs(p) || strings.HasPrefix(p, "../") || p == "LOCK" || !strings.HasSuffix(p, ".json") {
			vs = append(vs, Violation{"RP7", "lock-path", at, "path " + p + " must be a clean relative path of a .json definition under library/"})
			continue
		}
		if _, dup := entries[p]; dup {
			vs = append(vs, Violation{"RP7", "lock-duplicate", at, "path " + p + " is listed twice"})
			continue
		}
		entries[p] = m[1]
	}
	return entries, vs
}

// checkLock is RP7 (FR-03): a shipped definition version is immutable. Every .json file under
// library/ is listed in LOCK with its SHA-256 and still has that hash; a listed file may not vanish;
// and, against the base ref, no entry that was already locked may be edited or removed, so the LOCK
// file cannot be rewritten together with the definition it protects.
func checkLock(root, baseRef string) ([]Violation, []string, []string, error) {
	lib := filepath.Join(root, filepath.FromSlash(libraryDir))
	if !dirExists(lib) {
		return nil, []string{"RP7 library/LOCK (internal/modules/reports/library has not landed: row B5; the rule applies the moment the directory exists)"}, nil, nil
	}
	var vs []Violation
	lockPath := filepath.Join(root, filepath.FromSlash(lockFile))
	fh, err := os.Open(lockPath)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, nil, nil, err
		}
		vs = append(vs, Violation{"RP7", "lock-missing", lockFile, "the library directory exists but has no LOCK file: every shipped definition is listed with its SHA-256"})
	}
	entries := map[string]string{}
	if fh != nil {
		defer fh.Close()
		var pv []Violation
		entries, pv = parseLock(bufio.NewScanner(fh), lockFile)
		vs = append(vs, pv...)
	}

	paths := make([]string, 0, len(entries))
	for p := range entries {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		got, err := fileSHA(filepath.Join(lib, filepath.FromSlash(p)))
		where := libraryDir + "/" + p
		switch {
		case os.IsNotExist(err):
			vs = append(vs, Violation{"RP7", "locked-file-missing", where, "listed in LOCK but missing: a shipped definition version is never deleted or renamed"})
		case err != nil:
			return nil, nil, nil, err
		case got != entries[p]:
			vs = append(vs, Violation{"RP7", "locked-file-changed", where, "changed since it was locked (sha256 " + got + ", LOCK says " + entries[p] + "): ship a new version as a new file instead of editing this one (FR-03)"})
		}
	}

	err = filepath.WalkDir(lib, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel := relSlash(lib, p)
		if d.Type()&fs.ModeSymlink != 0 {
			vs = append(vs, Violation{"RP7", "symlink", libraryDir + "/" + rel, "a symbolic link in the library cannot be locked by content"})
			return nil
		}
		if d.IsDir() || !strings.HasSuffix(rel, ".json") {
			return nil
		}
		if _, ok := entries[rel]; !ok {
			vs = append(vs, Violation{"RP7", "unlisted-file", libraryDir + "/" + rel, "not listed in LOCK: add its SHA-256 in the change that ships it"})
		}
		return nil
	})
	if err != nil {
		return nil, nil, nil, err
	}

	var notes []string
	if baseRef != "" {
		bv, err := checkLockHistory(root, baseRef, entries)
		if err != nil {
			return nil, nil, nil, err
		}
		vs = append(vs, bv...)
		notes = append(notes, lockBaseMsg+": compared with "+baseRef)
	} else {
		notes = append(notes, lockBaseMsg+": not compared (no -lock-base): a LOCK edited together with its definition passes")
	}
	return vs, nil, notes, nil
}

// checkLockHistory requires every entry of the base ref's LOCK to be present and equal.
func checkLockHistory(root, baseRef string, now map[string]string) ([]Violation, error) {
	git := func(args ...string) ([]byte, error) {
		cmd := exec.Command("git", append([]string{"-C", root}, args...)...)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		out, err := cmd.Output()
		if err != nil {
			return nil, fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
		}
		return out, nil
	}
	if _, err := git("rev-parse", "--verify", "-q", baseRef+"^{commit}"); err != nil {
		return nil, fmt.Errorf("-lock-base %q does not resolve to a commit, so the append-only rule cannot be checked: %w", baseRef, err)
	}
	if _, err := git("cat-file", "-e", baseRef+":"+lockFile); err != nil {
		return nil, nil // LOCK is new in this change: nothing to protect yet
	}
	raw, err := git("show", baseRef+":"+lockFile)
	if err != nil {
		return nil, err
	}
	before, _ := parseLock(bufio.NewScanner(bytes.NewReader(raw)), baseRef+":"+lockFile)
	paths := make([]string, 0, len(before))
	for p := range before {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	var vs []Violation
	for _, p := range paths {
		switch got, ok := now[p]; {
		case !ok:
			vs = append(vs, Violation{"RP7", "lock-entry-removed", lockFile, "the entry for " + p + " exists on " + baseRef + " and is gone: locked versions are never unlocked"})
		case got != before[p]:
			vs = append(vs, Violation{"RP7", "lock-entry-rewritten", lockFile, "the hash of " + p + " differs from " + baseRef + ": a shipped version is immutable, so ship a new version"})
		}
	}
	return vs, nil
}

func fileSHA(p string) (string, error) {
	b, err := os.ReadFile(p)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}
