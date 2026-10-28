package signer_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// P8 (ADR-0007 fitness): the signer package is the only code that can reach the sealed policy key. The
// accessor is unexported, so Go already forbids another package calling it; this scan closes the other
// routes: SQL that names the key table or its sealed column, and code that builds a private key from a
// seed or opens a policy-key blob, anywhere outside the signer package.
func TestP8OnlyTheSignerReachesThePolicyPrivateKey(t *testing.T) {
	root := "../../../.."
	needles := []string{"agent_policy_key"}
	allowedPrefix := filepath.ToSlash(filepath.Join("internal", "platform", "agentpolicy", "signer")) + "/"
	var hits []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "web", "garage", "knowledge", "migrations", "factory":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		rel = filepath.ToSlash(rel)
		if strings.HasPrefix(rel, allowedPrefix) {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		s := string(b)
		for _, n := range needles {
			if strings.Contains(s, n) {
				hits = append(hits, rel+": names "+n)
			}
		}
		// A policy private key comes only from the signer; nothing else may rebuild one from a seed.
		if strings.Contains(s, "agentpolicy") && strings.Contains(s, "ed25519.NewKeyFromSeed") {
			hits = append(hits, rel+": builds an Ed25519 private key beside the policy code")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 0 {
		t.Fatalf("code outside the signer package reaches the policy key:\n%s", strings.Join(hits, "\n"))
	}
}
