package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TM-F-FLEET, last failing condition: "the fleet contract gains a secret-bearing message type outside
// operation payloads" (threat-model §15; TB6-T6). The proof mutates a copy of the real
// proto/activediq/fleet/v1/fleet.proto, so it tests the contract we ship and not a fixture, and
// requires the fitness check to fail for each way a secret could be added.

const realProto = "../../../proto"

func copyTree(t *testing.T, src, dst string) {
	t.Helper()
	err := filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		if d.IsDir() {
			return os.MkdirAll(filepath.Join(dst, rel), 0o700)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(dst, rel), b, 0o600)
	})
	if err != nil {
		t.Fatal(err)
	}
}

func lintMutatedFleet(t *testing.T, mutate func(string) string) []Violation {
	t.Helper()
	dir := t.TempDir()
	copyTree(t, realProto, dir)
	p := filepath.Join(dir, "activediq", "fleet", "v1", "fleet.proto")
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)
	out := mutate(src)
	if mutate != nil && out == src {
		t.Fatal("mutation did not change fleet.proto (the proof has gone stale)")
	}
	if err := os.WriteFile(p, []byte(out), 0o600); err != nil {
		t.Fatal(err)
	}
	files, err := Compile(dir)
	if err != nil {
		t.Fatalf("mutated contract must compile: %v", err)
	}
	return append(Lint(files), RequireFleet(files)...)
}

func TestTMFFleetRealContractIsClean(t *testing.T) {
	if vs := lintMutatedFleet(t, func(s string) string { return s + "\n" }); len(vs) != 0 {
		t.Fatalf("the shipped fleet contract violates its own rules: %v", vs)
	}
}

func TestTMFFleetSecretBearingMessageTypeFails(t *testing.T) {
	cases := []struct {
		name, rule string
		mutate     func(string) string
	}{
		{"new secret-named message type", "F9", func(s string) string {
			return s + "\nmessage PasswordPush { bytes blob = 1; }\n"
		}},
		{"new credential message carried in a frame", "F9", func(s string) string {
			s = strings.Replace(s, "message TunnelFrame {", "message CredentialEnvelope { bytes blob = 1; }\nmessage TunnelFrame {\n  CredentialEnvelope env = 20;", 1)
			return s
		}},
		{"password field on an existing message", "F3", func(s string) string {
			return strings.Replace(s, "message CallData {", "message CallData {\n  string password = 9;", 1)
		}},
		{"private key on the Enroll response", "F3", func(s string) string {
			return strings.Replace(s, "message EnrollResponse {", "message EnrollResponse {\n  bytes private_key_der = 9;", 1)
		}},
		{"second token field", "F3", func(s string) string {
			return strings.Replace(s, "message EnrollRequest {", "message EnrollRequest {\n  string session_token = 9;", 1)
		}},
		{"new RPC", "F1", func(s string) string {
			return strings.Replace(s, "service Fleet {", "message PushRequest {}\nservice Fleet {\n  rpc Push(PushRequest) returns (EnrollResponse);", 1)
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			vs := lintMutatedFleet(t, c.mutate)
			if len(vs) == 0 {
				t.Fatal("a secret-bearing addition to the fleet contract passed the check")
			}
			if c.rule != "F1" && !strings.Contains(rules(vs), c.rule) {
				t.Fatalf("want a %s violation, got %q", c.rule, rules(vs))
			}
		})
	}
}
