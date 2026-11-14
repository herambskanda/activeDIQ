package server

import (
	"strings"
	"testing"
)

func set(gs ...string) map[string]struct{} {
	m := map[string]struct{}{}
	for _, g := range gs {
		m[g] = struct{}{}
	}
	return m
}

func TestGUIDSetDiffNamesOnlyTheGUIDsInOneSet(t *testing.T) {
	msg, ok := guidSetDiff(set("a", "b", "c"), set("a", "b", "c"))
	if !ok || msg != "" {
		t.Fatalf("equal sets: %q %v", msg, ok)
	}
	msg, ok = guidSetDiff(set("00000000-0000-0000-0000-00000000000b", "a"), set("a", "00000000-0000-0000-0000-00000000000c"))
	if ok {
		t.Fatal("different sets reported equal")
	}
	want := "only in the LDAP ground truth (1): [00000000-0000-0000-0000-00000000000b]; only in the report (1): [00000000-0000-0000-0000-00000000000c]"
	if msg != want {
		t.Fatalf("got %q", msg)
	}
	if strings.Contains(msg, "=") || strings.Contains(strings.ToLower(msg), "dc=") {
		t.Fatalf("the message carries a DN or attribute value: %q", msg)
	}
}
