package main

import (
	"strings"
	"testing"
	"time"
)

const base = "Contact: https://example.test/report\nExpires: %s\nPolicy: https://example.test/SECURITY.md\n"

var now = time.Date(2027, 5, 1, 13, 0, 0, 0, time.UTC)

func file(exp string) []byte { return []byte(strings.Replace(base, "%s", exp, 1)) }

func TestRenewsInsideWindow(t *testing.T) {
	out, changed, err := Renew(file("2027-07-23T00:00:00Z"), now, 90*24*time.Hour, 330*24*time.Hour)
	if err != nil || !changed {
		t.Fatalf("changed=%v err=%v", changed, err)
	}
	if !strings.Contains(string(out), "Expires: 2028-03-26T00:00:00Z\n") {
		t.Fatalf("unexpected output:\n%s", out)
	}
	if !strings.Contains(string(out), "Contact: https://example.test/report\n") || !strings.HasSuffix(string(out), "SECURITY.md\n") {
		t.Fatalf("other fields disturbed:\n%s", out)
	}
}

func TestRenewsExpiredAndUnparseable(t *testing.T) {
	for _, e := range []string{"2020-01-01T00:00:00Z", "next-year"} {
		if _, changed, err := Renew(file(e), now, 90*24*time.Hour, 330*24*time.Hour); err != nil || !changed {
			t.Fatalf("%s: changed=%v err=%v", e, changed, err)
		}
	}
}

func TestCurrentFileIsUntouched(t *testing.T) {
	in := file("2028-01-01T00:00:00Z")
	out, changed, err := Renew(in, now, 90*24*time.Hour, 330*24*time.Hour)
	if err != nil || changed || string(out) != string(in) {
		t.Fatalf("changed=%v err=%v", changed, err)
	}
}

func TestRefusesAmbiguousFile(t *testing.T) {
	for _, in := range []string{"Contact: x\n", "Expires: 2028-01-01T00:00:00Z\nExpires: 2029-01-01T00:00:00Z\n"} {
		if _, _, err := Renew([]byte(in), now, 90*24*time.Hour, 330*24*time.Hour); err == nil {
			t.Fatalf("accepted %q", in)
		}
	}
}
