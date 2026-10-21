package main

import (
	"strings"
	"testing"
	"time"
)

func day(s string) time.Time {
	d, err := time.Parse(time.DateOnly, s)
	if err != nil {
		panic(err)
	}
	return d
}

const stream = `{"config":{"scanner_name":"govulncheck"}}
{"osv":{"id":"GO-2026-0001","summary":"called flaw"}}
{"osv":{"id":"GO-2026-0002","summary":"imported only"}}
{"finding":{"osv":"GO-2026-0002","trace":[{"module":"example.test/b","version":"v1.0.0","package":"example.test/b"}]}}
{"finding":{"osv":"GO-2026-0003","trace":[{"module":"example.test/c","version":"v1.0.0"}]}}
{"finding":{"osv":"GO-2026-0001","fixed_version":"v1.2.0","trace":[{"module":"example.test/a","version":"v1.0.0","package":"example.test/a","function":"Do"},{"module":"example.test/app","function":"main"}]}}
{"finding":{"osv":"GO-2026-0001","fixed_version":"v1.2.0","trace":[{"module":"example.test/a","version":"v1.0.0","package":"example.test/a","function":"Other"}]}}
`

func TestParseStreamKeepsOnlyCalledOncePerModule(t *testing.T) {
	got, err := ParseStream(strings.NewReader(stream))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].OSV != "GO-2026-0001" || got[0].Function != "example.test/a.Do" ||
		got[0].Fixed != "v1.2.0" || got[0].Summary != "called flaw" {
		t.Fatalf("got %+v", got)
	}
}

func TestParseStreamRejectsGarbage(t *testing.T) {
	if _, err := ParseStream(strings.NewReader(`{"finding":`)); err == nil {
		t.Fatal("truncated output must be an error, not an empty result")
	}
}

func allow(t *testing.T, entries string) AllowFile {
	t.Helper()
	f, err := ParseAllow([]byte(`{"entries":[` + entries + `]}`))
	if err != nil {
		t.Fatal(err)
	}
	return f
}

const entry = `{"osv":"GO-2026-0001","reason":"waiting for upstream","ticket":"T-0100","expires":"2026-12-01"}`

func findings(t *testing.T) []Finding {
	t.Helper()
	f, err := ParseStream(strings.NewReader(stream))
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestVerdict(t *testing.T) {
	f := findings(t)
	cases := []struct {
		name  string
		allow AllowFile
		today string
		want  string // substring of the single expected problem; "" for none
	}{
		{"called and not allowed fails", allow(t, ""), "2026-11-01", "GO-2026-0001: called through example.test/a.Do in example.test/a v1.0.0 (fixed in v1.2.0)"},
		{"allowed and unexpired passes", allow(t, entry), "2026-11-01", ""},
		{"expiry day itself still passes", allow(t, entry), "2026-12-01", ""},
		{"expired entry fails", allow(t, entry), "2026-12-02", "allow entry expired on 2026-12-01 (ticket T-0100)"},
		{"stale entry fails", allow(t, entry+`,{"osv":"GO-2026-0009","reason":"x","ticket":"T-0101","expires":"2026-12-01"}`), "2026-11-01", "GO-2026-0009: allow entry (ticket T-0101) matches no finding"},
	}
	for _, c := range cases {
		got := Verdict(f, c.allow, day(c.today))
		switch {
		case c.want == "" && len(got) != 0:
			t.Errorf("%s: unexpected %v", c.name, got)
		case c.want != "" && (len(got) != 1 || !strings.Contains(got[0], c.want)):
			t.Errorf("%s: got %v, want %q", c.name, got, c.want)
		}
	}
}

func TestVerdictCleanTree(t *testing.T) {
	if got := Verdict(nil, allow(t, ""), day("2026-11-01")); len(got) != 0 {
		t.Fatal(got)
	}
	if got := Verdict(nil, allow(t, entry), day("2026-11-01")); len(got) != 1 {
		t.Fatal("an entry with no finding must fail", got)
	}
}

func TestParseAllowRejects(t *testing.T) {
	good := `"reason":"r","ticket":"T-0100","expires":"2026-12-01"`
	bad := map[string]string{
		"unknown field":   `{"entries":[],"x":1}`,
		"bad id":          `{"entries":[{"osv":"nope",` + good + `}]}`,
		"no reason":       `{"entries":[{"osv":"GO-2026-0001","reason":" ","ticket":"T-0100","expires":"2026-12-01"}]}`,
		"no ticket":       `{"entries":[{"osv":"GO-2026-0001","reason":"r","ticket":"","expires":"2026-12-01"}]}`,
		"no expiry":       `{"entries":[{"osv":"GO-2026-0001","reason":"r","ticket":"T-0100"}]}`,
		"bad date":        `{"entries":[{"osv":"GO-2026-0001","reason":"r","ticket":"T-0100","expires":"01/12/2026"}]}`,
		"duplicate":       `{"entries":[{"osv":"GO-2026-0001",` + good + `},{"osv":"GO-2026-0001",` + good + `}]}`,
		"not json":        `entries`,
		"misspelled list": `{"entrys":[]}`,
	}
	for name, in := range bad {
		if _, err := ParseAllow([]byte(in)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := ParseAllow([]byte(`{"entries":[]}`)); err != nil {
		t.Errorf("empty list rejected: %v", err)
	}
}
