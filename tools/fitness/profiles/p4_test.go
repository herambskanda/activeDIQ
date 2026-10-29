package main

import (
	"os"
	"strings"
	"testing"
)

// P4 telemetry half (T-0135, TM-TB17-T8, TM-Q10): one failing fixture per rule, one passing twin.

const p4Hdr = "package svc\n\nimport (\n\t\"log/slog\"\n\n\t\"example.test/diq/internal/platform/tenant\"\n)\n\nvar _ = slog.Info\nvar _ tenant.ID\n\n"

func p4Repo(t *testing.T, body string) string {
	return p4files(t, map[string]string{"internal/modules/svc/svc.go": p4Hdr + body})
}

// p4files is repo with the manifest's real exemptions removed, so each fixture starts with none.
func p4files(t *testing.T, extra map[string]string) string {
	if _, ok := extra["tools/fitness/profiles/manifest.json"]; !ok {
		extra["tools/fitness/profiles/manifest.json"] = realManifest(t)
	}
	return repo(t, extra)
}

func TestP4LogWithoutTenantFails(t *testing.T) {
	for name, body := range map[string]string{
		"package slog":  "func Work(t tenant.ID) { slog.Info(\"synced\", \"n\", 3) }\n",
		"logger field":  "type S struct{ log *slog.Logger }\n\nfunc (s *S) Work(t tenant.ID) { s.log.Warn(\"synced\") }\n",
		"tenant struct": "type Job struct{ Tenant tenant.ID }\n\nfunc Run(j Job) { slog.Error(\"failed\") }\n",
		"literal other": "func Work(t tenant.ID) { slog.Info(\"synced\", \"tenant\", t.String()) }\n",
		"after With":    "func Work(t tenant.ID) { slog.Default().With(\"job\", 1).Info(\"synced\") }\n",
	} {
		t.Run(name, func(t *testing.T) {
			expect(t, run(t, p4Repo(t, body), "P4"), "P4", "internal/modules/svc/svc.go:", "does not carry \"tenant_id\"")
		})
	}
}

func TestP4LogWithTenantPasses(t *testing.T) {
	for name, body := range map[string]string{
		"attribute":  "func Work(t tenant.ID) { slog.Info(\"synced\", \"tenant_id\", t.String()) }\n",
		"slog attr":  "func Work(t tenant.ID) { slog.Info(\"synced\", slog.String(\"tenant_id\", t.String())) }\n",
		"with":       "func Work(t tenant.ID) { slog.With(\"tenant_id\", t.String()).Info(\"synced\") }\n",
		"bound var":  "func Work(t tenant.ID) {\n\tl := slog.Default().With(\"tenant_id\", t.String())\n\tl.Info(\"a\")\n\tl.Warn(\"b\")\n}\n",
		"no tenant":  "func Platform() { slog.Info(\"listening\") }\n",
		"other call": "func Work(t tenant.ID) { println(\"x\") }\n",
	} {
		t.Run(name, func(t *testing.T) {
			if vs := run(t, p4Repo(t, body), "P4"); len(vs) != 0 {
				t.Fatalf("should pass:\n%s", dump(vs))
			}
		})
	}
}

const promHdr = "package svc\n\nimport \"github.com/prometheus/client_golang/prometheus\"\n\n"

func TestP4MetricWithoutTenantFails(t *testing.T) {
	cases := map[string][2]string{
		"labels without":  {"var m = prometheus.NewCounterVec(prometheus.CounterOpts{Name: \"x\"}, []string{\"result\"})\n", "does not list the label \"tenant_id\""},
		"no labels":       {"var m = prometheus.NewCounter(prometheus.CounterOpts{Name: \"x\"})\n", "has no labels"},
		"labels in a var": {"var l = []string{\"tenant_id\"}\n\nfunc New() { _ = prometheus.NewGaugeVec(prometheus.GaugeOpts{}, l) }\n", "cannot be checked"},
		"in a function":   {"func New() { _ = prometheus.NewHistogramVec(prometheus.HistogramOpts{}, []string{\"op\"}) }\n", "does not list"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			root := p4files(t, map[string]string{"internal/modules/svc/m.go": promHdr + c[0]})
			expect(t, run(t, root, "P4"), "P4", "internal/modules/svc/m.go:", c[1])
		})
	}
}

func TestP4MetricWithTenantPasses(t *testing.T) {
	src := promHdr + "var m = prometheus.NewCounterVec(prometheus.CounterOpts{Name: \"x\"}, []string{\"tenant_id\", \"result\"})\n\nfunc f() int { return big() }\n\nfunc big() int { return 1 }\n"
	if vs := run(t, p4files(t, map[string]string{"internal/modules/svc/m.go": src}), "P4"); len(vs) != 0 {
		t.Fatalf("should pass:\n%s", dump(vs))
	}
	// A constructor of a library that is not a metric library is not a metric.
	src = "package svc\n\nimport \"math/big\"\n\nvar n = big.NewInt(1)\n"
	if vs := run(t, p4files(t, map[string]string{"internal/modules/svc/n.go": src}), "P4"); len(vs) != 0 {
		t.Fatalf("big.NewInt is not a metric:\n%s", dump(vs))
	}
}

func TestP4CacheNotKeyedByTenantFails(t *testing.T) {
	for name, body := range map[string]string{
		"string key":    "type S struct{ cache map[string]int }\n",
		"cache type":    "type EntryCache struct{ seen map[string]int }\n",
		"package var":   "var userCache = map[int]string{}\n",
		"sync.Map":      "type S struct{ lookupCache sync.Map }\n",
		"struct no tid": "type key struct{ id string }\n\ntype S struct{ cache map[key]int }\n",
	} {
		t.Run(name, func(t *testing.T) {
			src := p4Hdr + "import \"sync\"\n\nvar _ sync.Mutex\n\n" + body
			src = strings.Replace(src, "import \"sync\"\n\nvar _ sync.Mutex\n\n", "", 1)
			if strings.Contains(body, "sync.Map") {
				src = strings.Replace(p4Hdr, "\t\"log/slog\"\n", "\t\"log/slog\"\n\t\"sync\"\n", 1) + body
			}
			expect(t, run(t, p4files(t, map[string]string{"internal/modules/svc/svc.go": src}), "P4"), "P4", "internal/modules/svc/svc.go:", "cache ")
		})
	}
}

func TestP4CacheKeyedByTenantPasses(t *testing.T) {
	for name, body := range map[string]string{
		"tenant key":     "type S struct{ cache map[tenant.ID]int }\n",
		"struct key":     "type key struct {\n\tt  tenant.ID\n\tid string\n}\n\ntype S struct{ cache map[key]int }\n",
		"nested":         "type S struct{ cache map[tenant.ID]map[string]int }\n",
		"not a cache":    "type S struct{ names map[string]int }\n",
		"local variable": "func f() { cache := map[string]int{}; _ = cache }\n",
	} {
		t.Run(name, func(t *testing.T) {
			if vs := run(t, p4Repo(t, body), "P4"); len(vs) != 0 {
				t.Fatalf("should pass:\n%s", dump(vs))
			}
		})
	}
}

func TestP4OutOfScopeAndTests(t *testing.T) {
	root := p4files(t, map[string]string{
		"tools/x/x.go":                     p4Hdr + "func Work(t tenant.ID) { slog.Info(\"x\") }\n",
		"internal/modules/svc/svc_test.go": p4Hdr + "func Work(t tenant.ID) { slog.Info(\"x\") }\n",
	})
	if vs := run(t, root, "P4"); len(vs) != 0 {
		t.Fatalf("outside scope and test files are not checked:\n%s", dump(vs))
	}
}

func TestP4Exceptions(t *testing.T) {
	body := "type S struct{ cache map[string]int }\n"
	pos := "internal/modules/svc/svc.go"
	manifest := func(entry string) map[string]string {
		m := realManifest(t)
		m = strings.Replace(m, `"exempt": [`, `"exempt": [`+entry, 1)
		return map[string]string{"tools/fitness/profiles/manifest.json": m, pos: p4Hdr + body}
	}
	good := `{"path": "` + pos + `#cache", "adr": "0002-deployment-model.md", "reason": "one tenant per instance"}`
	if vs := run(t, p4files(t, manifest(good)), "P4"); len(vs) != 0 {
		t.Fatalf("a declared exception passes:\n%s", dump(vs))
	}
	// No reason, an ADR that does not grant, and a stale entry each fail.
	expect(t, run(t, p4files(t, manifest(`{"path": "`+pos+`#cache", "adr": "0002-deployment-model.md", "reason": ""}`)), "P4"), "P4", "manifest p4.exempt", "no reason")
	expect(t, run(t, p4files(t, manifest(`{"path": "`+pos+`#cache", "adr": "0009-draft.md", "reason": "x"}`)), "P4"), "P4", "manifest p4.exempt", "only a ratified or accepted ADR")
	stale := `{"path": "internal/modules/svc/gone.go#cache", "adr": "0002-deployment-model.md", "reason": "x"}`
	expect(t, run(t, p4files(t, manifest(stale)), "P4"), "P4", "manifest p4.exempt", "stale")
}

func TestP4CannotBeSwitchedOffByDeletingConfig(t *testing.T) {
	m := realManifest(t)
	i := strings.Index(m, `  "p4": {`)
	j := strings.Index(m[i:], "  },\n")
	m = m[:i] + m[i+j+len("  },\n"):]
	vs := run(t, p4files(t, map[string]string{"tools/fitness/profiles/manifest.json": m}), "P4")
	expect(t, vs, "P4", "manifest p4", "cannot be switched off")
}

func realManifest(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	m := string(b)
	i := strings.Index(m, `"exempt": [`)
	j := strings.Index(m[i:], "]\n")
	return m[:i] + `"exempt": [` + m[i+j:]
}
