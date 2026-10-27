package saml_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/authn/sso"
	"github.com/skenzeriq/activediq/internal/platform/authn/sso/saml"
	"github.com/skenzeriq/activediq/internal/platform/authn/sso/saml/samltest"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

type record struct {
	ID     string   `json:"id"`
	Class  string   `json:"class"`
	Cites  []string `json:"cites"`
	Build  string   `json:"build"`
	Expect string   `json:"expect"`
	Reason string   `json:"reason"`
}

const corpusDir = "../testdata/corpus/saml"

func loadCorpus(t testing.TB) []record {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(corpusDir, "*.json"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no corpus records in %s: %v", corpusDir, err)
	}
	sort.Strings(files)
	var out []record
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var r record
		if err := json.Unmarshal(b, &r); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		out = append(out, r)
	}
	return out
}

// TestCorpus runs every record end to end (TM-F-SSO, spec §10.1): a case that is accepted, or refused with
// another reason, fails.
func TestCorpus(t *testing.T) {
	for _, rec := range loadCorpus(t) {
		t.Run(rec.ID, func(t *testing.T) {
			if rec.Expect != "refuse" || rec.Reason == "" {
				t.Fatalf("record %s must expect a refusal with a reason", rec.ID)
			}
			r := newRig(t)
			v, err := r.run(t, rec.Build)
			if err == nil {
				t.Fatalf("ACCEPTED: %+v", v)
			}
			if got := sso.ReasonOf(err); got != rec.Reason {
				t.Fatalf("reason %q, want %q (%v)", got, rec.Reason, err)
			}
		})
	}
}

// TestCorpusCoverage is the FIT-SSO-2 shape for SAML: every check SAML-1..19 is cited, and every class has a
// record.
func TestCorpusCoverage(t *testing.T) {
	cited, classes := map[string]bool{}, map[string]bool{}
	for _, r := range loadCorpus(t) {
		classes[r.Class] = true
		for _, c := range r.Cites {
			cited[c] = true
		}
	}
	for n := 1; n <= 19; n++ {
		id := "SAML-" + itoa(n)
		if !cited[id] {
			t.Errorf("%s is cited by no corpus record", id)
		}
	}
	for _, c := range []string{"forged", "wrapped", "replayed", "misaddressed", "malformed"} {
		if !classes[c] {
			t.Errorf("no %s record", c)
		}
	}
}

func itoa(n int) string {
	if n < 10 {
		return string(rune('0' + n))
	}
	return string(rune('0'+n/10)) + string(rune('0'+n%10))
}

// FuzzSAMLComplete mutates responses and checks the oracle (spec §10.1): any Verified must be a tuple the
// test IdP actually signed, and the same assertion ID is never accepted twice. Seeds are every corpus case
// and the known-good responses.
func FuzzSAMLComplete(f *testing.F) {
	seedEnv := samltest.NewEnv()
	tx := seedEnv.Tx(sso.IntentSignin)
	for name, b := range samltest.Builders {
		out := b(seedEnv, tx)
		if v := out.Form.Get("SAMLResponse"); v != "" {
			if raw, err := base64.StdEncoding.DecodeString(v); err == nil {
				f.Add(raw)
			}
		}
		_ = name
	}
	env := samltest.NewEnv()
	f.Fuzz(func(t *testing.T, doc []byte) {
		now := func() time.Time { return env.Now }
		v := saml.New(saml.NewMemoryReplayCache(now), now)
		cb := sso.Callback{IdPID: samltest.IdPID, Form: samltest.Form(doc)}
		got, err := v.Complete(context.Background(), tenant.ID{}, env.IdP(), tx, cb)
		if err != nil {
			return
		}
		if !env.Signed(samltest.Tuple{Issuer: got.Issuer, Subject: got.Subject, ResponseID: got.ResponseID}) {
			t.Fatalf("forgery accepted: %+v", got)
		}
		if _, err := v.Complete(context.Background(), tenant.ID{}, env.IdP(), tx, cb); err == nil {
			t.Fatalf("assertion %s accepted twice", got.ResponseID)
		}
	})
}
