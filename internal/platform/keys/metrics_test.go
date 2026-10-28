package keys_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/skenzeriq/activediq/internal/platform/keys"
	"github.com/skenzeriq/activediq/internal/platform/keys/keystest"
	"github.com/skenzeriq/activediq/internal/platform/secret"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// TM-TB5-T3 / T-0177 AC1: UnwrapDEK increments the per-tenant counter by outcome, on every profile.
func TestUnwrapMetricPerTenantByOutcome(t *testing.T) {
	kek := bytes.Repeat([]byte{7}, keys.DEKSize)
	local, err := keys.NewLocalProvider("k1", secret.FromBytes(kek))
	if err != nil {
		t.Fatal(err)
	}
	profiles := map[string]keys.Provider{"local": local, "kms": keystest.New("key-1")}
	for name, p := range profiles {
		t.Run(name, func(t *testing.T) {
			ta, tb := tenant.New(), tenant.New()
			dek, _ := keys.NewDEK(2)
			wrapped, ref, err := keys.WrapDEK(p, ta, dek)
			if err != nil {
				t.Fatal(err)
			}
			okA, failA, okB, failB := keys.UnwrapCount(ta, keys.OutcomeSuccess), keys.UnwrapCount(ta, keys.OutcomeFailure),
				keys.UnwrapCount(tb, keys.OutcomeSuccess), keys.UnwrapCount(tb, keys.OutcomeFailure)

			if _, err := keys.UnwrapDEK(p, ta, 2, ref, wrapped); err != nil {
				t.Fatal(err)
			}
			if got := keys.UnwrapCount(ta, keys.OutcomeSuccess); got != okA+1 {
				t.Fatalf("success = %d, want %d", got, okA+1)
			}
			// Cross-tenant unwrap fails and is attributed to the tenant asking.
			if _, err := keys.UnwrapDEK(p, tb, 2, ref, wrapped); err == nil {
				t.Fatal("cross-tenant unwrap succeeded")
			}
			if got := keys.UnwrapCount(tb, keys.OutcomeFailure); got != failB+1 {
				t.Fatalf("tenant B failure = %d, want %d", got, failB+1)
			}
			if keys.UnwrapCount(ta, keys.OutcomeFailure) != failA || keys.UnwrapCount(ta, keys.OutcomeSuccess) != okA+1 ||
				keys.UnwrapCount(tb, keys.OutcomeSuccess) != okB {
				t.Fatal("counters leaked across tenants/outcomes")
			}

			var buf bytes.Buffer
			if err := keys.WriteMetrics(&buf); err != nil {
				t.Fatal(err)
			}
			out := buf.String()
			if !strings.Contains(out, `activediq_keys_dek_unwraps_total{tenant="`+ta.String()+`",outcome="success"}`) {
				t.Fatalf("scrape missing tenant series:\n%s", out)
			}
			if strings.Contains(out, ref.KeyID) {
				t.Fatal("key ref leaked into metrics")
			}
		})
	}
}
