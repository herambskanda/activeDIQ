package authn

import "testing"

// realAN8Target builds the real AN-8 handler of T-0200 behind the an8Target seam: the shared store faked
// only at its port, the clock fixed, the seed accounts present (Known active local with Password,
// NonLocal not local, Disabled local and disabled), the key table capped small enough for FillTable.
// It returns ok=false while the handler is the 501 stub. T-0200 replaces this body; it must not
// return ok=false once the handler exists, and the five TestAN8* tests must pass against it.
func realAN8Target(t *testing.T, seed an8Seed) (an8Target, bool) {
	t.Helper()
	return nil, false
}
