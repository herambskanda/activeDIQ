package apihost

import (
	"bytes"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

// The CSRF value must not appear when a principal is printed or logged (T-0854 AC4).
func TestPrincipalRedactsCSRFValue(t *testing.T) {
	const secret = "csrf-value-must-not-leak"
	p := Principal{ID: "acct", Tenant: "ten", Kind: KindSession, SessionID: "sid", CSRF: secret}
	for name, got := range map[string]string{
		"%v": fmt.Sprintf("%v", p), "%+v": fmt.Sprintf("%+v", p), "%#v": fmt.Sprintf("%#v", p), "%s": fmt.Sprintf("%s", p),
		"pointer %v": fmt.Sprintf("%v", &p), "in a struct": fmt.Sprintf("%+v", struct{ P Principal }{p}),
	} {
		if strings.Contains(got, secret) {
			t.Errorf("%s leaks the CSRF value: %s", name, got)
		}
		if !strings.Contains(got, "acct") {
			t.Errorf("%s dropped the principal ID: %s", name, got)
		}
	}
	var buf bytes.Buffer
	slog.New(slog.NewJSONHandler(&buf, nil)).Info("x", "principal", p)
	slog.New(slog.NewTextHandler(&buf, nil)).Info("x", "principal", p)
	if strings.Contains(buf.String(), secret) || !strings.Contains(buf.String(), "acct") {
		t.Errorf("log output: %s", buf.String())
	}
}
