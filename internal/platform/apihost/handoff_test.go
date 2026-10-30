package apihost

import (
	"net/http/httptest"
	"strings"
	"testing"
)

// T-0800: the handoff page is rendered by html/template; a hostile target cannot leave the attribute.
func TestWriteHandoffEscapesTarget(t *testing.T) {
	rec := httptest.NewRecorder()
	writeHandoff(rec, `/x"><script>alert(1)</script>`)
	body := rec.Body.String()
	if strings.Contains(body, "<script>") || strings.Contains(body, `"><`+`script`) {
		t.Fatalf("target not escaped: %s", body)
	}
	if rec.Code != 200 || !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/html") || !strings.Contains(body, "Signing in") {
		t.Fatalf("unexpected response %d %q", rec.Code, body)
	}
}
