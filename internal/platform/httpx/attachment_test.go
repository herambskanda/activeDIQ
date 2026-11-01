package httpx

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"mime"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"net/url"
	"strings"
	"testing"

	"github.com/skenzeriq/activediq/internal/platform/corpus/corpustest"
)

var formatByName = map[string]Format{"csv": CSV, "xlsx": XLSX, "html": HTML, "pdf": PDF}

func TestExtensionComesFromFormat(t *testing.T) {
	for f, ext := range map[Format]string{CSV: ".csv", XLSX: ".xlsx", PDF: ".pdf"} {
		rec := httptest.NewRecorder()
		if err := Attachment(rec, "a.exe", f, nil); err != nil {
			t.Fatal(err)
		}
		_, params, err := mime.ParseMediaType(rec.Header().Get("Content-Disposition"))
		if err != nil || params["filename"] != "a.exe"+ext {
			t.Errorf("format %d: filename %q err %v", f, params["filename"], err)
		}
	}
}

func TestHeadersEveryFormat(t *testing.T) {
	sum := sha256.Sum256([]byte("body{}"))
	for name, f := range formatByName {
		rec := httptest.NewRecorder()
		body := bytes.NewReader([]byte("payload"))
		if err := Attachment(rec, "r", f, body, WithStyleSHA256(sum)); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		h := rec.Header()
		if !strings.HasPrefix(h.Get("Content-Disposition"), "attachment; ") {
			t.Errorf("%s: disposition %q", name, h.Get("Content-Disposition"))
		}
		if h.Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("%s: no nosniff", name)
		}
		csp := h.Get("Content-Security-Policy")
		if (name == "html") != (csp != "") {
			t.Errorf("%s: CSP %q", name, csp)
		}
		if rec.Body.String() != "payload" {
			t.Errorf("%s: body %q", name, rec.Body.String())
		}
	}
	rec := httptest.NewRecorder()
	if err := Attachment(rec, "r", HTML, nil, WithStyleSHA256(sum)); err != nil {
		t.Fatal(err)
	}
	csp := rec.Header().Get("Content-Security-Policy")
	for _, want := range []string{"sandbox; ", "default-src 'none'", "style-src 'sha256-", "img-src data:"} {
		if !strings.Contains(csp, want) {
			t.Errorf("CSP %q lacks %q", csp, want)
		}
	}
	if strings.Contains(strings.ToLower(rec.Header().Get("Content-Disposition")), "inline") {
		t.Error("inline disposition")
	}
}

func TestErrorsWriteNothing(t *testing.T) {
	for _, c := range []struct {
		f    Format
		want error
	}{{0, ErrUnknownFormat}, {Format(99), ErrUnknownFormat}, {HTML, ErrMissingStyleHash}} {
		h := http.Header{}
		if err := Headers(h, "x", c.f); !errors.Is(err, c.want) {
			t.Errorf("format %d: %v, want %v", c.f, err, c.want)
		}
		if len(h) != 0 {
			t.Errorf("format %d: headers set on error: %v", c.f, h)
		}
	}
}

func TestBaseEdgeCases(t *testing.T) {
	cases := map[string]string{
		"":                       "download.csv",
		"Résumé":                 "Résumé.csv",
		"100%":                   "100_.csv",
		"bad\xffutf8":            "bad_utf8.csv",
		strings.Repeat("a", 500): strings.Repeat("a", MaxBaseRunes) + ".csv",
	}
	for in, want := range cases {
		h := http.Header{}
		if err := Headers(h, in, CSV); err != nil {
			t.Fatal(err)
		}
		_, params, err := mime.ParseMediaType(h.Get("Content-Disposition"))
		if err != nil || params["filename"] == "" {
			t.Fatalf("%q: unparsable %q: %v", in, h.Get("Content-Disposition"), err)
		}
		if in != "Résumé" && params["filename"] != want {
			t.Errorf("%q: filename %q, want %q", in, params["filename"], want)
		}
	}
	h := http.Header{}
	_ = Headers(h, "Résumé", CSV)
	if got := h.Get("Content-Disposition"); !strings.Contains(got, `filename="R_sum_.csv"; filename*=UTF-8''R%C3%A9sum%C3%A9.csv`) {
		t.Errorf("non-ASCII: %q", got)
	}
}

// checkHeader is the independent-parse property: the stdlib parser reads exactly one attachment
// disposition with only the filename parameters, the raw value has no CR, LF or control byte, and
// the quoted fallback holds no quote or backslash inside.
func checkHeader(t testing.TB, base string) {
	h := http.Header{}
	if err := Headers(h, base, CSV); err != nil {
		t.Fatalf("Headers(%q): %v", base, err)
	}
	v := h.Get("Content-Disposition")
	for i := 0; i < len(v); i++ {
		if v[i] < 0x20 || v[i] == 0x7f {
			t.Fatalf("control byte %#x in %q (base %q)", v[i], v, base)
		}
	}
	const pre, mid = `attachment; filename="`, `"; filename*=UTF-8''`
	if !strings.HasPrefix(v, pre) {
		t.Fatalf("header %q does not start with %q", v, pre)
	}
	i := strings.Index(v, mid)
	if i < 0 {
		t.Fatalf("header %q lacks filename*", v)
	}
	if fb := v[len(pre):i]; strings.ContainsAny(fb, "\"\\") {
		t.Fatalf("fallback %q holds a quote or backslash (base %q)", fb, base)
	}
	disp, params, err := mime.ParseMediaType(v)
	if err != nil || disp != "attachment" {
		t.Fatalf("stdlib parse of %q: %q %v", v, disp, err)
	}
	if len(params) != 1 { // mime merges filename* into filename
		t.Fatalf("parameters %v, want only the file name (base %q)", params, base)
	}
	ext, err := url.PathUnescape(v[i+len(mid):])
	if err != nil || !strings.HasSuffix(ext, ".csv") || params["filename"] != ext {
		t.Fatalf("filename* %q does not round-trip to %q: %v", ext, params["filename"], err)
	}
	if strings.ContainsAny(ext, "\\/:*?\"<>|%\r\n") {
		t.Fatalf("mapped name %q still holds a reserved character", ext)
	}
}

func FuzzAttachment(f *testing.F) {
	corpustest.Seed(f, "html")
	f.Fuzz(func(t *testing.T, in []byte) { checkHeader(t, string(in)) })
}

func TestPartHeaders(t *testing.T) {
	h := textproto.MIMEHeader{}
	if err := PartHeaders(h, "x\r\nContent-Type: text/html", CSV); err != nil {
		t.Fatal(err)
	}
	if got := len(h); got != 2 {
		t.Fatalf("headers = %v, want Content-Disposition and Content-Type only", h)
	}
	if got, want := h.Get("Content-Disposition"), `attachment; filename="x__Content-Type_ text_html.csv"; filename*=UTF-8''x__Content-Type_%20text_html.csv`; got != want {
		t.Fatalf("Content-Disposition = %q, want %q", got, want)
	}
	if got, want := h.Get("Content-Type"), `text/csv; name="x__Content-Type_ text_html.csv"`; got != want {
		t.Fatalf("Content-Type = %q, want %q", got, want)
	}
	// the same disposition value as the response header
	rh := http.Header{}
	if err := Headers(rh, "x\r\nContent-Type: text/html", CSV); err != nil {
		t.Fatal(err)
	}
	if rh.Get("Content-Disposition") != h.Get("Content-Disposition") {
		t.Fatalf("part %q and response %q disagree", h.Get("Content-Disposition"), rh.Get("Content-Disposition"))
	}
}

func TestPartHeadersRefuse(t *testing.T) {
	for _, c := range []struct {
		f    Format
		want error
	}{{0, ErrUnknownFormat}, {Format(99), ErrUnknownFormat}, {HTML, ErrPartFormat}} {
		h := textproto.MIMEHeader{}
		if err := PartHeaders(h, "report", c.f); !errors.Is(err, c.want) || len(h) != 0 {
			t.Errorf("PartHeaders(%d) = %v, headers %v; want %v and nothing set", c.f, err, h, c.want)
		}
	}
}
