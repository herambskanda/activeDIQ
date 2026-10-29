package apihost

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/apihost/apitypes"
)

// This file and chain.go are the only code in internal/** that writes an HTTP status
// (ADR-0004 rule 8).

const problemMedia = "application/problem+json"

// responseOpts is the one set of encode options for every JSON document apihost writes
// (safe-primitives §12.5 rule 7): encoding/json/v2 does not escape <, >, & or U+2028/2029 by
// default, and directory attributes are attacker-influenced text. FF-SP2 bans turning either off,
// and TestEveryEncodeSiteUsesResponseOptions keeps marshalResponse the only encode site.
var responseOpts = json.JoinOptions(jsontext.EscapeForHTML(true), jsontext.EscapeForJS(true))

// marshalResponse is the only place apihost encodes a response body.
func marshalResponse(v any) ([]byte, error) {
	return json.Marshal(v, responseOpts)
}

func newTraceID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// writeProblem renders any failure as application/problem+json. A *apitypes.Problem is rendered as
// built; a validation error set becomes a validation problem; everything else is /problems/internal
// with only the trace ID, and the real error goes to the log.
func writeProblem(w http.ResponseWriter, r *http.Request, err error, log *slog.Logger) {
	writeProblemChallenge(w, r, err, log, "Bearer")
}

// writeProblemChallenge is writeProblem with the WWW-Authenticate scheme a 401 carries.
func writeProblemChallenge(w http.ResponseWriter, r *http.Request, err error, log *slog.Logger, challenge string) {
	var p *apitypes.Problem
	if !errors.As(err, &p) || p == nil {
		trace := TraceID(r.Context())
		log.Error("request failed", "trace_id", trace, "operation_path", r.URL.Path, "error", err)
		p = apitypes.Internal("")
	}
	p = cloneProblem(p)
	inst := r.URL.Path
	p.Instance = &inst
	if t := TraceID(r.Context()); t != "" {
		p.TraceID = &t
	}
	body, merr := marshalResponse(p)
	if merr != nil {
		body = []byte(`{"type":"` + apitypes.ProblemTypeInternal + `","title":"Internal error","status":500}`)
		p.Status = 500
	}
	h := w.Header()
	h.Set("Content-Type", problemMedia)
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	if p.Status == http.StatusUnauthorized {
		h.Add("WWW-Authenticate", challenge)
	}
	w.WriteHeader(int(p.Status))
	_, _ = w.Write(body)
}

func cloneProblem(p *apitypes.Problem) *apitypes.Problem {
	c := *p
	c.Errors = append([]apitypes.ProblemError(nil), p.Errors...)
	return &c
}

// writeResponse encodes a handler's successful response: JSON v2, a stream, or no body.
func writeResponse(w http.ResponseWriter, r *http.Request, meta RouteMeta, resp Response, log *slog.Logger) {
	status := resp.StatusCode()
	body := resp.ResponseBody()
	var enc []byte
	if body != nil {
		if _, ok := body.(Stream); !ok {
			var err error
			if enc, err = marshalResponse(body); err != nil {
				writeProblem(w, r, err, log) // never a half-written 200
				return
			}
		}
	}
	h := w.Header()
	for k, v := range resp.ResponseHeaders() {
		h.Set(k, v)
	}
	if hl, ok := resp.(HeaderLists); ok {
		for k, vs := range hl.ResponseHeaderLists() {
			for _, v := range vs {
				if v != "" {
					h.Add(k, v)
				}
			}
		}
	}
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	if meta.Deprecated {
		h.Set("Deprecation", "true")
		if meta.Sunset != "" {
			h.Set("Sunset", httpDate(meta.Sunset))
		}
	}
	switch b := body.(type) {
	case nil:
		w.WriteHeader(status)
	case Stream:
		ct := b.ContentType
		if ct == "" {
			ct = "application/octet-stream"
		}
		h.Set("Content-Type", ct)
		// Content-Disposition is set only by httpx.Attachment (safe-primitives P7, §12.5 rule 5), which
		// does not exist yet: a Stream's Filename is not emitted until it does.
		w.WriteHeader(status)
		if r.Method != http.MethodHead && b.Reader != nil {
			_, _ = io.Copy(w, b.Reader) // the status is out; a mid-stream failure can only close the connection
		}
	default:
		h.Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write(enc)
	}
}

// httpDate renders a sunset date (RFC 3339 or a calendar date) as an HTTP date; anything else is
// passed through, so the header never silently drops.
func httpDate(s string) string {
	for _, layout := range []string{time.RFC3339, "2006-01-02"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC().Format(http.TimeFormat)
		}
	}
	return s
}

func retryAfter(d Decision) string {
	secs := int64((d.RetryAfter + time.Second - 1) / time.Second)
	if secs < 1 {
		secs = 1
	}
	return strconv.FormatInt(secs, 10)
}

// credentialQueryKeys are query parameter names refused outright (rule 9, chain step 5).
var credentialQueryKeys = []string{"password", "pwd", "secret", "token", "apikey", "api_key", "access_token", "accesstoken", "client_secret", "private_key", "authorization"}

func hasCredentialQuery(q url.Values) bool {
	for k := range q {
		lk := strings.ToLower(k)
		for _, c := range credentialQueryKeys {
			if lk == c {
				return true
			}
		}
	}
	return false
}
