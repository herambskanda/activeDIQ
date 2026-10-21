package apihost

import (
	"encoding/json/v2"
	"errors"
	"net"
	"net/http"
	"strings"

	"github.com/skenzeriq/activediq/internal/platform/apihost/apitypes"
	"github.com/skenzeriq/activediq/internal/platform/secret/secretjson"
)

func isUnsafe(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return false
	}
	return true
}

func sourceIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func hostOnly(h string) string {
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	return strings.ToLower(strings.TrimSuffix(h, "."))
}

// routeHandler is the fixed middleware chain for one route (ADR-0004 rule 5). Recover and the trace
// ID are in ServeHTTP. The order is the contract: nothing before authentication reads the body, and
// an unauthorised body is never parsed.
func (s *Server) routeHandler(rt Route, boundHost string) http.Handler {
	meta := rt.Meta()
	anonymous := meta.Permission == "anonymous"
	authenticatedOnly := meta.Permission == "authenticated"
	needsStepUp := s.policy.stepUp(meta.Permission)
	hasBody := meta.Body == BodyJSON || meta.Body == BodyMergePatch

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fail := func(err error) { writeProblem(w, r, err, s.log) }
		ctx := r.Context()

		// 3. per-source-IP rate limit, before any authentication work.
		if d, err := s.ports.Limits.AllowIP(ctx, meta.Class, sourceIP(r)); err != nil {
			fail(err)
			return
		} else if !d.Allowed {
			w.Header().Set("Retry-After", retryAfter(d))
			fail(apitypes.RateLimited(""))
			return
		}
		// 4. host binding.
		if boundHost != "" && hostOnly(r.Host) != strings.ToLower(boundHost) {
			fail(apitypes.NotFound(""))
			return
		}
		// 5. query-credential refusal.
		if hasCredentialQuery(r) {
			fail(apitypes.MalformedRequest("credentials are never accepted in the query string"))
			return
		}
		// 6. body cap (declared length; the read enforces it again).
		if r.ContentLength > meta.MaxBody {
			fail(apitypes.PayloadTooLarge(""))
			return
		}
		// 7. Content-Type.
		if meta.Body != BodyNone && (r.ContentLength != 0 || hasBody) {
			if !mediaTypeOK(r.Header.Get("Content-Type"), meta.MediaType) {
				fail(apitypes.UnsupportedMediaType("expected " + meta.MediaType))
				return
			}
		}

		if !anonymous {
			// 8. authentication.
			p, err := s.ports.Authn.Authenticate(r)
			if err != nil {
				if errors.Is(err, ErrUnauthenticated) {
					fail(apitypes.Unauthenticated(""))
				} else {
					fail(err)
				}
				return
			}
			ctx = withPrincipal(ctx, p)
			r = r.WithContext(ctx)
			// 9. CSRF for cookie sessions on unsafe methods.
			if p.Kind == KindSession && isUnsafe(r.Method) {
				if err := s.ports.Authn.CheckCSRF(r, p); err != nil {
					if errors.Is(err, ErrCSRF) {
						fail(apitypes.CSRFFailed(""))
					} else {
						fail(err)
					}
					return
				}
			}
			// 10. per-principal rate limit by class.
			if d, err := s.ports.Limits.AllowPrincipal(ctx, meta.Class, p); err != nil {
				fail(err)
				return
			} else if !d.Allowed {
				w.Header().Set("Retry-After", retryAfter(d))
				fail(apitypes.RateLimited(""))
				return
			}
			// 11. step-up.
			if needsStepUp {
				if ok, err := s.ports.StepUp.Fresh(ctx, p); err != nil {
					fail(err)
					return
				} else if !ok {
					fail(apitypes.StepUpRequired(""))
					return
				}
			}
			// 12. permission. An "authenticated" row passes any authenticated principal.
			if !authenticatedOnly {
				if ok, err := s.ports.Authz.Allow(ctx, p, meta.Permission, meta.Scope); err != nil {
					fail(err)
					return
				} else if !ok {
					fail(apitypes.Forbidden(""))
					return
				}
			}
		}

		// 13. buffer, validate and decode.
		in := rt.NewInput()
		var buf []byte
		defer func() { // 16. secret clean-up, on panic too
			in.DestroySecrets()
			clear(buf)
		}()
		req := &Request{PathValue: r.PathValue, Query: r.URL.Query(), Header: r.Header}
		var errs apitypes.Errors
		if meta.Body == BodyBinary {
			req.Upload = Upload{Reader: http.MaxBytesReader(w, r.Body, meta.MaxBody)}
		}
		in.BindRequest(req, &errs)

		switch {
		case hasBody:
			var err error
			if buf, err = readBody(r, meta.MaxBody); err != nil {
				if errors.Is(err, errTooLarge) {
					fail(apitypes.PayloadTooLarge(""))
				} else {
					fail(apitypes.MalformedRequest("the request body could not be read"))
				}
				return
			}
			if err := checkJSON(buf, meta.Class == classBulk); err != nil {
				fail(apitypes.MalformedRequest("the request body is not valid JSON"))
				return
			}
			decoded := true
			if target := in.BodyTarget(); target != nil {
				if err := secretjson.Decode(buf, target); err != nil {
					decoded = false
					collectDecodeError(&errs, err)
				}
			}
			if decoded {
				in.Validate(&errs)
			}
		default:
			in.Validate(&errs)
		}
		if errs.Len() > 0 {
			fail(apitypes.Validation("").WithErrors(&errs))
			return
		}

		// 14. handler.
		resp, err := rt.Call(ctx, in)
		if err != nil {
			fail(err)
			return
		}
		// 15. encode.
		writeResponse(w, r, meta, resp, s.log)
	})
}

// collectDecodeError turns a decoder failure into violations without ever echoing v2's text: a
// generated decoder's ViolationError carries a fixed detail; a semantic error becomes a type
// violation at its pointer; anything else is a type violation at the root.
func collectDecodeError(errs *apitypes.Errors, err error) {
	var ve *apitypes.ViolationError
	if errors.As(err, &ve) {
		errs.Merge(ve.V)
		return
	}
	var se *json.SemanticError
	if errors.As(err, &se) {
		errs.AddBody(se.JSONPointer, apitypes.CodeType, "the value has the wrong type or format")
		return
	}
	errs.AddBody("", apitypes.CodeType, "the body does not match the schema")
}
