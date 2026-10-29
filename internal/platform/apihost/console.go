package apihost

import (
	"io"
	"io/fs"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/apihost/apitypes"
)

// WithConsole makes the router also serve the built console from root (it must contain index.html):
// a GET or HEAD outside /api/ answers the file at that path, or index.html for a client-side route
// (a path with no file extension). Everything under /api/ stays the API's, so an unknown API path
// is still a problem, never HTML. A nil root serves no console.
func WithConsole(root fs.FS) Option { return func(s *Server) { s.console = root } }

// consoleCSP lets the console load only its own scripts, styles, fonts and images and call only its
// own origin. Inline style attributes are allowed (React style props); inline scripts never.
const consoleCSP = "default-src 'none'; script-src 'self'; style-src 'self'; style-src-attr 'unsafe-inline'; " +
	"img-src 'self' data:; font-src 'self'; connect-src 'self'; manifest-src 'self'; " +
	"base-uri 'none'; form-action 'self'; frame-ancestors 'none'"

// serveConsole answers a request that matched no API route, reporting whether it did.
func (s *Server) serveConsole(w http.ResponseWriter, r *http.Request) bool {
	if s.console == nil || r.URL.Path == "/api" || strings.HasPrefix(r.URL.Path, "/api/") {
		return false
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return false
	}
	name := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
	if name == "" || name == "." {
		name = "index.html"
	}
	if info, err := fs.Stat(s.console, name); err != nil || info.IsDir() {
		if path.Ext(name) != "" {
			writeProblem(w, r, apitypes.NotFound(""), s.log)
			return true
		}
		name = "index.html" // a client-side route
	}
	f, err := s.console.Open(name)
	if err != nil {
		writeProblem(w, r, apitypes.NotFound(""), s.log)
		return true
	}
	defer f.Close()
	rs, ok := f.(io.ReadSeeker)
	if !ok {
		writeProblem(w, r, apitypes.Internal(""), s.log)
		return true
	}
	h := w.Header()
	h.Set("Content-Security-Policy", consoleCSP)
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	if strings.HasPrefix(name, "assets/") {
		h.Set("Cache-Control", "public, max-age=31536000, immutable") // content-hashed file names
	} else {
		h.Set("Cache-Control", "no-cache")
	}
	http.ServeContent(w, r, name, time.Time{}, rs)
	return true
}
