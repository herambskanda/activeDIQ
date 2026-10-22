package apihost

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"path"
	"slices"
	"sort"
	"strings"

	"github.com/skenzeriq/activediq/internal/platform/apihost/apitypes"
)

// apiPrefix is where the document's relative paths are mounted.
const apiPrefix = "/api/v1"

// Option configures Build.
type Option func(*Server)

// WithLogger sets the logger for internal errors and start-up notes. The default discards nothing:
// it is slog.Default().
func WithLogger(l *slog.Logger) Option { return func(s *Server) { s.log = l } }

// WithBodyBudget sets the total bytes of request-body buffers the router may hold at once across
// all in-flight requests (default DefaultBodyBudget). A request whose buffer does not fit is
// refused with 429 and Retry-After before anything is allocated. It must be positive.
func WithBodyBudget(bytes int64) Option {
	return func(s *Server) { s.budgetTotal, s.budgetSet = bytes, true }
}

// WithAnonymousBodyBudget sets how much of the body budget anonymous routes may hold (default a
// quarter of the total) — a slice of the total, not an addition to it, so the total stays the
// ceiling on body memory. Anonymous traffic draws only from this pool, so an unauthenticated flood
// can starve other anonymous flows but never an authenticated request, which draws from the
// remainder (total minus this). It must be positive and less than the total.
func WithAnonymousBodyBudget(bytes int64) Option {
	return func(s *Server) { s.anonBudgetTotal, s.anonSet = bytes, true }
}

// Server is the built API router. It is an http.Handler that answers every path with either a
// route of the document or a problem.
type Server struct {
	mux        *http.ServeMux
	log        *slog.Logger
	ports      Ports
	policy     Policy
	rows       []RouteInfo
	unmounted  []string
	budget     *bodyBudget // authenticated routes: total minus the anonymous slice
	anonBudget *bodyBudget // anonymous routes only

	budgetTotal, anonBudgetTotal int64
	budgetSet, anonSet           bool
}

// RouteInfo describes one mounted route, for the route-table probes of fitness-api (A4).
type RouteInfo struct {
	OperationID string
	Method      string
	Path        string // with the /api/v1 prefix
	Permission  string
	Anonymous   bool
	Host        string // the hostname an anonymous route is bound to, or empty
}

// Routes returns the mounted routes ordered by operation.
func (s *Server) Routes() []RouteInfo { return append([]RouteInfo(nil), s.rows...) }

// Unmounted lists the tags of the document that no TagHandlers contributed (capability-disabled
// modules). Their operations answer not-found.
func (s *Server) Unmounted() []string { return append([]string(nil), s.unmounted...) }

// Build is the one function that makes the route table. compose/server calls it at start-up and
// fitness-api calls it with the same ports, so production and the test cannot diverge. It refuses
// to return a Server when (ADR-0004 rule 5):
//   - a contributed route does not match a document operation exactly (method, path, operationId, tag);
//   - an operation of a contributed tag has no handler;
//   - an operation has no x-permission, or one outside the catalogue, or is "anonymous" or
//     "authenticated" without its policy row;
//   - an anonymous row names a host binding that does not exist or has no hostname;
//   - two patterns conflict.
func Build(doc Document, tags []TagHandlers, policy Policy, catalogue PermissionCatalogue, ports Ports, opts ...Option) (*Server, error) {
	s := &Server{mux: http.NewServeMux(), log: slog.Default(), ports: ports, policy: policy}
	for _, o := range opts {
		o(s)
	}
	var errs []error
	fail := func(format string, a ...any) { errs = append(errs, fmt.Errorf("apihost: "+format, a...)) }
	if !s.budgetSet {
		s.budgetTotal = DefaultBodyBudget
	}
	if !s.anonSet {
		s.anonBudgetTotal = max(s.budgetTotal/4, 1)
	}
	if s.budgetTotal <= 0 || s.anonBudgetTotal <= 0 || s.anonBudgetTotal >= s.budgetTotal {
		fail("the body budgets must be positive and the anonymous budget less than the total")
	} else {
		s.budget = newBodyBudget(s.budgetTotal - s.anonBudgetTotal)
		s.anonBudget = newBodyBudget(s.anonBudgetTotal)
	}

	if ports.Authn == nil || ports.Authz == nil || ports.Limits == nil || ports.StepUp == nil {
		fail("every port (Authn, Authz, Limits, StepUp) must be set")
	}
	for _, b := range policy.Anonymous {
		if b.Host == "" {
			continue
		}
		if _, ok := LookupHostBinding(b.Host); !ok {
			fail("policy.anonymous %s names unknown host binding %q", b.Operation, b.Host)
		} else if policy.Hosts[b.Host] == "" {
			fail("host binding %q has no hostname configured", b.Host)
		}
	}

	byKey := map[string]Operation{}
	byID := map[string]Operation{}
	for _, op := range doc.ops {
		if _, dup := byID[op.ID]; dup {
			fail("operationId %q is declared twice in the document", op.ID)
		}
		byID[op.ID] = op
		byKey[op.Method+" "+op.Path] = op
		switch {
		case op.Permission == "":
			fail("%s (%s %s) has no x-permission", op.ID, op.Method, op.Path)
		case op.Permission == "anonymous":
			if _, ok := policy.anonymous(op.ID); !ok {
				fail("%s is anonymous but has no policy.anonymous row", op.ID)
			}
		case op.Permission == "authenticated":
			if !policy.authenticated(op.ID) {
				fail("%s is authenticated but has no policy.authenticated row", op.ID)
			}
		case catalogue == nil || !catalogue.Has(op.Permission):
			fail("%s: x-permission %q is not in the permission catalogue", op.ID, op.Permission)
		}
	}

	contributed := map[string]bool{}
	handled := map[string]bool{}
	for _, th := range tags {
		contributed[th.Tag()] = true
		for _, rt := range th.Routes() {
			m := rt.Meta()
			op, ok := byID[m.OperationID]
			switch {
			case !ok:
				fail("tag %s contributes %q, which is not in the document", th.Tag(), m.OperationID)
				continue
			case op.Tag != th.Tag() || m.Tag != op.Tag:
				fail("%s: tag %q does not match the document's %q", m.OperationID, th.Tag(), op.Tag)
				continue
			case m.Method != op.Method || m.Path != op.Path:
				fail("%s: %s %s does not match the document's %s %s", m.OperationID, m.Method, m.Path, op.Method, op.Path)
				continue
			case m.Permission != op.Permission:
				fail("%s: permission %q does not match the document's %q", m.OperationID, m.Permission, op.Permission)
				continue
			case m.Scope != op.Scope || m.Class != op.Class:
				fail("%s: scope/class %q/%q do not match the document's %q/%q", m.OperationID, m.Scope, m.Class, op.Scope, op.Class)
				continue
			case handled[m.OperationID]:
				fail("%s is contributed twice", m.OperationID)
				continue
			}
			handled[m.OperationID] = true
			host := ""
			if row, ok := policy.anonymous(m.OperationID); ok && row.Host != "" {
				host = policy.Hosts[row.Host]
			}
			if err := s.mount(rt, host); err != nil {
				fail("%s: %v", m.OperationID, err)
				continue
			}
			s.rows = append(s.rows, RouteInfo{OperationID: m.OperationID, Method: m.Method, Path: apiPrefix + m.Path,
				Permission: m.Permission, Anonymous: m.Permission == "anonymous", Host: host})
		}
	}
	missing := map[string]bool{}
	for _, op := range doc.ops {
		if !contributed[op.Tag] {
			missing[op.Tag] = true
			continue
		}
		if !handled[op.ID] {
			fail("%s (tag %s) has no handler", op.ID, op.Tag)
		}
	}
	for t := range missing {
		s.unmounted = append(s.unmounted, t)
	}
	sort.Strings(s.unmounted)
	for _, t := range s.unmounted {
		s.log.Info("api tag not mounted: no module contributes it", "tag", t)
	}
	for _, th := range tags {
		if !slices.ContainsFunc(doc.ops, func(o Operation) bool { return o.Tag == th.Tag() }) {
			fail("tag %s is not in the document", th.Tag())
		}
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	sort.Slice(s.rows, func(i, j int) bool { return s.rows[i].OperationID < s.rows[j].OperationID })
	return s, nil
}

// mount registers a route, turning ServeMux's pattern-conflict panic into an error.
func (s *Server) mount(rt Route, host string) (err error) {
	m := rt.Meta()
	if !strings.HasPrefix(m.Path, "/") {
		return fmt.Errorf("path %q is not absolute", m.Path)
	}
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("pattern %s %s conflicts: %v", m.Method, m.Path, r)
		}
	}()
	s.mux.Handle(m.Method+" "+apiPrefix+m.Path, s.routeHandler(rt, host))
	return nil
}

// ServeHTTP is the whole API: recover, trace ID, then the mux. A path or method outside the table
// is a problem, never the mux's plain text and never HTML.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	trace := newTraceID()
	r = r.WithContext(withTrace(r.Context(), trace))
	w.Header().Set("X-Trace-Id", trace)
	defer func() {
		if rec := recover(); rec != nil {
			if rec == http.ErrAbortHandler {
				panic(rec)
			}
			s.log.Error("handler panic", "trace_id", trace, "panic", fmt.Sprint(rec))
			writeProblem(w, r, apitypes.Internal(""), s.log)
		}
	}()
	// A non-canonical path would get the mux's HTML redirect, outside the chain. Refuse it.
	if p := r.URL.Path; p != "" && p != "/" && strings.HasPrefix(p, "/") {
		c := path.Clean(p)
		if strings.HasSuffix(p, "/") && c != "/" {
			c += "/"
		}
		if c != p {
			writeProblem(w, r, apitypes.NotFound(""), s.log)
			return
		}
	}
	h, pattern := s.mux.Handler(r)
	if pattern != "" {
		h.ServeHTTP(w, r)
		return
	}
	probe := &statusProbe{header: http.Header{}}
	h.ServeHTTP(probe, r)
	if probe.status == http.StatusMethodNotAllowed {
		if allow := probe.header.Get("Allow"); allow != "" {
			w.Header().Set("Allow", allow)
		}
		writeProblem(w, r, apitypes.MethodNotAllowed(""), s.log)
		return
	}
	writeProblem(w, r, apitypes.NotFound(""), s.log)
}

// statusProbe captures the mux's own 404/405 so they can be rendered as problems.
type statusProbe struct {
	header http.Header
	status int
}

func (p *statusProbe) Header() http.Header         { return p.header }
func (p *statusProbe) Write(b []byte) (int, error) { return len(b), nil }
func (p *statusProbe) WriteHeader(code int)        { p.status = code }
