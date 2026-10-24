// Package health serves the anonymous platform probes /health/live and /health/ready (AN-1).
//
// The probes are reachable by anyone who can reach the port, so they say nothing about the
// installation (TM §7.6, rules for AN-1): the 200 body is {"status":"ok"} and every failure is a
// problem without a detail member. Why a check failed goes to the server log only.
//
// Cost control (AN-1): an anonymous caller must not be able to drive dependency probes. Each check
// is bounded by a timeout, at most one probe round runs at a time (concurrent callers share it),
// and a finished round's result is reused for a short TTL.
package health

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"sync"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/apihost/apitypes"
	"github.com/skenzeriq/activediq/internal/platform/health/api"
)

const (
	// DefaultCheckTimeout bounds each check. A check that has not answered by then has failed.
	DefaultCheckTimeout = 3 * time.Second
	// DefaultResultTTL is how long a finished round answers further callers without probing again.
	DefaultResultTTL = 2 * time.Second
)

// Check probes one dependency. Its error text is for the log; it never reaches a client.
//
// The error MUST NOT carry secrets: no connection string with a password, token, key or other
// credential. The wiring that builds a Check wraps the driver's errors (which may echo the DSN)
// into a message with the secret removed. As a backstop the log line is run through redact, which
// catches URL userinfo and password/secret/token key=value pairs, but that is not a licence to rely on it.
// A Check should honour ctx; one that does not is abandoned when its timeout fires and is not
// started again until it returns.
type Check func(ctx context.Context) error

// NamedCheck labels a Check for the log.
type NamedCheck struct {
	Name  string
	Check Check
}

// Option configures New.
type Option func(*Handlers)

// WithCheckTimeout sets the per-check timeout (default DefaultCheckTimeout). d <= 0 is ignored.
func WithCheckTimeout(d time.Duration) Option {
	return func(h *Handlers) {
		if d > 0 {
			h.timeout = d
		}
	}
}

// WithResultTTL sets how long a finished round is reused (default DefaultResultTTL). 0 disables reuse;
// concurrent callers still share the round in flight.
func WithResultTTL(d time.Duration) Option {
	return func(h *Handlers) {
		if d >= 0 {
			h.ttl = d
		}
	}
}

// Handlers implements api.Handlers.
type Handlers struct {
	checks  []NamedCheck
	log     *slog.Logger
	timeout time.Duration
	ttl     time.Duration
	now     func() time.Time

	mu      sync.Mutex
	round   *round       // in flight, nil otherwise
	last    bool         // outcome of the last finished round
	lastAt  time.Time    // when it finished; zero before the first round
	running map[int]bool // checks whose probe goroutine has not returned yet
}

type round struct {
	done chan struct{}
	ok   bool
	err  error // a check panicked: answered as 500 /problems/internal
}

var _ api.Handlers = (*Handlers)(nil)

// New builds the handlers. Readiness is ready when every check passes. A nil log uses slog.Default.
func New(log *slog.Logger, checks []NamedCheck, opts ...Option) *Handlers {
	if log == nil {
		log = slog.Default()
	}
	h := &Handlers{checks: checks, log: log, timeout: DefaultCheckTimeout, ttl: DefaultResultTTL, now: time.Now, running: map[int]bool{}}
	for _, o := range opts {
		o(h)
	}
	return h
}

// GetLiveness answers 200 while the process can serve a request.
func (h *Handlers) GetLiveness(context.Context, api.GetLivenessInput) (api.GetLivenessOutput, error) {
	return api.GetLiveness200{Body: api.HealthStatus{Status: api.HealthStateOk}}, nil
}

// GetReadiness answers 200 when every dependency check passes, otherwise 503 /problems/not-ready
// with no detail. Callers share one probe round (see package doc). A check that panics is left to
// apihost's recover: 500 /problems/internal, also without detail, the panic text in the log only.
func (h *Handlers) GetReadiness(ctx context.Context, _ api.GetReadinessInput) (api.GetReadinessOutput, error) {
	ok, err := h.ready(ctx)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, apitypes.NotReady("")
	}
	return api.GetReadiness200{Body: api.HealthStatus{Status: api.HealthStateOk}}, nil
}

func (h *Handlers) ready(ctx context.Context) (bool, error) {
	h.mu.Lock()
	if h.round == nil && !h.lastAt.IsZero() && h.now().Sub(h.lastAt) < h.ttl {
		ok := h.last
		h.mu.Unlock()
		return ok, nil
	}
	r := h.round
	if r == nil {
		r = &round{done: make(chan struct{})}
		h.round = r
		go h.run(r)
	}
	h.mu.Unlock()
	select {
	case <-r.done:
		return r.ok, r.err
	case <-ctx.Done():
		return false, ctx.Err()
	}
}

// run probes every check concurrently, each bounded by the timeout, and publishes the outcome.
// It does not use a caller's context: the round is shared, so no single caller may cancel it.
func (h *Handlers) run(r *round) {
	type result struct {
		name  string
		err   error
		panic bool
	}
	results := make(chan result, len(h.checks))
	var wg sync.WaitGroup
	for i, c := range h.checks {
		h.mu.Lock()
		busy := h.running[i]
		if !busy {
			h.running[i] = true
		}
		h.mu.Unlock()
		if busy { // a previous, abandoned probe of this check has not returned: do not stack another
			results <- result{c.Name, errors.New("previous probe still running"), false}
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			cctx, cancel := context.WithTimeout(context.Background(), h.timeout)
			defer cancel()
			out := make(chan error, 1)
			go func() {
				defer func() {
					h.mu.Lock()
					delete(h.running, i)
					h.mu.Unlock()
				}()
				defer func() {
					if p := recover(); p != nil {
						out <- &panicError{p}
					}
				}()
				out <- c.Check(cctx)
			}()
			select {
			case err := <-out:
				var pe *panicError
				results <- result{c.Name, err, errors.As(err, &pe)}
			case <-cctx.Done():
				results <- result{c.Name, fmt.Errorf("timed out after %s", h.timeout), false}
			}
		}()
	}
	wg.Wait()
	close(results)
	ok := true
	var failure error
	for res := range results {
		if res.err != nil {
			ok = false
			if res.panic {
				failure = errors.New("readiness check panicked")
			}
			h.log.Warn("readiness check failed", "check", res.name, "error", redact(res.err.Error()))
		}
	}
	h.mu.Lock()
	r.ok, r.err = ok, failure
	h.last, h.lastAt, h.round = ok, h.now(), nil
	h.mu.Unlock()
	close(r.done)
}

type panicError struct{ v any }

func (e *panicError) Error() string { return fmt.Sprintf("check panicked: %v", e.v) }

var (
	// scheme://user:pass@host
	reUserinfo = regexp.MustCompile(`(?i)([a-z][a-z0-9+.-]*://[^\s/:@]*):[^\s/@]*@`)
	// password=..., pwd: ..., secret=..., token=..., key=... (value runs to whitespace, ';' or '&')
	reKV = regexp.MustCompile(`(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|sslpassword)(\s*[=:]\s*)('[^']*'|"[^"]*"|[^\s;&,]+)`)
)

// redact removes credentials from error text before it is logged. It is a backstop, not a contract:
// Check errors must already be free of secrets.
func redact(s string) string {
	s = reUserinfo.ReplaceAllString(s, "${1}:[REDACTED]@")
	return reKV.ReplaceAllString(s, "${1}${2}[REDACTED]")
}
