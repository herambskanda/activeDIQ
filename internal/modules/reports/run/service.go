package run

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/audit/chain"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/jobs"
	"github.com/skenzeriq/activediq/internal/platform/report"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/reportsql"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// Errors the handlers map to Problems. None carries a request value.
var (
	ErrRunNotFound       = errors.New("run: no such run")                      // 404 run_not_found
	ErrRunExpired        = errors.New("run: the result has expired")           // 410 report-result-expired
	ErrScopeChanged      = errors.New("run: read scope changed since the run") // 409 scope_changed_rerun
	ErrRunNotReady       = errors.New("run: the run has not finished")         // 409 run_not_ready
	ErrRunInProgress     = errors.New("run: the run is queued or running")     // 409 run_in_progress
	ErrTooManyJobs       = errors.New("run: too many report jobs")             // 429 too_many_report_jobs
	ErrDefinitionUnknown = errors.New("run: unknown report definition")        // 404
	ErrNotCancellable    = errors.New("run: the run is already finished")      // 409
	ErrScopesUnavailable = errors.New("run: no read-scope producer is configured") // 503 not-ready
	ErrOwnerDead         = authz.ErrOwnerDead
	ErrTokenRefused      = authz.ErrTokenRefused
)

// FailedError is a page read of a failed or cancelled run (409 run_failed with the reason).
type FailedError struct {
	State  State
	Reason FailureReason
}

func (e *FailedError) Error() string { return "run: the run " + string(e.State) }

// Audit kinds of the run path (reports.md §10).
const (
	KindCompleted  audit.Kind = "reports.run.completed"
	KindFailed     audit.Kind = "reports.run.failed"
	KindReadDenied audit.Kind = "reports.run.read_denied"
)

// Component is the audit component of every event here.
const Component = "reports"

// Limits (spec §8.1, §8.3; [PROPOSED] values to confirm on the scale tier).
const (
	ReuseWindow     = 60 * time.Second
	OpenRunLimit    = 4
	DefaultRowCap   = 1_000_000
	ResultRetention = 7 * 24 * time.Hour
	RecordRetention = 30 * 24 * time.Hour
	BatchSize       = 2000
	JobTimeout      = 30 * time.Minute
	JobKind         = "reports.run"
	RetentionKind   = "reports.retention"
	MaxPageSize     = 500
	DefaultPageSize = 100
)

// Perm is the permission a run reads under.
const Perm authz.Permission = "reports.run"

// ReadScopes produces the caller's read scope; *rbac.ReadScopes implements it.
type ReadScopes interface {
	For(ctx context.Context, tx store.Tx, t tenant.ID, chain authority.Chain, perm authz.Permission) (authz.ReadScope, error)
}

// Definition is a catalogue entry: the definition, the SHA-256 of the shipped file, and the dataset in
// both forms (the AST that Resolve checks, and the registered SQL form that Compile renders).
type Definition struct {
	Def     report.Definition
	SHA256  [32]byte
	Dataset report.Dataset
	SQL     reportsql.Dataset
}

// Catalog finds definitions. Version 0 means the newest. The library (B5) implements it.
type Catalog interface {
	Definition(id string, version int) (Definition, bool)
}

// ParamsCodec turns the stored request parameters (API shape) into typed run parameters. The module
// supplies it, so this package never imports the API package.
type ParamsCodec interface {
	Decode(raw json.RawMessage, def report.Definition) (report.RunParams, error)
}

// FreshnessSource reads the sync watermarks of the connections a result covers (§6.4). It runs its own
// short transaction, which is why it is read before the result cursor opens.
type FreshnessSource interface {
	Freshness(ctx context.Context, tid tenant.ID, connections []authz.ObjectID, now time.Time) (report.Freshness, time.Duration, error)
}

// Service is the run path. Every field is required except Now and RowCap.
type Service struct {
	DB      *store.DB
	Jobs    *jobs.Registry
	Scopes  ReadScopes
	Audit   audit.Sink
	Catalog Catalog
	Codec   ParamsCodec
	Fresh   FreshnessSource
	Now     func() time.Time
	RowCap  int
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

func (s *Service) rowCap() int {
	if s.RowCap > 0 {
		return s.RowCap
	}
	return DefaultRowCap
}

// CreateInput is one request to run a report.
type CreateInput struct {
	Tenant       tenant.ID
	Chain        authority.Chain
	DefinitionID string
	Version      int // 0: the newest
	Preset       string
	Params       json.RawMessage // API-shape parameters; nil is "none"
	RerunOf      *ID
}

// Create starts a run, or returns the identical one created in the last ReuseWindow (§6.1).
func (s *Service) Create(ctx context.Context, in CreateInput) (run Run, reused bool, err error) {
	def, ok := s.Catalog.Definition(in.DefinitionID, in.Version)
	if !ok {
		return Run{}, false, ErrDefinitionUnknown
	}
	preset := in.Preset
	if preset == "" {
		preset = def.Def.Presets[0].ID
	}
	raw := in.Params
	if len(raw) == 0 {
		raw = json.RawMessage(`{}`)
	}
	rp, err := s.Codec.Decode(raw, def.Def)
	if err != nil {
		return Run{}, false, err
	}
	q, err := report.Resolve(def.Def, preset, rp, def.Dataset)
	if err != nil {
		return Run{}, false, err
	}
	chainJSON, err := encodeChain(in.Chain)
	if err != nil {
		return Run{}, false, err
	}
	cols, _ := json.Marshal(columnIDs(q.Columns))
	qh := q.Hash()
	err = s.DB.WithTenant(ctx, in.Tenant, func(ctx context.Context, tx store.Tx) error {
		scope, err := s.Scopes.For(ctx, tx, in.Tenant, in.Chain, Perm)
		if err != nil {
			return err
		}
		fp := scope.Fingerprint()
		// One create at a time per tenant: the reuse lookup and the cap are only true under this lock.
		if _, err := tx.Exec(ctx, lockTenantJobs); err != nil {
			return err
		}
		var existing string
		switch err := tx.QueryRow(ctx, findReusable, string(in.Chain.Requester.ID), qh[:], fp[:], ReuseWindow.Seconds()).Scan(&existing); {
		case err == nil:
			id, err := ParseID(existing)
			if err != nil {
				return err
			}
			if run, err = load(ctx, tx, id, false); err != nil {
				return err
			}
			reused = true
			return nil
		case !isNoRows(err):
			return err
		}
		var open int
		if err := tx.QueryRow(ctx, countOpen).Scan(&open); err != nil {
			return err
		}
		if open >= OpenRunLimit {
			return ErrTooManyJobs
		}
		id := NewID()
		var rerun *string
		if in.RerunOf != nil {
			x := in.RerunOf.String()
			rerun = &x
		}
		if _, err := tx.Exec(ctx, insertRun, id.String(), in.DefinitionID, def.Def.Version, def.SHA256[:], preset, string(raw),
			qh[:], fp[:], string(in.Chain.Requester.ID), string(chainJSON), rerun, string(cols)); err != nil {
			return err
		}
		if _, err := s.Jobs.Enqueue(ctx, tx, jobs.Job{Kind: JobKind, Tenant: in.Tenant, Args: jobArgs{RunID: id.String()}, UniqueKey: id.String()}); err != nil {
			return err
		}
		run, err = load(ctx, tx, id, false)
		return err
	})
	return run, reused, err
}

type jobArgs struct {
	RunID string `json:"run_id"`
}

func columnIDs(cs []report.ColumnID) []string {
	out := make([]string, len(cs))
	for i, c := range cs {
		out[i] = string(c)
	}
	return out
}

// Get returns a run for its runner without any read-scope check: checks 1–2 of §6.6 (retry, cancel).
func (s *Service) get(ctx context.Context, tx store.Tx, id ID, chain authority.Chain) (Run, error) {
	r, err := load(ctx, tx, id, false)
	if err != nil {
		return Run{}, err
	}
	if r.Runner != string(chain.Requester.ID) {
		return Run{}, ErrRunNotFound
	}
	return r, nil
}

// Check is a subset of the checks of §6.6 after the existence check, which always runs.
type Check uint8

// The checks. Check 1 (the permission) is the route's.
const (
	CheckNotExpired Check = 1 << iota // 3: pages only
	CheckScope                        // 4
	CheckSucceeded                    // 5: pages, export create
)

// Named sets: run GET runs 1, 2 and 4; pages run all.
const (
	ForGet  = CheckScope
	ForPage = CheckNotExpired | CheckScope | CheckSucceeded
)

// denial is a refusal of ReadAccess that the caller must record. ReadAccess runs inside the caller's
// transaction, where the audit event cannot be appended in a transaction of its own (nested tenant
// transactions are refused), so Read records it after that transaction ends.
type denial struct {
	err   error
	check string
}

func (d *denial) Error() string { return d.err.Error() }
func (d *denial) Unwrap() error { return d.err }

// ReadAccess is the one gate every run read goes through (§6.6). It is pure: it reads the record and the
// caller's scope in tx and returns the refusal. A refusal at check 2, 3 or 4 is a *denial; use Read, which
// appends reports.run.read_denied once the transaction has ended, so the refusal is recorded even though
// the caller's transaction rolls back or only reads. Callers outside this package go through Read.
func (s *Service) ReadAccess(ctx context.Context, tx store.Tx, tid tenant.ID, id ID, chain authority.Chain, checks Check) (Run, error) {
	r, err := s.get(ctx, tx, id, chain)
	if errors.Is(err, ErrRunNotFound) {
		return Run{}, &denial{ErrRunNotFound, "exists"}
	}
	if err != nil {
		return Run{}, err
	}
	if checks&CheckNotExpired != 0 && (r.State == StateExpired || (r.State == StateSucceeded && r.ExpiresAt != nil && !r.ExpiresAt.After(s.now()))) {
		return r, &denial{ErrRunExpired, "expired"}
	}
	if checks&CheckScope != 0 {
		scope, err := s.Scopes.For(ctx, tx, tid, chain, Perm)
		if err != nil {
			return Run{}, err
		}
		if fp := scope.Fingerprint(); fp != r.ScopeFingerprint {
			return Run{}, &denial{ErrScopeChanged, "scope"}
		}
	}
	if checks&CheckSucceeded != 0 {
		switch r.State {
		case StateSucceeded:
		case StateFailed, StateCancelled:
			return r, &FailedError{State: r.State, Reason: r.Failure}
		case StateExpired:
			return r, ErrRunExpired
		default:
			return r, ErrRunNotReady
		}
	}
	return r, nil
}

// Read opens the tenant transaction, passes the §6.6 gate and runs fn on the run in the same
// transaction (so the rows read are the rows the gate cleared). A refusal is audited as read_denied
// after the transaction ends and returned as its sentinel error.
func (s *Service) Read(ctx context.Context, tid tenant.ID, id ID, chain authority.Chain, checks Check, fn func(ctx context.Context, tx store.Tx, r Run) error) error {
	err := s.DB.WithTenant(ctx, tid, func(ctx context.Context, tx store.Tx) error {
		r, err := s.ReadAccess(ctx, tx, tid, id, chain, checks)
		if err != nil {
			return err
		}
		if fn == nil {
			return nil
		}
		return fn(ctx, tx, r)
	})
	var den *denial
	if errors.As(err, &den) {
		s.denied(ctx, tid, chain, id, den.check)
		return den.err
	}
	return err
}

func (s *Service) denied(ctx context.Context, tid tenant.ID, c authority.Chain, id ID, check string) {
	if c.Validate() != nil {
		return
	}
	_ = s.DB.WithTenant(ctx, tid, func(ctx context.Context, tx store.Tx) error {
		return s.Audit.Append(ctx, tx, audit.Event{
			ID: "run:" + id.String() + ":read_denied:" + randomSuffix(), Kind: KindReadDenied, At: s.now(), Actor: c,
			Target: authority.TargetRef{GUID: id.String(), Class: "report_run"}, Component: Component, Outcome: audit.Denied,
			Reason: check, Details: []chain.Detail{{Key: "check", Value: check}, {Key: "run_id", Value: id.String()}},
		})
	})
}

// Retry takes the §6.1 create path again from a finished run, under the caller's current scope. It runs
// checks 1 and 2 only; a queued or running source is ErrRunInProgress.
func (s *Service) Retry(ctx context.Context, tid tenant.ID, chain authority.Chain, id ID) (Run, bool, error) {
	var src Run
	err := s.DB.WithTenant(ctx, tid, func(ctx context.Context, tx store.Tx) (err error) {
		src, err = s.get(ctx, tx, id, chain)
		return err
	})
	if err != nil {
		if errors.Is(err, ErrRunNotFound) {
			s.denied(ctx, tid, chain, id, "exists")
		}
		return Run{}, false, err
	}
	if src.State == StateQueued || src.State == StateRunning {
		return Run{}, false, ErrRunInProgress
	}
	return s.Create(ctx, CreateInput{Tenant: tid, Chain: chain, DefinitionID: src.DefinitionID, Version: src.DefinitionVer,
		Preset: src.Preset, Params: src.Params, RerunOf: &src.ID})
}

// Cancel stops a queued or running run of the caller's: the record goes to cancelled and any rows are
// deleted, in this order (the row trigger refuses a delete while the run is live).
func (s *Service) Cancel(ctx context.Context, tid tenant.ID, chain authority.Chain, id ID) (Run, error) {
	var out Run
	err := s.DB.WithTenant(ctx, tid, func(ctx context.Context, tx store.Tx) error {
		if _, err := s.get(ctx, tx, id, chain); err != nil {
			return err
		}
		r, err := load(ctx, tx, id, true)
		if err != nil {
			return err
		}
		if !r.State.CanMoveTo(StateCancelled) {
			out = r
			return ErrNotCancellable
		}
		if err := s.finish(ctx, tx, r, StateCancelled, "", nil); err != nil {
			return err
		}
		out, err = load(ctx, tx, id, false)
		return err
	})
	if errors.Is(err, ErrRunNotFound) {
		s.denied(ctx, tid, chain, id, "exists")
	}
	return out, err
}

const finishRun = `UPDATE public.report_runs SET state = $2, failure_reason = $3, finished_at = $4, expires_at = $5,
  scope_applied = COALESCE($6::jsonb, scope_applied)
WHERE id = $1::uuid AND state = $7`

const deleteRows = `DELETE FROM public.report_run_rows WHERE run_id = $1::uuid`

// finish moves a live run (queued or running, locked by the caller) to failed or cancelled, deletes its
// rows and appends the failed event. The state is set first: the row trigger allows a delete only then.
func (s *Service) finish(ctx context.Context, tx store.Tx, r Run, to State, reason FailureReason, detail map[string]int64) error {
	now := s.now()
	var fr *string
	if reason != "" {
		x := string(reason)
		fr = &x
	}
	var doc *string
	if len(detail) > 0 {
		sa := r.ScopeApplied
		sa.Detail = detail
		b, _ := json.Marshal(sa)
		x := string(b)
		doc = &x
	}
	tag, err := tx.Exec(ctx, finishRun, r.ID.String(), string(to), fr, now, now.Add(ResultRetention), doc, string(r.State))
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrNotCancellable
	}
	if _, err := tx.Exec(ctx, deleteRows, r.ID.String()); err != nil {
		return err
	}
	why := string(reason)
	if to == StateCancelled {
		why = "cancelled"
	}
	det := []chain.Detail{{Key: "definition", Value: r.DefinitionID + "@" + strconv.Itoa(r.DefinitionVer)}, {Key: "preset", Value: r.Preset},
		{Key: "run_id", Value: r.ID.String()}}
	for _, k := range sortedKeys(detail) {
		det = append(det, chain.Detail{Key: "x_" + k, Value: strconv.FormatInt(detail[k], 10)})
	}
	return s.Audit.Append(ctx, tx, audit.Event{ID: "run:" + r.ID.String() + ":failed", Kind: KindFailed, At: now, Actor: r.Chain,
		Target: authority.TargetRef{GUID: r.ID.String(), Class: "report_run"}, Component: Component, Outcome: audit.Failure,
		Reason: why, Details: sortDetails(det)})
}

func (s *Service) String() string { return fmt.Sprintf("run.Service(cap=%d)", s.rowCap()) }
