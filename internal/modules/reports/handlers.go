package reports

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"

	"github.com/skenzeriq/activediq/internal/modules/reports/api"
	"github.com/skenzeriq/activediq/internal/modules/reports/export"
	"github.com/skenzeriq/activediq/internal/modules/reports/run"
	"github.com/skenzeriq/activediq/internal/platform/apihost"
	"github.com/skenzeriq/activediq/internal/platform/apihost/apitypes"
	"github.com/skenzeriq/activediq/internal/platform/authn/tenantref"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/httpx"
	"github.com/skenzeriq/activediq/internal/platform/report"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// Handlers implements api.Handlers: the run operations (createReportRun, getReportRun,
// cancelReportRun, retryReportRun, listReportRuns, listReportRunRows). The permission reports.run is
// the route's (apihost enforces it from RouteMeta before a handler runs); what a handler adds is the
// runner binding and the read-scope check, both inside run.Service. The export operations
// (createReportExport, getReportExport, deleteReportExport, downloadReportExport) are the same: the
// permission is the route's, and export.Service owns the creator check and the gate. The other operations
// of the tag answer 501 until their rows land (pending.go).
type Handlers struct {
	pending
	Runs    *run.Service
	Exports *export.Service
	Now     func() time.Time
	Log     *slog.Logger
}

// Bind returns the tag's routes for apihost.Build.
func (h *Handlers) Bind() apihost.TagHandlers { return api.Bind(h) }

func (h *Handlers) now() time.Time {
	if h.Now != nil {
		return h.Now().UTC()
	}
	return time.Now().UTC()
}

func (h *Handlers) log() *slog.Logger {
	if h.Log != nil {
		return h.Log
	}
	return slog.Default()
}

// caller derives the tenant and the authority chain from the authenticated principal, never from the
// request. A token principal is refused at 2a: a token's runs would need the Via chain that scopes them
// to the token (reports.md 6.6 check 4), which the authenticator does not yet hand a handler. Refusing
// is the safe side: a token can neither start a run nor read one.
func (h *Handlers) caller(ctx context.Context) (tenant.ID, authority.Chain, error) {
	var none tenant.ID // the zero tenant accompanies every refusal
	p, ok := apihost.PrincipalFrom(ctx)
	if !ok || p.ID == "" {
		return none, authority.Chain{}, apitypes.Forbidden("")
	}
	if p.Kind == apihost.KindToken {
		return none, authority.Chain{}, apitypes.Forbidden("API tokens cannot use report runs yet; sign in to the console")
	}
	tid, err := tenantref.TenantFromText(p.Tenant)
	if err != nil {
		return none, authority.Chain{}, apitypes.Forbidden("")
	}
	if _, err := apitypes.ParseUUID(p.ID); err != nil {
		return none, authority.Chain{}, apitypes.Forbidden("")
	}
	c := authority.Chain{Requester: authority.Principal{ID: authority.PrincipalID(p.ID), Kind: authority.Human}}
	if err := c.Validate(); err != nil {
		return none, authority.Chain{}, apitypes.Forbidden("")
	}
	return tid, c, nil
}

func runID(u apitypes.UUID) (run.ID, error) { return run.ParseID(u.String()) }

func location(id run.ID) string { return "/api/v1/reports/runs/" + id.String() }

// CreateReportRun implements api.Handlers.
func (h *Handlers) CreateReportRun(ctx context.Context, in api.CreateReportRunInput) (api.CreateReportRunOutput, error) {
	tid, chain, err := h.caller(ctx)
	if err != nil {
		return nil, err
	}
	ci := run.CreateInput{Tenant: tid, Chain: chain, DefinitionID: in.Body.DefinitionID}
	if in.Body.DefinitionVersion != nil {
		ci.Version = int(*in.Body.DefinitionVersion)
	}
	if in.Body.PresetID != nil {
		ci.Preset = *in.Body.PresetID
	}
	if in.Body.Parameters != nil {
		if ci.Params, err = jsonv2.Marshal(*in.Body.Parameters); err != nil {
			return nil, apitypes.Validation("the parameters could not be read")
		}
	}
	r, _, err := h.Runs.Create(ctx, ci)
	if err != nil {
		return nil, h.problem(err)
	}
	return api.CreateReportRun202{Body: runView(r, h.Runs.HiddenGroups(r), h.now()), Location: location(r.ID)}, nil
}

// GetReportRun implements api.Handlers.
func (h *Handlers) GetReportRun(ctx context.Context, in api.GetReportRunInput) (api.GetReportRunOutput, error) {
	tid, chain, err := h.caller(ctx)
	if err != nil {
		return nil, err
	}
	id, err := runID(in.RunID)
	if err != nil {
		return nil, h.problem(run.ErrRunNotFound)
	}
	var got run.Run
	err = h.Runs.Read(ctx, tid, run.OpGet, id, chain, run.ForGet, func(_ context.Context, _ store.Tx, r run.Run) error {
		got = r
		return nil
	})
	if err != nil {
		return nil, h.problem(err)
	}
	return api.GetReportRun200{Body: runView(got, h.Runs.HiddenGroups(got), h.now())}, nil
}

// CancelReportRun implements api.Handlers.
func (h *Handlers) CancelReportRun(ctx context.Context, in api.CancelReportRunInput) (api.CancelReportRunOutput, error) {
	tid, chain, err := h.caller(ctx)
	if err != nil {
		return nil, err
	}
	id, err := runID(in.RunID)
	if err != nil {
		return nil, h.problem(run.ErrRunNotFound)
	}
	r, err := h.Runs.Cancel(ctx, tid, chain, id)
	if err != nil {
		return nil, h.problem(err)
	}
	return api.CancelReportRun200{Body: runView(r, h.Runs.HiddenGroups(r), h.now())}, nil
}

// RetryReportRun implements api.Handlers.
func (h *Handlers) RetryReportRun(ctx context.Context, in api.RetryReportRunInput) (api.RetryReportRunOutput, error) {
	tid, chain, err := h.caller(ctx)
	if err != nil {
		return nil, err
	}
	id, err := runID(in.RunID)
	if err != nil {
		return nil, h.problem(run.ErrRunNotFound)
	}
	r, _, err := h.Runs.Retry(ctx, tid, chain, id)
	if err != nil {
		return nil, h.problem(err)
	}
	return api.RetryReportRun202{Body: runView(r, h.Runs.HiddenGroups(r), h.now()), Location: location(r.ID)}, nil
}

// ListReportRuns implements api.Handlers: the caller's own history, never anyone else's.
func (h *Handlers) ListReportRuns(ctx context.Context, in api.ListReportRunsInput) (api.ListReportRunsOutput, error) {
	tid, chain, err := h.caller(ctx)
	if err != nil {
		return nil, err
	}
	f := run.ListFilter{}
	if in.State != nil {
		f.State = run.State(*in.State)
	}
	if in.DefinitionID != nil {
		f.DefinitionID = *in.DefinitionID
	}
	if in.Limit != nil {
		f.Limit = int(*in.Limit)
	}
	if in.Cursor != nil {
		f.Cursor = string(*in.Cursor)
	}
	items, next, err := h.Runs.List(ctx, tid, chain, f)
	if err != nil {
		return nil, h.problem(err)
	}
	now := h.now()
	out := api.ReportRunList{Items: make([]api.ReportRunSummary, 0, len(items)), Page: apitypes.PageInfo{NextCursor: strp(next)}}
	for _, it := range items {
		out.Items = append(out.Items, summaryView(it, now))
	}
	return api.ListReportRuns200{Body: out}, nil
}

// ListReportRunRows implements api.Handlers: one page of a stored result, read through the one gate.
func (h *Handlers) ListReportRunRows(ctx context.Context, in api.ListReportRunRowsInput) (api.ListReportRunRowsOutput, error) {
	tid, chain, err := h.caller(ctx)
	if err != nil {
		return nil, err
	}
	id, err := runID(in.RunID)
	if err != nil {
		return nil, h.problem(run.ErrRunNotFound)
	}
	pq := run.PageQuery{}
	if in.Cursor != nil {
		pq.Cursor = string(*in.Cursor)
	}
	if in.Limit != nil {
		pq.Limit = int(*in.Limit)
	}
	if in.SortBy != nil {
		pq.SortBy = string(*in.SortBy)
	}
	if in.Order != nil {
		pq.Desc = *in.Order == api.ReportSortOrderDesc
	}
	pg, err := h.Runs.Page(ctx, tid, chain, id, pq)
	if err != nil {
		return nil, h.problem(err)
	}
	body, err := pageView(pg)
	if err != nil {
		h.log().Error("reports: a stored cell could not be rendered", "run", id.String(), "err", err)
		return nil, apitypes.Internal("")
	}
	return api.ListReportRunRows200{Body: body}, nil
}

func exportID(u apitypes.UUID) (export.ID, error) { return export.ParseID(u.String()) }

func exportLocation(id export.ID) string { return "/api/v1/reports/exports/" + id.String() }

// CreateReportExport implements api.Handlers.
func (h *Handlers) CreateReportExport(ctx context.Context, in api.CreateReportExportInput) (api.CreateReportExportOutput, error) {
	tid, chain, err := h.caller(ctx)
	if err != nil {
		return nil, err
	}
	rid, err := runID(in.RunID)
	if err != nil {
		return nil, h.problem(run.ErrRunNotFound)
	}
	e, err := h.Exports.Create(ctx, tid, chain, rid, export.Format(in.Body.Format))
	if err != nil {
		return nil, h.problem(err)
	}
	return api.CreateReportExport202{Body: exportView(e, h.now()), Location: exportLocation(e.ID)}, nil
}

// GetReportExport implements api.Handlers.
func (h *Handlers) GetReportExport(ctx context.Context, in api.GetReportExportInput) (api.GetReportExportOutput, error) {
	tid, chain, err := h.caller(ctx)
	if err != nil {
		return nil, err
	}
	id, err := exportID(in.ExportID)
	if err != nil {
		return nil, h.problem(export.ErrExportNotFound)
	}
	e, err := h.Exports.Get(ctx, tid, chain, id)
	if err != nil {
		return nil, h.problem(err)
	}
	return api.GetReportExport200{Body: exportView(e, h.now())}, nil
}

// DeleteReportExport implements api.Handlers.
func (h *Handlers) DeleteReportExport(ctx context.Context, in api.DeleteReportExportInput) (api.DeleteReportExportOutput, error) {
	tid, chain, err := h.caller(ctx)
	if err != nil {
		return nil, err
	}
	id, err := exportID(in.ExportID)
	if err != nil {
		return nil, h.problem(export.ErrExportNotFound)
	}
	if err := h.Exports.Delete(ctx, tid, chain, id); err != nil {
		return nil, h.problem(err)
	}
	return api.DeleteReportExport204{}, nil
}

// DownloadReportExport implements api.Handlers: the creator's file, through the one gate. The headers come
// from httpx.Headers (apihost.Stream.FileFormat), never from this package.
func (h *Handlers) DownloadReportExport(ctx context.Context, in api.DownloadReportExportInput) (api.DownloadReportExportOutput, error) {
	tid, chain, err := h.caller(ctx)
	if err != nil {
		return nil, err
	}
	id, err := exportID(in.ExportID)
	if err != nil {
		return nil, h.problem(export.ErrExportNotFound)
	}
	d, err := h.Exports.Download(ctx, tid, chain, id)
	if err != nil {
		return nil, h.problem(err)
	}
	ff := httpx.CSV
	if d.Format == export.XLSX {
		ff = httpx.XLSX
	}
	return api.DownloadReportExport200{Body: apihost.Stream{Reader: d.Reader, FileBase: d.Base, FileFormat: ff}}, nil
}

// coded adds the machine-readable errors[].code a client branches on. The detail is fixed text.
func coded(p *apitypes.Problem, in, pointer, code, detail string) *apitypes.Problem {
	var e apitypes.Errors
	e.Add(in, jsonPointer(pointer), code, detail)
	return p.WithErrors(&e)
}

// problem maps a run-path error to its Problem. No message carries a request value, an object name
// or the text of the underlying error.
func (h *Handlers) problem(err error) error {
	var failed *run.FailedError
	var ve report.ValidationError
	var capErr *export.CapError
	switch {
	case errors.As(err, &capErr):
		return coded(apitypes.ReportRowCapExceeded(capErr.Error()), apitypes.InBody, "format", "row_cap_exceeded", "")
	case errors.Is(err, export.ErrExportNotFound):
		return coded(apitypes.NotFound("no such export"), apitypes.InPath, "exportId", "export_not_found", "")
	case errors.Is(err, export.ErrFormatUnavailable):
		return coded(apitypes.Validation("that export format is not available"), apitypes.InBody, "format", "format_unavailable", "")
	case errors.Is(err, export.ErrExportNotReady):
		return coded(apitypes.Conflict("the export file is not ready"), apitypes.InPath, "exportId", "export_not_ready", "")
	case errors.Is(err, export.ErrExportInProgress):
		return coded(apitypes.Conflict("the export is still queued or running"), apitypes.InPath, "exportId", "export_in_progress", "")
	case errors.Is(err, export.ErrExportExpired):
		return apitypes.ReportResultExpired("the export file has expired; export the report again")
	case errors.Is(err, export.ErrNotPermitted):
		return apitypes.Forbidden("")
	case errors.Is(err, export.ErrDenialNotRecorded):
		return apitypes.NotReady("the request could not be recorded; try again shortly")
	case errors.Is(err, export.ErrExportUnavailable):
		return apitypes.NotReady("exports are not available until a file store is configured for this installation")
	case errors.As(err, &failed):
		return coded(apitypes.Conflict("the run did not produce a result"), apitypes.InBody, "", "run_failed", string(failed.Reason)+" ("+string(failed.State)+")")
	case errors.As(err, &ve):
		return coded(apitypes.Validation("the report parameters were refused"), apitypes.InBody, "parameters."+ve.Path, string(ve.Code), "")
	case errors.Is(err, run.ErrRunNotFound):
		return coded(apitypes.NotFound("no such report run"), apitypes.InPath, "runId", "run_not_found", "")
	case errors.Is(err, run.ErrDefinitionUnknown):
		return coded(apitypes.NotFound("no such report"), apitypes.InBody, "definitionId", "definition_not_found", "")
	case errors.Is(err, run.ErrRunExpired):
		return apitypes.ReportResultExpired("the stored result has expired; run the report again")
	case errors.Is(err, run.ErrScopeChanged):
		return coded(apitypes.Conflict("your access has changed since this run; run the report again"), apitypes.InPath, "runId", "scope_changed_rerun", "")
	case errors.Is(err, run.ErrRunNotReady):
		return coded(apitypes.Conflict("the run has not finished"), apitypes.InPath, "runId", "run_not_ready", "")
	case errors.Is(err, run.ErrRunInProgress):
		return coded(apitypes.Conflict("the run is still queued or running"), apitypes.InPath, "runId", "run_in_progress", "")
	case errors.Is(err, run.ErrNotCancellable):
		return coded(apitypes.Conflict("the run has already finished"), apitypes.InPath, "runId", "run_finished", "")
	case errors.Is(err, run.ErrTooManyJobs):
		return coded(apitypes.RateLimited("this tenant already has the most report jobs it can run at once; try again when one finishes"), apitypes.InBody, "", "too_many_report_jobs", "")
	case errors.Is(err, run.ErrBadCursor):
		return coded(apitypes.Validation("the cursor is not valid for this run and sort"), apitypes.InQuery, "cursor", "bad_cursor", "")
	case errors.Is(err, run.ErrBadSort):
		return coded(apitypes.Validation("the result cannot be sorted by that column"), apitypes.InQuery, "sortBy", "bad_sort", "")
	case errors.Is(err, run.ErrBadLimit):
		return coded(apitypes.Validation("the page size is out of range"), apitypes.InQuery, "limit", "bad_limit", "")
	case errors.Is(err, run.ErrScopesUnavailable):
		return apitypes.NotReady("reports are not available until access scopes are configured for this installation")
	case errors.Is(err, run.ErrOwnerDead), errors.Is(err, run.ErrTokenRefused):
		return apitypes.Forbidden("")
	}
	h.log().Error("reports: run operation failed", "err", err)
	return apitypes.Internal("")
}

func jsonPointer(s string) jsontext.Pointer { return jsontext.Pointer(s) }
