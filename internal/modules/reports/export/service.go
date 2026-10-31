package export

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/skenzeriq/activediq/internal/modules/reports/run"
	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/audit/chain"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/blob"
	"github.com/skenzeriq/activediq/internal/platform/jobs"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// Errors the handlers map to Problems. None carries a request value.
var (
	ErrExportNotFound    = errors.New("export: no such export")                  // 404 export_not_found
	ErrFormatUnavailable = errors.New("export: that format is not available")    // 400 format_unavailable
	ErrExportNotReady    = errors.New("export: the file is not ready")           // 409 export_not_ready
	ErrExportInProgress  = errors.New("export: the export is queued or running") // 409 export_in_progress
	ErrExportExpired     = errors.New("export: the file has expired")            // 410 report-result-expired
	ErrExportUnavailable = errors.New("export: no blob store is configured")     // 503 not-ready
)

// CapError is an export refused for its size (FR-18): the row count, the format's cap and the formats that
// would take the result. Nothing is written when it is returned: no row, no job, no file.
type CapError struct {
	Format       Format
	Rows, Cap    int64
	Alternatives []Format
}

func (e *CapError) Error() string {
	msg := fmt.Sprintf("This export has %d rows. %s allows %d. Narrow the filters", e.Rows, strings.ToUpper(string(e.Format)), e.Cap)
	if len(e.Alternatives) > 0 {
		alt := make([]string, len(e.Alternatives))
		for i, f := range e.Alternatives {
			alt[i] = strings.ToUpper(string(f))
		}
		msg += " or use " + strings.Join(alt, " or ")
	}
	return msg + "."
}

// Audit kinds of the export path (reports.md §10). reports.export.expired is the retention sweep's
// (run.KindExportExpired).
const (
	KindCreated        audit.Kind = "reports.export.created"
	KindDownloaded     audit.Kind = "reports.export.downloaded"
	KindDownloadDenied audit.Kind = "reports.export.download_denied"
	KindDeleted        audit.Kind = "reports.export.deleted"
	KindFailed         audit.Kind = "reports.export.failed"
)

// Limits.
const (
	// DefaultCap is the most rows a CSV or XLSX export holds. Configuration may only lower it (FR-18).
	DefaultCap = 1_000_000
	// JobKind is the reports.export job kind (EP-5), registered by the composition root.
	JobKind = "reports.export"
	// JobTimeout bounds one attempt of the job.
	JobTimeout = 30 * time.Minute
	// PollEvery is how long an export waits before it looks at a still-running source run again, and
	// MaxPolls how many times it does (about 40 minutes).
	PollEvery = 5 * time.Second
	MaxPolls  = 480
)

// Component is the audit component of every event here.
const Component = "reports"

const targetClass = "report_export"

// Service is the export path. DB, Jobs, Runs, Blob and Audit are required; Now, Caps and Log are optional.
type Service struct {
	DB    *store.DB
	Jobs  *jobs.Registry
	Runs  *run.Service
	Blob  blob.Store
	Audit audit.Sink
	Now   func() time.Time
	// Caps lowers the row cap of a format below DefaultCap. A value above it, or zero, is ignored.
	Caps map[Format]int64
	Log  *slog.Logger
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

func (s *Service) log() *slog.Logger {
	if s.Log != nil {
		return s.Log
	}
	return slog.Default()
}

// Cap is the row cap of f: the hard cap, or the configured one when that is lower.
func (s *Service) Cap(f Format) int64 {
	if c, ok := s.Caps[f]; ok && c > 0 && c < DefaultCap {
		return c
	}
	return DefaultCap
}

// capCheck refuses a result over the cap of f, naming the formats that would take it.
func (s *Service) capCheck(f Format, rows int64) error {
	if rows <= s.Cap(f) {
		return nil
	}
	ce := &CapError{Format: f, Rows: rows, Cap: s.Cap(f)}
	for _, other := range Formats() {
		if other != f && rows <= s.Cap(other) {
			ce.Alternatives = append(ce.Alternatives, other)
		}
	}
	return ce
}

func hexOf(b []byte) string { return hex.EncodeToString(b) }

func randomSuffix() string {
	var b [6]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func sortDetails(d []chain.Detail) []chain.Detail {
	slices.SortFunc(d, func(a, b chain.Detail) int { return strings.Compare(a.Key, b.Key) })
	return d
}

func (s *Service) ready() error {
	if s.Blob == nil {
		return ErrExportUnavailable
	}
	return nil
}

type jobArgs struct {
	ExportID string `json:"export_id"`
	// Poll counts how many times the export has waited for its source run.
	Poll int `json:"poll,omitempty"`
}

func blobKey(id ID, f Format) string { return "reports/exports/" + id.String() + "." + f.Ext() }

// Create starts an export of run rid in format f (spec §8.3). The source must be the caller's own, finished
// and readable under their current scope (the one gate, run.Service.Read). A source whose result expired is
// run again as the caller and the export follows the new run (rerun). A result over the format's cap is
// refused here, before any record, job or file exists.
func (s *Service) Create(ctx context.Context, tid tenant.ID, c authority.Chain, rid run.ID, f Format) (Export, error) {
	if err := s.ready(); err != nil {
		return Export{}, err
	}
	if !slices.Contains(Formats(), f) {
		return Export{}, ErrFormatUnavailable
	}
	var src run.Run
	if err := s.Runs.Read(ctx, tid, rid, c, 0, func(_ context.Context, _ store.Tx, r run.Run) error {
		src = r
		return nil
	}); err != nil {
		return Export{}, err
	}
	now := s.now()
	if src.State == run.StateExpired || (src.State == run.StateSucceeded && src.ExpiresAt != nil && !src.ExpiresAt.After(now)) {
		return s.createRerun(ctx, tid, c, src, f)
	}
	var out Export
	err := s.Runs.Read(ctx, tid, rid, c, run.CheckScope|run.CheckSucceeded, func(ctx context.Context, tx store.Tx, r run.Run) (err error) {
		if r.ExpiresAt == nil || !r.ExpiresAt.After(now) {
			return run.ErrRunExpired // expired between the two reads
		}
		out, err = s.insert(ctx, tx, tid, c, r, f, nil)
		return err
	})
	return out, err
}

// createRerun runs the expired source again as the caller (under their scope now) and binds the export to
// the new run. The new run may still be running: the job waits for it.
func (s *Service) createRerun(ctx context.Context, tid tenant.ID, c authority.Chain, src run.Run, f Format) (Export, error) {
	nr, _, err := s.Runs.Retry(ctx, tid, c, src.ID)
	if err != nil {
		return Export{}, err
	}
	var out Export
	err = s.DB.WithTenant(ctx, tid, func(ctx context.Context, tx store.Tx) (err error) {
		out, err = s.insert(ctx, tx, tid, c, nr, f, &src.ID)
		return err
	})
	return out, err
}

const insertExport = `INSERT INTO public.report_exports
  (tenant_id, id, run_id, rerun, rerun_of_run_id, format, state, created_by, chain, row_count, digest, blob_key, expires_at)
VALUES (NULLIF(current_setting('app.tenant_id', true), '')::uuid, $1::uuid, $2::uuid, $3, $4::uuid, $5, 'queued', $6::uuid, $7::jsonb,
  $8, $9, $10, $11)`

// insert is the one write of Create: cap check, job limit, record, job and audit event, in the caller's
// transaction, so they commit together or not at all.
func (s *Service) insert(ctx context.Context, tx store.Tx, tid tenant.ID, c authority.Chain, r run.Run, f Format, rerunOf *run.ID) (Export, error) {
	now := s.now()
	var rows *int64
	var digest []byte
	expires := now.Add(run.ResultRetention)
	if r.State == run.StateSucceeded {
		if r.RowCount == nil || r.ExpiresAt == nil {
			return Export{}, errors.New("export: a succeeded run has no row count")
		}
		if err := s.capCheck(f, *r.RowCount); err != nil {
			return Export{}, err
		}
		rows, digest, expires = r.RowCount, r.Digest, *r.ExpiresAt
	}
	if err := s.Runs.LockJobs(ctx, tx); err != nil {
		return Export{}, err
	}
	if err := s.Runs.CheckJobLimit(ctx, tx); err != nil {
		return Export{}, err
	}
	chainJSON, err := encodeChain(c)
	if err != nil {
		return Export{}, err
	}
	id := NewID()
	var ro *string
	if rerunOf != nil {
		x := rerunOf.String()
		ro = &x
	}
	if _, err := tx.Exec(ctx, insertExport, id.String(), r.ID.String(), rerunOf != nil, ro, string(f), string(c.Requester.ID), string(chainJSON),
		rows, digest, blobKey(id, f), expires); err != nil {
		return Export{}, err
	}
	if _, err := s.Jobs.Enqueue(ctx, tx, jobs.Job{Kind: JobKind, Tenant: tid, Args: jobArgs{ExportID: id.String()}, UniqueKey: id.String()}); err != nil {
		return Export{}, err
	}
	det := []chain.Detail{
		{Key: "definition", Value: r.DefinitionID + "@" + strconv.Itoa(r.DefinitionVer)},
		{Key: "export_id", Value: id.String()},
		{Key: "format", Value: string(f)},
		{Key: "preset", Value: r.Preset},
		{Key: "rerun", Value: strconv.FormatBool(rerunOf != nil)},
		{Key: "run_id", Value: r.ID.String()},
	}
	if rows != nil {
		det = append(det, chain.Detail{Key: "row_count", Value: strconv.FormatInt(*rows, 10)}, chain.Detail{Key: "digest", Value: hexOf(digest)})
	}
	if err := s.Audit.Append(ctx, tx, audit.Event{ID: "export:" + id.String() + ":created", Kind: KindCreated, At: now, Actor: c,
		Target: authority.TargetRef{GUID: id.String(), Class: targetClass}, Component: Component, Outcome: audit.Success, Details: sortDetails(det)}); err != nil {
		return Export{}, err
	}
	return load(ctx, tx, id, false)
}

// Get returns the caller's own export. Anyone else's is not found. An export whose file is past its
// expiry reads as expired whether or not the sweep has flipped it yet.
func (s *Service) Get(ctx context.Context, tid tenant.ID, c authority.Chain, id ID) (Export, error) {
	var e Export
	err := s.DB.WithTenant(ctx, tid, func(ctx context.Context, tx store.Tx) (err error) {
		e, err = load(ctx, tx, id, false)
		if err != nil {
			return err
		}
		if e.CreatedBy != string(c.Requester.ID) {
			return ErrExportNotFound
		}
		if e.Expired(s.now()) {
			e.State = StateExpired
		}
		return nil
	})
	return e, err
}

const deleteExport = `UPDATE public.report_exports SET state = 'deleted', finished_at = COALESCE(finished_at, $2) WHERE id = $1::uuid AND state = 'succeeded'`

// Delete removes the caller's own finished export early: the record goes to deleted, the file is deleted
// and reports.export.deleted is audited. A queued or running export is ErrExportInProgress. An export that
// holds no file already (failed, expired, deleted) is a no-op.
func (s *Service) Delete(ctx context.Context, tid tenant.ID, c authority.Chain, id ID) error {
	if err := s.ready(); err != nil {
		return err
	}
	var e Export
	deleted := false
	err := s.DB.WithTenant(ctx, tid, func(ctx context.Context, tx store.Tx) error {
		var err error
		if e, err = load(ctx, tx, id, true); err != nil {
			return err
		}
		if e.CreatedBy != string(c.Requester.ID) {
			return ErrExportNotFound
		}
		switch {
		case e.State == StateQueued || e.State == StateRunning:
			return ErrExportInProgress
		case e.State != StateSucceeded || e.Expired(s.now()):
			return nil
		}
		now := s.now()
		if _, err := tx.Exec(ctx, deleteExport, id.String(), now); err != nil {
			return err
		}
		deleted = true
		return s.Audit.Append(ctx, tx, audit.Event{ID: "export:" + id.String() + ":deleted", Kind: KindDeleted, At: now, Actor: c,
			Target: authority.TargetRef{GUID: id.String(), Class: targetClass}, Component: Component, Outcome: audit.Success,
			Details: sortDetails(s.fileDetails(e))})
	})
	if err != nil || !deleted {
		return err
	}
	if err := s.Blob.Delete(ctx, tid, e.BlobKey); err != nil {
		// The record says deleted, so no download is served; the file goes with the next expiry sweep.
		s.log().Error("reports: an export file could not be deleted", "export", id.String(), "err", err)
	}
	return nil
}

func (s *Service) fileDetails(e Export) []chain.Detail {
	det := []chain.Detail{{Key: "export_id", Value: e.ID.String()}, {Key: "format", Value: string(e.Format)}, {Key: "run_id", Value: e.RunID.String()}}
	if e.RowCount != nil {
		det = append(det, chain.Detail{Key: "row_count", Value: strconv.FormatInt(*e.RowCount, 10)})
	}
	if e.Digest != nil {
		det = append(det, chain.Detail{Key: "digest", Value: hexOf(e.Digest)})
	}
	return det
}

// Download is an opened export file. The caller closes Reader.
type Download struct {
	Reader io.ReadCloser
	// Base is the file name without its extension; Format says which extension and media type.
	Base   string
	Format Format
}

// denied records a refused download. Like run.Service.Read it runs after the reading transaction has
// ended: a transaction cannot open another, and the refusal must be recorded though the read rolled back.
func (s *Service) denied(ctx context.Context, tid tenant.ID, c authority.Chain, id ID, check string) {
	if c.Validate() != nil {
		return
	}
	err := s.DB.WithTenant(ctx, tid, func(ctx context.Context, tx store.Tx) error {
		return s.Audit.Append(ctx, tx, audit.Event{ID: "export:" + id.String() + ":download_denied:" + randomSuffix(), Kind: KindDownloadDenied,
			At: s.now(), Actor: c, Target: authority.TargetRef{GUID: id.String(), Class: targetClass}, Component: Component,
			Outcome: audit.Denied, Reason: check, Details: []chain.Detail{{Key: "check", Value: check}, {Key: "export_id", Value: id.String()}}})
	})
	if err != nil {
		s.log().Error("reports: a download refusal could not be audited", "export", id.String(), "err", err)
	}
}

// Download opens the file of the caller's own export (spec §8.3; reports.md §7.1). Order of checks: the
// export exists, the caller made it, it has not expired, it succeeded, and the caller's read scope is still
// the one the run was made under (the one gate, run.Service.Read). Each refusal is audited as
// download_denied with the check that failed. The downloaded event is appended BEFORE the first byte is
// served, so a file is never delivered unrecorded.
func (s *Service) Download(ctx context.Context, tid tenant.ID, c authority.Chain, id ID) (*Download, error) {
	if err := s.ready(); err != nil {
		return nil, err
	}
	var e Export
	err := s.DB.WithTenant(ctx, tid, func(ctx context.Context, tx store.Tx) (err error) {
		e, err = load(ctx, tx, id, false)
		return err
	})
	switch {
	case errors.Is(err, ErrExportNotFound):
		s.denied(ctx, tid, c, id, "exists")
		return nil, ErrExportNotFound
	case err != nil:
		return nil, err
	case e.CreatedBy != string(c.Requester.ID):
		s.denied(ctx, tid, c, id, "creator")
		return nil, ErrExportNotFound
	case e.Expired(s.now()):
		s.denied(ctx, tid, c, id, "expired")
		return nil, ErrExportExpired
	}
	switch e.State {
	case StateSucceeded:
	case StateDeleted:
		s.denied(ctx, tid, c, id, "deleted")
		return nil, ErrExportNotFound
	default:
		s.denied(ctx, tid, c, id, "state")
		return nil, ErrExportNotReady
	}
	if err := s.Runs.Read(ctx, tid, e.RunID, c, run.CheckScope, nil); err != nil {
		if errors.Is(err, run.ErrScopeChanged) {
			s.denied(ctx, tid, c, id, "scope")
		}
		return nil, err
	}
	rc, _, err := s.Blob.Get(ctx, tid, e.BlobKey)
	if errors.Is(err, blob.ErrNotFound) {
		s.denied(ctx, tid, c, id, "file")
		return nil, ErrExportExpired
	}
	if err != nil {
		return nil, err
	}
	if err := s.DB.WithTenant(ctx, tid, func(ctx context.Context, tx store.Tx) error {
		return s.Audit.Append(ctx, tx, audit.Event{ID: "export:" + id.String() + ":downloaded:" + randomSuffix(), Kind: KindDownloaded, At: s.now(),
			Actor: c, Target: authority.TargetRef{GUID: id.String(), Class: targetClass}, Component: Component, Outcome: audit.Success,
			Details: sortDetails(s.fileDetails(e))})
	}); err != nil {
		_ = rc.Close()
		return nil, err
	}
	base := ""
	if e.FileName != nil {
		base = strings.TrimSuffix(*e.FileName, "."+e.Format.Ext())
	}
	return &Download{Reader: rc, Base: base, Format: e.Format}, nil
}
