package export

import (
	"context"
	"encoding/hex"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"errors"
	"strconv"
	"time"

	"github.com/skenzeriq/activediq/internal/modules/reports/run"
	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/audit/chain"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/blob"
	pexport "github.com/skenzeriq/activediq/internal/platform/export"
	"github.com/skenzeriq/activediq/internal/platform/export/csv"
	"github.com/skenzeriq/activediq/internal/platform/export/pdf"
	"github.com/skenzeriq/activediq/internal/platform/export/xlsx"
	"github.com/skenzeriq/activediq/internal/platform/htmlx"
	"github.com/skenzeriq/activediq/internal/platform/jobs"
	"github.com/skenzeriq/activediq/internal/platform/report"
	"github.com/skenzeriq/activediq/internal/platform/store"
)

// Kind is the reports.export job kind (EP-5), registered by the composition root. The body is managed: it
// holds no transaction while it streams, only short ones to take the export, read a page of rows and finish.
func (s *Service) Kind() jobs.Kind {
	return jobs.Kind{
		Name: JobKind, Timeout: JobTimeout, Mode: jobs.ModeManagedTx,
		ValidateArgs: func(args jsontext.Value) error {
			var a jobArgs
			if err := jsonv2.Unmarshal(args, &a); err != nil {
				return errors.New("reports.export: bad args")
			}
			if _, err := ParseID(a.ExportID); err != nil {
				return errors.New("reports.export: bad export id")
			}
			return nil
		},
		RunManaged: s.runJob,
	}
}

// outcome is how an attempt ends when it does not produce a file.
type outcome struct {
	reason run.FailureReason
	detail map[string]int64
}

func (o *outcome) Error() string { return "export failed: " + string(o.reason) }

const startExport = `UPDATE public.report_exports SET state = 'running', attempt = $2, row_count = $3, digest = $4, expires_at = $5
WHERE id = $1::uuid AND state IN ('queued', 'running')`

const failExport = `UPDATE public.report_exports SET state = 'failed', failure_reason = $2, failure_detail = $3::jsonb, finished_at = $4
WHERE id = $1::uuid AND state IN ('queued', 'running')`

const succeedExport = `UPDATE public.report_exports SET state = 'succeeded', byte_size = $3, file_sha256 = $4, file_name = $5, finished_at = $6,
  row_count = $7, digest = $8, expires_at = $9
WHERE id = $1::uuid AND state = 'running' AND attempt = $2`

// fail moves a live export (locked by the caller) to failed and appends reports.export.failed.
func (s *Service) fail(ctx context.Context, tx store.Tx, e Export, reason run.FailureReason, detail map[string]int64) error {
	now := s.now()
	var dj *string
	if len(detail) > 0 {
		b, _ := jsonv2.Marshal(detail)
		x := string(b)
		dj = &x
	}
	tag, err := tx.Exec(ctx, failExport, e.ID.String(), string(reason), dj, now)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return nil // already final: another delivery finished it
	}
	det := []chain.Detail{{Key: "export_id", Value: e.ID.String()}, {Key: "format", Value: string(e.Format)}, {Key: "run_id", Value: e.RunID.String()}}
	for _, k := range sortedKeys(detail) {
		det = append(det, chain.Detail{Key: "x_" + k, Value: strconv.FormatInt(detail[k], 10)})
	}
	return s.Audit.Append(ctx, tx, audit.Event{ID: "export:" + e.ID.String() + ":failed", Kind: KindFailed, At: now, Actor: e.Chain,
		Target: authority.TargetRef{GUID: e.ID.String(), Class: targetClass}, Component: Component, Outcome: audit.Failure,
		Reason: string(reason), Details: sortDetails(det)})
}

func sortedKeys(m map[string]int64) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

func (s *Service) runJob(ctx context.Context, jt jobs.TenantTx, c jobs.Claimed) error {
	var a jobArgs
	if err := jsonv2.Unmarshal(c.Args, &a); err != nil {
		return &jobs.Failure{Code: "bad_args", Permanent: true}
	}
	id, err := ParseID(a.ExportID)
	if err != nil {
		return &jobs.Failure{Code: "bad_args", Permanent: true}
	}
	if s.Blob == nil {
		return &jobs.Failure{Code: "no_blob_store", Permanent: true}
	}

	// T1: take the export. The row lock serialises two deliveries of the same job.
	var e Export
	var r run.Run
	var go_ bool
	err = jt.Run(ctx, func(ctx context.Context, t store.Tx) error {
		cur, err := load(ctx, t, id, true)
		if errors.Is(err, ErrExportNotFound) {
			return nil // the record is gone: nothing to do
		}
		if err != nil {
			return err
		}
		if cur.State != StateQueued && cur.State != StateRunning {
			return nil // finished by an earlier delivery
		}
		e = cur
		if r, err = s.Runs.Peek(ctx, t, e.RunID); err != nil {
			return err
		}
		switch r.State {
		case run.StateQueued, run.StateRunning:
			if a.Poll >= MaxPolls {
				return s.fail(ctx, t, e, run.FailInternal, nil)
			}
			_, err := s.Jobs.Enqueue(ctx, t, jobs.Job{Kind: JobKind, Tenant: c.Tenant, Args: jobArgs{ExportID: id.String(), Poll: a.Poll + 1},
				UniqueKey: id.String() + ":poll-" + strconv.Itoa(a.Poll+1), RunAt: time.Now().Add(PollEvery)})
			return err
		case run.StateFailed, run.StateCancelled:
			reason := r.Failure
			if reason == "" {
				reason = run.FailInternal
			}
			return s.fail(ctx, t, e, reason, nil)
		case run.StateSucceeded:
		default:
			return s.fail(ctx, t, e, run.FailInternal, nil)
		}
		if r.RowCount == nil || r.ExpiresAt == nil {
			return s.fail(ctx, t, e, run.FailInternal, nil)
		}
		if cerr := s.capCheck(e.Format, *r.RowCount); cerr != nil {
			var ce *CapError
			errors.As(cerr, &ce)
			return s.fail(ctx, t, e, run.FailRowCapExceeded, map[string]int64{"cap": ce.Cap, "rows": ce.Rows})
		}
		if _, err := t.Exec(ctx, startExport, id.String(), c.Attempt, r.RowCount, r.Digest, *r.ExpiresAt); err != nil {
			return err
		}
		e.Attempt, e.RowCount, e.Digest, e.ExpiresAt = c.Attempt, r.RowCount, r.Digest, *r.ExpiresAt
		go_ = true
		return nil
	})
	if err != nil || !go_ {
		return err
	}

	// T2: stream the rows into the blob (no transaction held), then T3: finish.
	info, name, werr := s.write(ctx, jt, c, e, r)
	if werr == nil {
		return jt.Run(ctx, func(ctx context.Context, t store.Tx) error {
			cur, err := load(ctx, t, id, true)
			if err != nil {
				return err
			}
			if cur.State != StateRunning || cur.Attempt != c.Attempt {
				return nil
			}
			sum, err := hex.DecodeString(info.SHA256)
			if err != nil || len(sum) != 32 {
				return errors.New("export: the blob store returned no file digest")
			}
			tag, err := t.Exec(ctx, succeedExport, id.String(), c.Attempt, info.Size, sum, name, s.now(), r.RowCount, r.Digest, *r.ExpiresAt)
			if err != nil {
				return err
			}
			if tag.RowsAffected() != 1 {
				return nil
			}
			return nil
		})
	}

	// The attempt produced no file: remove any partial blob, then fail the export with a stable reason.
	if ctx.Err() != nil && !errors.As(werr, new(*outcome)) {
		return werr // the worker is stopping: leave the claim to lapse and the job to be retried
	}
	_ = s.Blob.Delete(context.WithoutCancel(ctx), c.Tenant, e.BlobKey)
	reason, detail := run.FailInternal, map[string]int64(nil)
	var o *outcome
	switch {
	case errors.As(werr, &o):
		reason, detail = o.reason, o.detail
	case errors.Is(werr, pexport.ErrRowCapExceeded):
		reason, detail = run.FailRowCapExceeded, map[string]int64{"cap": s.Cap(e.Format), "rows": *r.RowCount}
	default:
		s.log().Error("reports: an export failed", "export", id.String(), "err", werr)
	}
	return jt.Run(ctx, func(ctx context.Context, t store.Tx) error {
		cur, err := load(ctx, t, id, true)
		if err != nil {
			return err
		}
		if cur.State != StateRunning || cur.Attempt != c.Attempt {
			return nil
		}
		return s.fail(ctx, t, cur, reason, detail)
	})
}

// write serialises the run's stored rows into the export's blob and proves that the rows it served are the
// rows the run's digest covers. It returns what the blob store holds and the file name.
func (s *Service) write(ctx context.Context, jt jobs.TenantTx, c jobs.Claimed, e Export, r run.Run) (blob.Info, string, error) {
	def, ok := s.Runs.Catalog.Definition(r.DefinitionID, r.DefinitionVer)
	if !ok || def.SHA256 != r.DefinitionSHA256 {
		return blob.Info{}, "", &outcome{reason: run.FailDefinitionRetired}
	}
	rp, err := s.Runs.Codec.Decode(r.Params, def.Def)
	if err != nil {
		return blob.Info{}, "", err
	}
	q, err := report.Resolve(def.Def, r.Preset, rp, def.Dataset)
	if err != nil {
		return blob.Info{}, "", err
	}
	cols := make([]report.Column, len(q.Columns))
	for i, id := range q.Columns {
		col, ok := def.Dataset.Column(id)
		if !ok {
			return blob.Info{}, "", &outcome{reason: run.FailInternal}
		}
		cols[i] = col
	}
	pager := func(ctx context.Context, after int64, limit int) ([]run.StoredRow, error) {
		var rows []run.StoredRow
		err := jt.Run(ctx, func(ctx context.Context, t store.Tx) (err error) {
			rows, err = run.PageAfter(ctx, t, r.ID, after, limit)
			return err
		})
		return rows, err
	}
	src, err := run.NewStoredSource(r, cols, pager)
	if err != nil {
		return blob.Info{}, "", err
	}
	now := s.now()
	cap := s.Cap(e.Format)
	var f pexport.Format
	switch e.Format {
	case CSV:
		f = csv.Format(csv.Options{MaxRows: cap})
	case XLSX:
		f = xlsx.Format(xlsx.Options{Sheet: xlsx.ParseSheetName(def.Def.Title), Title: def.Def.Title, MaxRows: cap, About: s.about(r, def, q, e)})
	case PDF:
		f = pdf.Format(pdf.Options{Title: def.Def.Title, MaxRows: cap, About: s.about(r, def, q, e)})
	case HTML:
		f = htmlx.Format(htmlx.Options{Title: def.Def.Title, MaxRows: cap, About: s.about(r, def, q, e)})
	default:
		return blob.Info{}, "", &outcome{reason: run.FailInternal}
	}
	_, info, err := pexport.RunToBlob(ctx, s.Blob, s.now, pexport.Job{Tenant: c.Tenant, Key: e.BlobKey, Retention: e.ExpiresAt.Sub(now), MaxRows: cap}, src, f)
	if err != nil {
		return blob.Info{}, "", err
	}
	if sum := src.Digest(); src.Served() != *r.RowCount || !equal(sum[:], r.Digest) {
		// The file was not made from the rows the run's digest covers: never hand it out.
		s.log().Error("reports: an export did not reproduce its run's digest", "export", e.ID.String(), "run", r.ID.String())
		return blob.Info{}, "", &outcome{reason: run.FailInternal}
	}
	return info, fileBase(def, r, now) + "." + e.Format.Ext(), nil
}

func equal(a, b []byte) bool { return string(a) == string(b) }

// fileBase is the download name without its extension: report, preset and the UTC minute it was made.
func fileBase(def run.Definition, r run.Run, at time.Time) string {
	return string(def.Def.ID) + "-" + r.Preset + "-" + at.UTC().Format("20060102-1504") + "Z"
}
