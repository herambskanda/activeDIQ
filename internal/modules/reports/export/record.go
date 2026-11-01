package export

import (
	"context"
	"encoding/json/v2"
	"time"

	"github.com/skenzeriq/activediq/internal/modules/reports/run"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/htmlx"
	"github.com/skenzeriq/activediq/internal/platform/httpx"
	"github.com/skenzeriq/activediq/internal/platform/store"
)

// ID identifies one export. It is minted here and parsed from the canonical text only.
type ID struct{ r run.ID }

// NewID returns a random export ID.
func NewID() ID { return ID{run.NewID()} }

// ParseID reads the canonical 8-4-4-4-12 form.
func ParseID(s string) (ID, error) {
	r, err := run.ParseID(s)
	if err != nil {
		return ID{}, ErrExportNotFound
	}
	return ID{r}, nil
}

// String is the canonical lower-case form, safe to bind.
func (id ID) String() string { return id.r.String() }

// Format is an export format: csv and xlsx (row B9), pdf and html (row B10).
type Format string

// The formats that exist.
const (
	CSV  Format = "csv"
	XLSX Format = "xlsx"
	PDF  Format = "pdf"
	HTML Format = "html"
)

// Ext is the file extension without the dot.
func (f Format) Ext() string { return string(f) }

// HTTPX is the download description of f: its media type and extension (httpx.Attachment). An HTML
// download must also carry the style hash of the page (see Style).
func (f Format) HTTPX() httpx.Format {
	switch f {
	case XLSX:
		return httpx.XLSX
	case PDF:
		return httpx.PDF
	case HTML:
		return httpx.HTML
	}
	return httpx.CSV
}

// DownloadOptions are the extra header inputs of f's download: an HTML file's Content-Security-Policy
// pins the hash of the one style block the encoder writes.
func (f Format) DownloadOptions() []httpx.Option {
	if f == HTML {
		return []httpx.Option{httpx.WithStyleSHA256(htmlx.StyleSHA256())}
	}
	return nil
}

// Formats lists the formats this installation can produce, in the order the UI offers them.
func Formats() []Format { return []Format{CSV, XLSX, PDF, HTML} }

// State is an export's state (the API's ReportExportState).
type State string

// The states. succeeded is "ready" in the module page's older wording.
const (
	StateQueued    State = "queued"
	StateRunning   State = "running"
	StateSucceeded State = "succeeded"
	StateFailed    State = "failed"
	StateExpired   State = "expired"
	StateDeleted   State = "deleted"
)

// Export is one report_exports row. BlobKey never leaves the server: no API view, audit event or mail
// carries it.
type Export struct {
	ID            ID
	RunID         run.ID
	Rerun         bool
	RerunOf       *run.ID
	Format        Format
	State         State
	Failure       run.FailureReason
	FailureDetail map[string]int64
	Attempt       int
	CreatedBy     string
	Chain         authority.Chain
	RowCount      *int64
	Digest        []byte
	ByteSize      *int64
	FileSHA256    []byte
	BlobKey       string
	FileName      *string
	CreatedAt     time.Time
	FinishedAt    *time.Time
	ExpiresAt     time.Time
}

// Expired reports whether the file is past its expiry at now, whatever the sweep has flipped yet.
func (e Export) Expired(now time.Time) bool {
	return e.State == StateExpired || (e.State == StateSucceeded && !e.ExpiresAt.After(now))
}

const selectExport = `SELECT id::text, run_id::text, rerun, rerun_of_run_id::text, format, state, failure_reason, failure_detail,
  attempt, created_by::text, chain, row_count, digest, byte_size, file_sha256, blob_key, file_name, created_at, finished_at, expires_at
FROM public.report_exports WHERE id = $1::uuid`

const lockExport = `SELECT id FROM public.report_exports WHERE id = $1::uuid FOR UPDATE`

type scanner interface{ Scan(dest ...any) error }

func scanExport(row scanner) (Export, error) {
	var (
		e                     Export
		id, runID, by, format string
		rerunOf, failure      *string
		detail, chainJSON     []byte
	)
	var st string
	err := row.Scan(&id, &runID, &e.Rerun, &rerunOf, &format, &st, &failure, &detail, &e.Attempt, &by, &chainJSON,
		&e.RowCount, &e.Digest, &e.ByteSize, &e.FileSHA256, &e.BlobKey, &e.FileName, &e.CreatedAt, &e.FinishedAt, &e.ExpiresAt)
	if err != nil {
		return Export{}, err
	}
	if e.ID, err = ParseID(id); err != nil {
		return Export{}, err
	}
	if e.RunID, err = run.ParseID(runID); err != nil {
		return Export{}, err
	}
	if rerunOf != nil {
		x, err := run.ParseID(*rerunOf)
		if err != nil {
			return Export{}, err
		}
		e.RerunOf = &x
	}
	e.Format, e.State, e.CreatedBy = Format(format), State(st), by
	if failure != nil {
		e.Failure = run.FailureReason(*failure)
	}
	if detail != nil {
		if err := json.Unmarshal(detail, &e.FailureDetail); err != nil {
			return Export{}, err
		}
	}
	if e.Chain, err = decodeChain(chainJSON); err != nil {
		return Export{}, err
	}
	return e, nil
}

type principalJSON struct {
	ID   string `json:"id"`
	Kind string `json:"kind"`
}
type chainJSON struct {
	Requester principalJSON   `json:"requester"`
	Via       []principalJSON `json:"via,omitempty"`
}

func encodeChain(c authority.Chain) ([]byte, error) {
	j := chainJSON{Requester: principalJSON{string(c.Requester.ID), string(c.Requester.Kind)}}
	for _, p := range c.Via {
		j.Via = append(j.Via, principalJSON{string(p.ID), string(p.Kind)})
	}
	return json.Marshal(j)
}

func decodeChain(b []byte) (authority.Chain, error) {
	var j chainJSON
	if err := json.Unmarshal(b, &j); err != nil {
		return authority.Chain{}, err
	}
	c := authority.Chain{Requester: authority.Principal{ID: authority.PrincipalID(j.Requester.ID), Kind: authority.PrincipalKind(j.Requester.Kind)}}
	for _, p := range j.Via {
		c.Via = append(c.Via, authority.Principal{ID: authority.PrincipalID(p.ID), Kind: authority.PrincipalKind(p.Kind)})
	}
	return c, nil
}

// load reads an export by ID in the transaction's tenant (RLS), optionally locking it.
func load(ctx context.Context, tx store.Tx, id ID, lock bool) (Export, error) {
	if lock {
		var locked string
		if err := tx.QueryRow(ctx, lockExport, id.String()).Scan(&locked); err != nil {
			if store.IsNoRows(err) {
				return Export{}, ErrExportNotFound
			}
			return Export{}, err
		}
	}
	e, err := scanExport(tx.QueryRow(ctx, selectExport, id.String()))
	if store.IsNoRows(err) {
		return Export{}, ErrExportNotFound
	}
	return e, err
}
