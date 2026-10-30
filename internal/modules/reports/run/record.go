package run

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/store"
)

// ID identifies one run. It is minted here and parsed from the canonical text only.
type ID [16]byte

// NewID returns a random version-4 run ID.
func NewID() ID {
	var id ID
	if _, err := rand.Read(id[:]); err != nil {
		panic(fmt.Sprintf("run: no entropy: %v", err))
	}
	id[6] = id[6]&0x0f | 0x40
	id[8] = id[8]&0x3f | 0x80
	return id
}

// ParseID reads the canonical 8-4-4-4-12 form.
func ParseID(s string) (ID, error) {
	var id ID
	if len(s) != 36 || s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' {
		return id, ErrRunNotFound
	}
	b, err := hex.DecodeString(s[:8] + s[9:13] + s[14:18] + s[19:23] + s[24:])
	if err != nil || len(b) != 16 {
		return id, ErrRunNotFound
	}
	copy(id[:], b)
	return id, nil
}

// String is the canonical lower-case form, safe to bind.
func (id ID) String() string {
	h := hex.EncodeToString(id[:])
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

// Run is one report_runs row (DM-72).
type Run struct {
	ID               ID
	DefinitionID     string
	DefinitionVer    int
	DefinitionSHA256 [32]byte
	Preset           string
	Params           json.RawMessage // the validated request parameters, API shape
	QueryHash        [32]byte
	ScopeFingerprint [32]byte
	Runner           string
	Chain            authority.Chain
	ScheduleID       *ID
	RerunOf          *ID
	State            State
	Failure          FailureReason
	Attempt          int
	ScopeApplied     ScopeApplied
	Freshness        *FreshnessRecord
	AsOf             *time.Time
	RowCount         *int64
	ObjectsChecked   *int64
	HiddenCounts     map[string]int64
	Digest           []byte
	Columns          []string
	CreatedAt        time.Time
	StartedAt        *time.Time
	FinishedAt       *time.Time
	ExpiresAt        *time.Time
}

// ScopeApplied is the scope_applied document: what trimmed the rows, in words and reason codes.
type ScopeApplied struct {
	Summary     string   `json:"summary,omitempty"`
	Reasons     []string `json:"reasons,omitempty"`
	EmptyReason string   `json:"emptyReason,omitempty"`
	// Detail holds the numbers a failure names (row_cap_exceeded: rows, cap); never a value.
	Detail map[string]int64 `json:"detail,omitempty"`
}

// FreshnessRecord is the freshness document (§6.4). Connections and naming contexts are canonical GUID
// text; Age is whole seconds.
type FreshnessRecord struct {
	State      string       `json:"state"` // synced, stale, not_synced_yet
	Label      string       `json:"label"`
	AsOf       *time.Time   `json:"asOf,omitempty"`
	Stale      []StaleEntry `json:"stale,omitempty"`
	NotSynced  []string     `json:"notSynced,omitempty"`
	Threshold  int64        `json:"thresholdSeconds"`
	ComputedAt time.Time    `json:"computedAt"`
}

// StaleEntry names a naming context that makes a result stale.
type StaleEntry struct {
	Connection string `json:"connection"`
	NC         string `json:"nc"`
	AgeSeconds int64  `json:"ageSeconds"`
	State      string `json:"state"`
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

// scanner is the one method scanRun needs of a pgx row.
type scanner interface{ Scan(dest ...any) error }

// selectRun and lockRun are whole constants (no assembled SQL text): lockRun takes the row lock, which
// load then follows with selectRun so a locked read sees the committed latest version.
const selectRun = `SELECT id::text, definition_id, definition_version, definition_sha256, preset, params, query_hash,
  scope_fingerprint, runner_account::text, chain, schedule_id::text, rerun_of::text, state, failure_reason, attempt,
  scope_applied, freshness, as_of, row_count, objects_checked, hidden_counts, digest, columns,
  created_at, started_at, finished_at, expires_at FROM public.report_runs WHERE id = $1::uuid`

const lockRun = `SELECT id FROM public.report_runs WHERE id = $1::uuid FOR UPDATE`

func scanRun(row scanner) (Run, error) {
	var (
		r                                 Run
		id, runner                        string
		sched, rerun, failure             *string
		state                             string
		sha, qh, fp                       []byte
		chain, scope, fresh, hidden, cols []byte
		digest                            []byte
	)
	err := row.Scan(&id, &r.DefinitionID, &r.DefinitionVer, &sha, &r.Preset, &r.Params, &qh, &fp, &runner, &chain,
		&sched, &rerun, &state, &failure, &r.Attempt, &scope, &fresh, &r.AsOf, &r.RowCount, &r.ObjectsChecked,
		&hidden, &digest, &cols, &r.CreatedAt, &r.StartedAt, &r.FinishedAt, &r.ExpiresAt)
	if err != nil {
		return Run{}, err
	}
	if r.ID, err = ParseID(id); err != nil {
		return Run{}, err
	}
	copy(r.DefinitionSHA256[:], sha)
	copy(r.QueryHash[:], qh)
	copy(r.ScopeFingerprint[:], fp)
	r.Runner, r.State, r.Digest = runner, State(state), digest
	if failure != nil {
		r.Failure = FailureReason(*failure)
	}
	for _, p := range []struct {
		in  *string
		out **ID
	}{{sched, &r.ScheduleID}, {rerun, &r.RerunOf}} {
		if p.in != nil {
			x, err := ParseID(*p.in)
			if err != nil {
				return Run{}, err
			}
			*p.out = &x
		}
	}
	if r.Chain, err = decodeChain(chain); err != nil {
		return Run{}, err
	}
	if scope != nil {
		if err := json.Unmarshal(scope, &r.ScopeApplied); err != nil {
			return Run{}, err
		}
	}
	if fresh != nil {
		r.Freshness = new(FreshnessRecord)
		if err := json.Unmarshal(fresh, r.Freshness); err != nil {
			return Run{}, err
		}
	}
	if hidden != nil {
		if err := json.Unmarshal(hidden, &r.HiddenCounts); err != nil {
			return Run{}, err
		}
	}
	if err := json.Unmarshal(cols, &r.Columns); err != nil {
		return Run{}, err
	}
	return r, nil
}

// load reads a run by ID in the transaction's tenant (RLS), optionally locking it.
func load(ctx context.Context, tx store.Tx, id ID, lock bool) (Run, error) {
	if lock {
		var locked string
		if err := tx.QueryRow(ctx, lockRun, id.String()).Scan(&locked); err != nil {
			if store.IsNoRows(err) {
				return Run{}, ErrRunNotFound
			}
			return Run{}, err
		}
	}
	r, err := scanRun(tx.QueryRow(ctx, selectRun, id.String()))
	if store.IsNoRows(err) {
		return Run{}, ErrRunNotFound
	}
	return r, err
}

const insertRun = `INSERT INTO public.report_runs
  (tenant_id, id, definition_id, definition_version, definition_sha256, preset, params, query_hash, scope_fingerprint,
   runner_account, chain, rerun_of, state, columns)
VALUES (NULLIF(current_setting('app.tenant_id', true), '')::uuid, $1::uuid, $2, $3, $4, $5, $6::jsonb, $7, $8,
   $9::uuid, $10::jsonb, $11::uuid, 'queued', $12::jsonb)`

// findReusable returns a run of the same runner, query and scope created in the last window and still
// queued, running or succeeded (ADR-0010 reuse window, §6.1 step 3).
const findReusable = `SELECT id::text FROM public.report_runs
WHERE runner_account = $1::uuid AND query_hash = $2 AND scope_fingerprint = $3
  AND created_at > now() - make_interval(secs => $4::double precision) AND state IN ('queued', 'running', 'succeeded')
  AND (state <> 'succeeded' OR expires_at > now())
ORDER BY created_at DESC, id DESC LIMIT 1`

const countOpen = `SELECT count(*) FROM public.report_runs WHERE state IN ('queued', 'running')`

const lockTenantJobs = `SELECT pg_advisory_xact_lock(hashtextextended('reports.jobs:' || current_setting('app.tenant_id', true), 0))`

func isNoRows(err error) bool { return store.IsNoRows(err) }

func randomSuffix() string {
	var b [6]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
