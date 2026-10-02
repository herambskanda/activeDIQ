// Package store is the data-access package of ADR-0002 and safe-primitives P5: the only way product code
// gets a database connection. It has exactly two entry points, and both run fn inside one transaction:
//
//	db.WithTenant(ctx, id, fn)         tenant context set; row-level security shows only that tenant's rows
//	db.WithPlatform(ctx, reason, fn)   no tenant context; only registered-global tables are reachable
//
// The connection pool is unexported, so there is no other way to a connection. Neither entry point
// returns the transaction: fn receives a Tx that can run statements but cannot commit, roll back or
// reach the underlying connection. The tenant is set with set_config(..., true) as the first statement
// of the transaction, so it ends with the transaction and cannot leak to the next user of a pooled
// connection (SQL-14). A tenant ID is a tenant.ID, which cannot be built from text outside the packages
// ADR-0002 rule 5 names, so no string reaches the setting without passing the UUID parser (SQL-03).
//
// WithPlatform may be called only from call sites listed in the exemption registry
// (internal/platform/store/exempt); fitness-tenancy T5 enforces that. It runs as the same runtime role,
// so it never sees a tenant row.
package store

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// DefaultStatementTimeout bounds every statement of every transaction unless Config says otherwise
// (safe-primitives rule 13, SQL-22). It is set per transaction, so it never outlives one.
const DefaultStatementTimeout = 30 * time.Second

// maxReasonLen bounds the WithPlatform reason, which is logged.
const maxReasonLen = 200

// Errors. They are typed so callers and the API's problem mapping can tell them apart; none of them
// carries SQL text, a parameter value or a connection string.
var (
	// ErrNoTenant is returned by WithTenant for the zero tenant.ID. No SQL has run.
	ErrNoTenant = errors.New("store: no tenant: refusing to open a tenant transaction for the zero tenant ID")
	// ErrReasonRequired is returned by WithPlatform when the reason is blank, too long or not printable.
	ErrReasonRequired = errors.New("store: WithPlatform needs a short printable reason")
	// ErrSimpleProtocolForbidden is returned by Open when the DSN selects pgx's simple protocol, which
	// interpolates client-side (CVE-2024-27289; safe-primitives rule 6, SQL-20).
	ErrSimpleProtocolForbidden = errors.New("store: default_query_exec_mode=simple_protocol is forbidden: it interpolates parameters client-side")
	// ErrTenantInDSN is returned by Open when the connection settings try to preset app.tenant_id.
	ErrTenantInDSN = errors.New("store: the connection settings must not preset app.tenant_id")
	// ErrPrivilegedRole is returned by Open when the runtime role could bypass row-level security: it is
	// a superuser, has BYPASSRLS or owns objects (ADR-0002 rule 4).
	ErrPrivilegedRole = errors.New("store: the runtime role must not be a superuser, have BYPASSRLS or own objects: connect as the runtime role, never the migration role")
	// ErrClosed is returned by an entry point on a nil or closed DB.
	ErrClosed = errors.New("store: closed")
)

// Config configures the pool.
type Config struct {
	// DSN is a pgx connection string for the runtime role (never the migration role). A multi-host DSN
	// with target_session_attrs=read-write follows a customer's failover (ADR-0002 rule 6).
	DSN string
	// MaxConns caps the pool; 0 keeps pgx's default.
	MaxConns int32
	// StatementTimeout bounds each statement in every transaction; 0 means DefaultStatementTimeout.
	StatementTimeout time.Duration
}

// DB is the data-access handle. It holds the pool; nothing returns it.
type DB struct {
	pool    *pgxpool.Pool
	timeout string // statement_timeout in milliseconds, as set_config wants it
}

// Open builds the pool, refuses an unsafe configuration and verifies the role it connects as.
func Open(ctx context.Context, cfg Config) (*DB, error) {
	pc, err := pgxpool.ParseConfig(cfg.DSN)
	if err != nil {
		// pgx redacts the password in this message.
		return nil, fmt.Errorf("store: invalid DSN: %w", err)
	}
	if err := checkConnConfig(pc.ConnConfig); err != nil {
		return nil, err
	}
	if cfg.MaxConns > 0 {
		pc.MaxConns = cfg.MaxConns
	}
	timeout := cfg.StatementTimeout
	if timeout <= 0 {
		timeout = DefaultStatementTimeout
	}
	pool, err := pgxpool.NewWithConfig(ctx, pc)
	if err != nil {
		return nil, fmt.Errorf("store: open pool: %w", err)
	}
	d := &DB{pool: pool, timeout: strconv.FormatInt(timeout.Milliseconds(), 10)}
	if err := d.checkRole(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return d, nil
}

// checkConnConfig is the part of Open that needs no server: the SQL-20 refusal and the ban on a
// preset tenant.
func checkConnConfig(cc *pgx.ConnConfig) error {
	if cc.DefaultQueryExecMode == pgx.QueryExecModeSimpleProtocol {
		return ErrSimpleProtocolForbidden
	}
	for k, v := range cc.RuntimeParams {
		if strings.EqualFold(k, "app.tenant_id") || (strings.EqualFold(k, "options") && strings.Contains(strings.ToLower(v), "app.tenant_id")) {
			return ErrTenantInDSN
		}
	}
	return nil
}

// checkRole refuses a role that could bypass row-level security. The fitness job proves the same
// properties of the provisioned roles (T3); this is the runtime's own refusal to start otherwise.
func (d *DB) checkRole(ctx context.Context) error {
	var bypass, owns bool
	err := d.pool.QueryRow(ctx, `SELECT r.rolsuper OR r.rolbypassrls,
		EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
			WHERE n.nspname NOT IN ('pg_catalog', 'information_schema') AND n.nspname NOT LIKE 'pg_toast%'
			AND pg_has_role(current_user, c.relowner, 'USAGE'))
		FROM pg_roles r WHERE r.rolname = current_user`).Scan(&bypass, &owns)
	if err != nil {
		return fmt.Errorf("store: check the runtime role: %w", err)
	}
	if bypass || owns {
		return ErrPrivilegedRole
	}
	return nil
}

// Close releases the pool. Entry points called afterwards fail.
func (d *DB) Close() {
	if d != nil && d.pool != nil {
		d.pool.Close()
	}
}

// Tx is what fn receives: the statement methods of a transaction and nothing else. It has the shape
// sqlc generates against for pgx/v5 (its DBTX), so generated query packages take it directly.
type Tx interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// WithTenant runs fn in one transaction scoped to tenant id: row-level security shows fn only that
// tenant's rows and rejects a row for any other. fn returning nil commits; an error or a panic rolls
// back. The zero ID is refused before any SQL runs.
func (d *DB) WithTenant(ctx context.Context, id tenant.ID, fn func(ctx context.Context, tx Tx) error) error {
	if id.IsZero() {
		return ErrNoTenant
	}
	return d.run(ctx, id.String(), fn)
}

// WithPlatform runs fn in one transaction with no tenant context, as the same runtime role: every
// tenant table reads as empty and rejects writes, and only registered-global tables are reachable.
// Call it only from a site listed in the exemption registry; reason says why, and is logged.
func (d *DB) WithPlatform(ctx context.Context, reason string, fn func(ctx context.Context, tx Tx) error) error {
	if !validReason(reason) {
		return ErrReasonRequired
	}
	slog.DebugContext(ctx, "store: platform transaction", "reason", reason)
	return d.run(ctx, "", fn)
}

func validReason(s string) bool {
	if strings.TrimSpace(s) == "" || len(s) > maxReasonLen || !utf8.ValidString(s) {
		return false
	}
	return strings.IndexFunc(s, func(r rune) bool { return !unicode.IsPrint(r) }) < 0
}

// run is the one place a transaction is opened. The first statement sets the tenant ("" means none) and
// the statement timeout, both local to the transaction.
func (d *DB) run(ctx context.Context, tenantID string, fn func(ctx context.Context, tx Tx) error) error {
	if d == nil || d.pool == nil {
		return ErrClosed
	}
	pgtx, err := d.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("store: begin: %w", err)
	}
	committed := false
	defer func() {
		if committed {
			return
		}
		// Error, panic or cancellation: roll back on a context that survives a cancelled request, so the
		// connection returns to the pool clean.
		rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = pgtx.Rollback(rctx)
	}()
	if _, err := pgtx.Exec(ctx, `SELECT set_config('app.tenant_id', $1, true), set_config('statement_timeout', $2, true)`, tenantID, d.timeout); err != nil {
		return fmt.Errorf("store: set transaction context: %w", err)
	}
	if err := fn(ctx, tx{pgtx}); err != nil {
		return err
	}
	if err := pgtx.Commit(ctx); err != nil {
		return fmt.Errorf("store: commit: %w", err)
	}
	committed = true
	return nil
}

// tx hides the pgx.Tx: no Commit, Rollback, Begin or Conn.
type tx struct{ t pgx.Tx }

func (x tx) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	return x.t.Exec(ctx, sql, args...)
}

func (x tx) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	return x.t.Query(ctx, sql, args...)
}

func (x tx) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	return x.t.QueryRow(ctx, sql, args...)
}
