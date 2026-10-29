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
	// ErrNestedTenant is returned by WithTenant when called with the context of a running store
	// transaction: a second transaction would not see the first's writes, and its tenant could differ.
	// Do the work through the Tx you were given. No SQL has run.
	ErrNestedTenant = errors.New("store: nested WithTenant: a transaction is already open on this context; use the Tx fn received")
	// ErrLockWait is returned by WithTenantSeparate when the lock wait is not positive or exceeds
	// maxSeparateLockWait.
	ErrLockWait = errors.New("store: WithTenantSeparate needs a lock wait between 1ms and 10s")
	// ErrReasonRequired is returned by WithPlatform when the reason is blank, too long or not printable.
	ErrReasonRequired = errors.New("store: WithPlatform needs a short printable reason")
	// ErrSimpleProtocolForbidden is returned by Open when the DSN selects pgx's simple protocol, which
	// interpolates client-side (CVE-2024-27289; safe-primitives rule 6, SQL-20).
	ErrSimpleProtocolForbidden = errors.New("store: default_query_exec_mode=simple_protocol is forbidden: it interpolates parameters client-side")
	// ErrTenantInDSN is returned by Open when the connection settings try to preset app.tenant_id.
	ErrTenantInDSN = errors.New("store: the connection settings must not preset app.tenant_id")
	// ErrPrivilegedRole is returned by Open when the runtime role could bypass row-level security: it is
	// a superuser, has BYPASSRLS, owns objects or the database, can create in a schema, or is a member of a
	// role that does (ADR-0002 rule 4).
	ErrPrivilegedRole = errors.New("store: the runtime role must not be, or be a member of, a role that is a superuser, has BYPASSRLS, owns objects, can create in a schema or create temporary tables, and must log in as itself rather than SET ROLE to itself: connect as the runtime role, never the migration role")
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
	// SeparateMaxConns caps the dedicated pool behind WithTenantSeparate; 0 means 4. It is a pool of
	// its own so a caller that holds a main-pool connection and waits for a second one cannot form a
	// circular wait with other callers.
	SeparateMaxConns int32
	// SeparateAcquireTimeout bounds the wait for a dedicated connection; 0 means 5 s. On timeout
	// WithTenantSeparate fails (callers fail closed).
	SeparateAcquireTimeout time.Duration
	// StatementTimeout bounds each statement in every transaction; 0 means DefaultStatementTimeout.
	StatementTimeout time.Duration
	// AllowInsecureTransport is the operator override of the transport policy (safe-primitives §7 rule 14):
	// it lets a remote host be reached without a verified TLS connection. It comes only from platform-scope
	// configuration, is logged at start-up and shown on the health page (DB.Transport). Leave it false.
	AllowInsecureTransport bool
}

// DB is the data-access handle. It holds the pool; nothing returns it.
type DB struct {
	pool      *pgxpool.Pool
	sepPool   *pgxpool.Pool // WithTenantSeparate only; never shared with the main pool
	sepWait   time.Duration
	timeout   string // statement_timeout in milliseconds, as set_config wants it
	transport TransportStatus
	hook      hookHolder
}

// Open builds the pool, refuses an unsafe configuration and verifies the role it connects as. It refuses,
// before any connection is attempted, a DSN that would reach a remote host without verified TLS
// (ErrInsecureTransport) unless Config.AllowInsecureTransport is set.
func Open(ctx context.Context, cfg Config) (*DB, error) { return open(ctx, cfg, false) }

// OpenMaintenance opens a store as the owner role, for the maintenance path only (audit retention purges,
// ADR-0005 rule 11): work the runtime role is denied by design (DELETE on the audit tables, DM-80.I2).
// It applies every other refusal of Open, and instead of refusing the owner it refuses a role that could
// bypass row security (a superuser or BYPASSRLS): FORCE ROW LEVEL SECURITY still binds the owner, and
// every transaction is still a tenant transaction. It is not for request handling.
func OpenMaintenance(ctx context.Context, cfg Config) (*DB, error) { return open(ctx, cfg, true) }

func open(ctx context.Context, cfg Config, maintenance bool) (*DB, error) {
	pc, err := guardParse(func() (*pgxpool.Config, error) { return pgxpool.ParseConfig(cfg.DSN) })
	if err != nil {
		return nil, err
	}
	if err := checkConnConfig(pc.ConnConfig); err != nil {
		return nil, err
	}
	ts, err := checkTransport(pc.ConnConfig, cfg.AllowInsecureTransport)
	if err != nil {
		return nil, err
	}
	if ts.OverrideConfigured {
		slog.WarnContext(ctx, "store: the insecure-transport override is set; TLS to the database is not verified for the hosts listed",
			"relaxed_hosts", ts.RelaxedHosts)
	}
	if cfg.MaxConns > 0 {
		pc.MaxConns = cfg.MaxConns
	}
	timeout := cfg.StatementTimeout
	if timeout <= 0 {
		timeout = DefaultStatementTimeout
	}
	sc := pc.Copy()
	sc.MaxConns = 4
	if cfg.SeparateMaxConns > 0 {
		sc.MaxConns = cfg.SeparateMaxConns
	}
	sc.MinConns = 0
	sepWait := cfg.SeparateAcquireTimeout
	if sepWait <= 0 {
		sepWait = 5 * time.Second
	}
	pool, err := pgxpool.NewWithConfig(ctx, pc)
	if err != nil {
		return nil, fmt.Errorf("store: open pool: %w", err)
	}
	sepPool, err := pgxpool.NewWithConfig(ctx, sc)
	if err != nil {
		pool.Close()
		return nil, fmt.Errorf("store: open pool: %w", err)
	}
	d := &DB{pool: pool, sepPool: sepPool, sepWait: sepWait, timeout: strconv.FormatInt(timeout.Milliseconds(), 10), transport: ts}
	check := d.checkRole
	if maintenance {
		check = d.checkMaintenanceRole
	}
	if err := check(ctx); err != nil {
		pool.Close()
		sepPool.Close()
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

// roleRisk is the one query that decides whether the connected role could get out of row-level
// security. It looks at every role the LOGIN (session_user) is a MEMBER of (itself included; direct or
// indirect, whatever its INHERIT and SET options, because a member that does not inherit can still
// SET ROLE to it; current_user is among them, and a privileged login that merely started the session
// as the runtime role through a role setting is caught here) and returns the first reason found, or no row. A role is a risk when it is a
// superuser, has BYPASSRLS, owns the current database, owns any object visible to this database
// (pg_shdepend, which also covers schemas, functions and other roles' objects), owns a product
// schema, can CREATE in one (which lets it plant objects that shadow ours), holds TEMPORARY on the
// database (pg_temp is searched first, so a planted temp table captures another tenant's unqualified
// writes on a reused connection), or is one of the predefined roles the PostgreSQL docs say can be
// used to gain superuser-level access. migrations/0001 repeats
// this logic in plpgsql for the role named activediq_app; keep the two in step.
const roleRisk = `SELECT x.rolname, CASE
		WHEN x.rolname = 'activediq_catrust' THEN 'trust-anchor reader (column-limited reader of fleet_ca; the runtime role may only EXECUTE its function)'
		WHEN x.rolsuper THEN 'superuser'
		WHEN x.rolbypassrls THEN 'BYPASSRLS'
		WHEN x.rolname IN ('pg_execute_server_program', 'pg_read_server_files', 'pg_write_server_files') THEN 'predefined role that is superuser-equivalent'
		WHEN EXISTS (SELECT 1 FROM pg_database WHERE datname = current_database() AND datdba = x.oid) THEN 'owner of the database'
		WHEN EXISTS (SELECT 1 FROM pg_shdepend d WHERE d.refclassid = 'pg_authid'::regclass AND d.refobjid = x.oid AND d.deptype = 'o'
			AND d.dbid IN (0, (SELECT oid FROM pg_database WHERE datname = current_database()))) THEN 'owner of objects'
		WHEN EXISTS (SELECT 1 FROM pg_namespace n WHERE n.nspowner = x.oid AND ` + productSchema + `) THEN 'owner of a schema'
		WHEN EXISTS (SELECT 1 FROM pg_namespace n WHERE ` + productSchema + ` AND has_schema_privilege(x.oid, n.oid, 'CREATE')) THEN 'can create in a schema'
		WHEN has_database_privilege(x.oid, current_database(), 'TEMPORARY') THEN 'has TEMPORARY on the database'
	END AS risk
	FROM pg_roles x
	WHERE pg_has_role(session_user, x.oid, 'MEMBER')
	ORDER BY (x.rolname = session_user) DESC, x.rolname`

// roleSwitched is true when the session runs as another role than it logged in as: the DSN's options
// parameter (-c role=...) or ALTER ROLE ... SET role. The runtime DSN must log in as the runtime role.
const roleSwitched = `SELECT session_user::text, current_user::text, session_user <> current_user`

const productSchema = `n.nspname NOT IN ('pg_catalog', 'information_schema') AND n.nspname NOT LIKE 'pg_toast%' AND n.nspname NOT LIKE 'pg_temp%'`

// checkRole refuses a role that could bypass row-level security, directly or through a membership. The
// fitness job proves the same properties of the provisioned roles (T3); this is the runtime's own
// refusal to start otherwise.
// checkMaintenanceRole refuses a login that bypasses row security.
func (d *DB) checkMaintenanceRole(ctx context.Context) error {
	var super, bypass bool
	if err := d.pool.QueryRow(ctx, `SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = session_user`).Scan(&super, &bypass); err != nil {
		return fmt.Errorf("store: check the maintenance role: %w", err)
	}
	if super || bypass {
		return fmt.Errorf("%w (the maintenance role bypasses row-level security)", ErrPrivilegedRole)
	}
	return nil
}

func (d *DB) checkRole(ctx context.Context) error {
	var login, running string
	var switched bool
	if err := d.pool.QueryRow(ctx, roleSwitched).Scan(&login, &running, &switched); err != nil {
		return fmt.Errorf("store: check the runtime role: %w", err)
	}
	if switched {
		return fmt.Errorf("%w (the session logged in as %s and was switched to %s; log in as the runtime role)", ErrPrivilegedRole, login, running)
	}
	rows, err := d.pool.Query(ctx, roleRisk)
	if err != nil {
		return fmt.Errorf("store: check the runtime role: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var role string
		var risk *string
		if err := rows.Scan(&role, &risk); err != nil {
			return fmt.Errorf("store: check the runtime role: %w", err)
		}
		if risk != nil {
			return fmt.Errorf("%w (%s is a %s)", ErrPrivilegedRole, role, *risk)
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("store: check the runtime role: %w", err)
	}
	return nil
}

// Transport reports the transport policy outcome for the health page: whether the operator override is
// set and which remote hosts it let through.
func (d *DB) Transport() TransportStatus {
	if d == nil {
		return TransportStatus{}
	}
	return d.transport
}

// Close releases the pool. Entry points called afterwards fail.
func (d *DB) Close() {
	if d != nil && d.pool != nil {
		d.pool.Close()
	}
	if d != nil && d.sepPool != nil {
		d.sepPool.Close()
	}
}

// Tx is what fn receives: the statement methods of a transaction and nothing else. It has the shape
// sqlc generates against for pgx/v5 (its DBTX), so generated query packages take it directly.
type Tx interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

func (d *DB) main() *pgxpool.Pool {
	if d == nil {
		return nil
	}
	return d.pool
}

func (d *DB) sepTimeout() time.Duration {
	if d == nil {
		return 0
	}
	return d.sepWait
}

func (d *DB) separate() *pgxpool.Pool {
	if d == nil {
		return nil
	}
	return d.sepPool
}

// WithTenant runs fn in one transaction scoped to tenant id: row-level security shows fn only that
// tenant's rows and rejects a row for any other. fn returning nil commits; an error or a panic rolls
// back. The zero ID is refused before any SQL runs.
func (d *DB) WithTenant(ctx context.Context, id tenant.ID, fn func(ctx context.Context, tx Tx) error) error {
	if id.IsZero() {
		return ErrNoTenant
	}
	if _, nested := ctx.Value(txCtxKey{}).(struct{}); nested {
		return ErrNestedTenant
	}
	return d.run(ctx, d.main(), 0, id, fn)
}

// maxSeparateLockWait caps the lock wait a WithTenantSeparate caller may ask for.
const maxSeparateLockWait = 10 * time.Second

// WithTenantSeparate is WithTenant for the one case where a second transaction beside a running one
// is the point: a record that must commit even if the surrounding transaction rolls back (a refused
// credential attempt counted against its budget). It is allowed on the context of a running
// transaction; it uses another connection, so it neither sees the outer transaction's uncommitted
// writes nor can it wait on them for long: lockWait (required, positive, at most maxSeparateLockWait)
// is set as the transaction's lock_timeout here, with a bound parameter, so a caller holding a row this
// body needs gets an error after lockWait instead of a hang. Only internal/platform/authn may call it
// (nestedtx analyzer, FF-SP2; ADR-0005 amendment 2026-10-26).
func (d *DB) WithTenantSeparate(ctx context.Context, id tenant.ID, lockWait time.Duration, fn func(ctx context.Context, tx Tx) error) error {
	if id.IsZero() {
		return ErrNoTenant
	}
	if lockWait <= 0 || lockWait > maxSeparateLockWait {
		return ErrLockWait
	}
	ms := strconv.FormatInt(lockWait.Milliseconds(), 10)
	return d.run(ctx, d.separate(), d.sepTimeout(), id, func(ctx context.Context, tx Tx) error {
		if _, err := tx.Exec(ctx, `SELECT set_config('lock_timeout', $1, true)`, ms); err != nil {
			return fmt.Errorf("store: set lock timeout: %w", err)
		}
		return fn(ctx, tx)
	})
}

// WithPlatform runs fn in one transaction with no tenant context, as the same runtime role: every
// tenant table reads as empty and rejects writes, and only registered-global tables are reachable.
// Call it only from a site listed in the exemption registry; reason says why, and is logged.
func (d *DB) WithPlatform(ctx context.Context, reason string, fn func(ctx context.Context, tx Tx) error) error {
	if !validReason(reason) {
		return ErrReasonRequired
	}
	slog.DebugContext(ctx, "store: platform transaction", "reason", reason)
	return d.run(ctx, d.main(), 0, noTenant, fn)
}

// txCtxKey marks the context handed to fn, so a nested WithTenant can be recognised.
type txCtxKey struct{}

func validReason(s string) bool {
	if strings.TrimSpace(s) == "" || len(s) > maxReasonLen || !utf8.ValidString(s) {
		return false
	}
	return strings.IndexFunc(s, func(r rune) bool { return !unicode.IsPrint(r) }) < 0
}

// run is the one place a transaction is opened. The first statement sets the tenant ("" means none) and
// the statement timeout, both local to the transaction.
//
// pool is the main pool, or for WithTenantSeparate the dedicated one; acquire (when positive) bounds the
// wait for a connection from it.
func (d *DB) run(ctx context.Context, pool *pgxpool.Pool, acquire time.Duration, tid tenant.ID, fn func(ctx context.Context, tx Tx) error) error {
	if d == nil || pool == nil {
		return ErrClosed
	}
	tenantID := "" // the zero ID is a platform transaction
	if !tid.IsZero() {
		tenantID = tid.String()
	}
	bctx, bcancel := ctx, context.CancelFunc(func() {})
	if acquire > 0 {
		bctx, bcancel = context.WithTimeout(ctx, acquire)
	}
	pgtx, err := pool.BeginTx(bctx, pgx.TxOptions{})
	bcancel()
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
	st := &txState{hooked: d.hook.get() != nil}
	if err := fn(context.WithValue(ctx, txCtxKey{}, struct{}{}), tx{t: pgtx, st: st, guard: true}); err != nil {
		return err
	}
	if len(st.slots) > 0 {
		hook := d.hook.get()
		st.sealed = true
		// The hook's last lock is a hot row (the audit head): bound the wait.
		if _, err := pgtx.Exec(ctx, `SELECT set_config('lock_timeout', $1, true)`, hookLockTimeout); err != nil {
			return fmt.Errorf("store: set hook lock timeout: %w", err)
		}
		if err := hook(ctx, tx{t: pgtx, st: st}, tid); err != nil {
			return err
		}
		if len(st.slots) > 0 {
			return ErrUndrained
		}
	}
	if err := pgtx.Commit(ctx); err != nil {
		return fmt.Errorf("store: commit: %w", err)
	}
	committed = true
	return nil
}

// tx hides the pgx.Tx: no Commit, Rollback, Begin or Conn. guard refuses transaction-control SQL; the
// hook's own Tx is not guarded.
type tx struct {
	t     pgx.Tx
	st    *txState
	guard bool
}

func (x tx) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	if x.guard && isTxControl(sql) {
		return pgconn.CommandTag{}, ErrTxControl
	}
	return x.t.Exec(ctx, sql, args...)
}

func (x tx) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	if x.guard && isTxControl(sql) {
		return nil, ErrTxControl
	}
	return x.t.Query(ctx, sql, args...)
}

func (x tx) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	if x.guard && isTxControl(sql) {
		return errRow{ErrTxControl}
	}
	return x.t.QueryRow(ctx, sql, args...)
}

// noTenant is the zero tenant.ID: the transaction has no tenant (WithPlatform).
var noTenant tenant.ID
