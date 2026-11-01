package operationtest

import (
	"context"
	"errors"
	"strings"
	"sync"
	"unicode"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// rolledBackDB is the store the Contract runs against. Every transaction it opens is rolled back:
// WithTenant returns whatever the body returned and keeps nothing, so no run leaves state behind
// and a test can run the same Action again. It reuses storetest.FakeTx, the kernel's own fake
// transaction, and adds the statement bookkeeping the clauses need.
type rolledBackDB struct {
	mu  sync.Mutex
	txs []*recordingTx
}

func (d *rolledBackDB) WithTenant(ctx context.Context, id tenant.ID, fn func(context.Context, store.Tx) error) error {
	if id.IsZero() {
		return store.ErrNoTenant
	}
	tx := &recordingTx{}
	d.mu.Lock()
	d.txs = append(d.txs, tx)
	d.mu.Unlock()
	return fn(ctx, tx) // always rolled back: nothing is carried out of the transaction
}

// recordingTx is a FakeTx that classifies the statements it is given. In a READ ONLY transaction it
// refuses a write the way PostgreSQL does (SQLSTATE 25006) and remembers the attempt, so an Action
// that swallows the error is still caught.
type recordingTx struct {
	storetest.FakeTx
	mu         sync.Mutex
	writes     int // write statements that were accepted (transaction read write)
	roAttempts int // write statements refused or attempted while READ ONLY
}

func (t *recordingTx) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	if err := t.observe(sql); err != nil {
		return pgconn.CommandTag{}, err
	}
	return t.FakeTx.Exec(ctx, sql, args...)
}

func (t *recordingTx) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	if err := t.observe(sql); err != nil {
		return nil, err
	}
	return t.FakeTx.Query(ctx, sql, args...)
}

func (t *recordingTx) QueryRow(_ context.Context, sql string, _ ...any) pgx.Row {
	if err := t.observe(sql); err != nil {
		return errRow{err}
	}
	return errRow{errors.New("operationtest: the rolled-back store returns no rows")}
}

type errRow struct{ err error }

func (r errRow) Scan(...any) error { return r.err }

func (t *recordingTx) isReadOnly() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.ReadOnly
}

func (t *recordingTx) counts() (writes, roAttempts int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.writes, t.roAttempts
}

// observe classifies one statement. It is a text classification of what the Action sent, never a
// way to build SQL. The PostgreSQL-backed run (storetest) is the authority; this is the unit-level
// stand-in.
func (t *recordingTx) observe(sql string) error {
	words := sqlWords(sql)
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(words) >= 3 && words[0] == "SET" && words[1] == "TRANSACTION" && words[2] == "READ" && len(words) >= 4 {
		switch words[3] {
		case "ONLY":
			t.ReadOnly = true
			return nil
		case "WRITE":
			if t.ReadOnly { // leaving READ ONLY is itself a write attempt
				t.roAttempts++
				return readOnlyErr("SET TRANSACTION READ WRITE")
			}
			return nil
		}
	}
	if !isWrite(words) {
		return nil
	}
	if t.ReadOnly {
		t.roAttempts++
		return readOnlyErr(words[0])
	}
	t.writes++
	return nil
}

func readOnlyErr(stmt string) error {
	return &pgconn.PgError{Severity: "ERROR", Code: "25006", Message: "cannot execute " + stmt + " in a read-only transaction"}
}

// sqlWords returns the upper-case words of a statement with string literals removed.
func sqlWords(sql string) []string {
	var b strings.Builder
	in := false
	for _, r := range sql {
		switch {
		case r == '\'':
			in = !in
			b.WriteRune(' ')
		case in:
		default:
			b.WriteRune(r)
		}
	}
	return strings.FieldsFunc(strings.ToUpper(b.String()), func(r rune) bool { return !unicode.IsLetter(r) && r != '_' })
}

var writeVerbs = map[string]bool{
	"INSERT": true, "UPDATE": true, "DELETE": true, "MERGE": true, "TRUNCATE": true, "CREATE": true,
	"ALTER": true, "DROP": true, "GRANT": true, "REVOKE": true, "COPY": true, "CALL": true, "DO": true,
	"REFRESH": true, "COMMENT": true, "LOCK": true, "NOTIFY": true,
}

func isWrite(words []string) bool {
	if len(words) == 0 {
		return false
	}
	if writeVerbs[words[0]] {
		return true
	}
	for i, w := range words {
		switch {
		case (words[0] == "WITH" || words[0] == "EXPLAIN") && (w == "INSERT" || w == "UPDATE" || w == "DELETE" || w == "MERGE"):
			return true
		case w == "FOR" && i+1 < len(words) && (words[i+1] == "UPDATE" || words[i+1] == "SHARE" || words[i+1] == "NO" || words[i+1] == "KEY"):
			return true // row locks are refused in a READ ONLY transaction
		}
	}
	return false
}

// allowAll authorises every request: authorisation is not what the Contract tests.
type allowAll struct{}

func (allowAll) FactsQuery(_ authority.Chain, _ authz.Permission, t authority.TargetRef) authority.FactsQuery {
	return authority.FactsQuery{Target: t}
}

func (allowAll) Authorize(context.Context, authority.Chain, authz.Permission, authority.TargetRef, authority.Facts) error {
	return nil
}

// validatingSink validates each event and drops it with the transaction, as the rolled-back store does.
type validatingSink struct{}

func (validatingSink) Append(_ context.Context, _ store.Tx, ev audit.Event) error {
	return ev.Validate()
}
