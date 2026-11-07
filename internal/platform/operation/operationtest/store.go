package operationtest

import (
	"context"
	"strings"
	"sync"
	"unicode"

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
	tx.Observe = tx.observe
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

// observe classifies what the Action sent. It is a text classification, never a way to build SQL,
// and it is the unit-level stand-in: the PostgreSQL-backed run (storetest) is the authority. Text is
// split with store.Lexings (store.Statements), the scanner the transaction-control guard uses, so a comment, a quoted
// identifier or a second statement cannot hide a write. Residuals only the PostgreSQL run catches: a
// writing function called from a SELECT, and other side-effecting built-ins not named below.
// The scanner reads UTF-8 text: a SET [LOCAL] client_encoding or SET NAMES is reported as a finding here
// (changesReadOnly), and the store guard refuses every statement once the session is not UTF8.
func (t *recordingTx) observe(sql string) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	var first error
	for _, lexing := range store.Lexings(sql) { // both string lexings: the session's setting is unknown
		for _, stmt := range lexing {
			if err := t.observeStatement(stmt); err != nil && first == nil {
				first = err
			}
		}
	}
	return first
}

func (t *recordingTx) observeStatement(stmt string) error {
	words := sqlWords(stmt)
	if len(words) == 0 {
		return nil
	}
	if !t.ReadOnly && len(words) >= 4 && words[0] == "SET" && words[1] == "TRANSACTION" && words[2] == "READ" && words[3] == "ONLY" {
		t.ReadOnly = true
		return nil
	}
	if store.IsTxControlStatement(stmt) {
		// The real store refuses these inside a body (store.ErrTxControl); a Plan that sends one is trying
		// to leave its READ ONLY transaction.
		if t.ReadOnly {
			t.roAttempts++
		}
		return store.ErrTxControl
	}
	switch {
	case changesReadOnly(words):
		// Leaving READ ONLY is itself a write attempt; so is any other change to the mode.
		if t.ReadOnly {
			t.roAttempts++
			return readOnlyErr(words[0] + " (read-only mode)")
		}
		return nil
	case isWrite(words):
		if t.ReadOnly {
			t.roAttempts++
			return readOnlyErr(words[0])
		}
		t.writes++
	}
	return nil
}

func readOnlyErr(stmt string) error {
	return storetest.ReadOnlyError(stmt)
}

// sqlWords returns the upper-case words of one statement from store.Statements (quoted text is
// already blanked).
func sqlWords(stmt string) []string {
	return strings.FieldsFunc(strings.ToUpper(stmt), func(r rune) bool { return !unicode.IsLetter(r) && r != '_' })
}

// changesReadOnly reports a statement that changes the transaction's read-only mode or the client
// encoding the scanner relies on: store.ChangesSessionSetting (set_config, transaction_read_only,
// client_encoding, SET NAMES) or SET TRANSACTION / SET SESSION CHARACTERISTICS … READ WRITE.
func changesReadOnly(words []string) bool {
	if store.ChangesSessionSetting(words) {
		return true
	}
	if words[0] == "SET" {
		for i := 1; i+1 < len(words); i++ {
			if words[i] == "READ" && words[i+1] == "WRITE" {
				return true
			}
		}
	}
	return false
}

var writeVerbs = map[string]bool{
	"INSERT": true, "UPDATE": true, "DELETE": true, "MERGE": true, "TRUNCATE": true, "CREATE": true,
	"ALTER": true, "DROP": true, "GRANT": true, "REVOKE": true, "COPY": true, "CALL": true, "DO": true,
	"REFRESH": true, "COMMENT": true, "LOCK": true, "NOTIFY": true, "REINDEX": true, "CLUSTER": true,
	"VACUUM": true, "IMPORT": true, "SECURITY": true, "DISCARD": true, "LISTEN": true, "UNLISTEN": true,
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
		case w == "INTO" && (words[0] == "SELECT" || words[0] == "WITH" || words[0] == "TABLE" || words[0] == "VALUES"):
			return true // SELECT … INTO creates a table
		case w == "NEXTVAL" || w == "SETVAL":
			return true // sequences are written by reading them
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
