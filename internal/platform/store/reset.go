package store

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Session-state reset (T-1313). A transaction body is caller code: it can run a session-level SET,
// set_config(..., false), SET SESSION AUTHORIZATION, create temp objects, LISTEN, take advisory locks or
// PREPARE a statement, and none of that ends with COMMIT. Left on a pooled connection it is inherited by the
// next borrower, who may be another tenant: search_path/pg_temp shadows that tenant's unqualified names, and
// client_encoding / standard_conforming_strings change how its SQL text is lexed (defeating the ErrTxControl
// scanner and pgx's sanitiser assumptions).
//
// Choice (recorded in the commit): every connection is reset when it is released (pgxpool AfterRelease); a
// connection whose reset fails, or that cannot be proven clean, is destroyed, never lent again. On acquire
// (PrepareConn) the cheap, round-trip-free ParameterStatus check is repeated as a second line, so a
// connection that somehow carries a lexing-relevant setting is destroyed instead of lent.
//
// Why not DISCARD ALL: it ends with DEALLOCATE ALL, which silently drops the statements behind pgx's
// per-connection statement cache (the default exec mode), so the next query on that connection fails with
// "prepared statement does not exist" or re-prepares every statement on every borrow. The batch below is
// DISCARD ALL minus DEALLOCATE ALL, in one simple-protocol round trip with no parameters (constant text).

// foreignPreparedPredicate selects the rows of pg_prepared_statements that pgx did not create (a body's own
// PREPARE). The name alone cannot be trusted: pgx names its cached statements deterministically,
// 'stmtcache_' || hex(sha256(sql)[0:24]) (pgx v5 internal/stmtcache), so a body could PREPARE a statement under
// a forged 'stmtcache_...' name, or DEALLOCATE a real cached name and re-PREPARE it with different SQL, and the
// victim's cache would then execute the planted statement. A statement is therefore pgx's own only if its name
// equals the hash of its own text; for a SQL-level PREPARE the statement column holds the PREPARE text, which
// cannot hash to the name it declares. A constant string: no value from the session is interpolated.
//
// Known gap, out of scope here: a body that DEALLOCATEs one of pgx's cached statements without replacing it
// leaves that connection's local cache stale, and the next query on it fails with "prepared statement does not
// exist" (an error, not a leak). Not detectable without a round trip per cached name.
const foreignPreparedPredicate = `(name !~ '^stmtcache_[0-9a-f]{48}$'
	OR name <> 'stmtcache_' || encode(substring(sha256(convert_to(statement, 'UTF8')) from 1 for 24), 'hex'))`

// resetSQL returns the connection to its start-up state. RESET ALL covers every session-level SET,
// set_config(..., false), SET ROLE and SET SESSION AUTHORIZATION (client_encoding returns to the start-up
// value pgx sent, UTF8). The final SELECT counts prepared statements pgx did not create (a body's own
// PREPARE): those cannot be cleared selectively without touching the statement cache, so such a connection
// is destroyed.
const resetSQL = `RESET ALL;
DISCARD TEMP;
DISCARD SEQUENCES;
CLOSE ALL;
UNLISTEN *;
SELECT pg_advisory_unlock_all();
SELECT count(*) FROM pg_prepared_statements WHERE ` + foreignPreparedPredicate

// resetTimeout bounds the reset round trip; a connection that cannot answer in time is destroyed.
const resetTimeout = 5 * time.Second

// errDirtyConn is why a connection was destroyed instead of lent; it never carries a value from the session.
var errDirtyConn = errors.New("store: connection state could not be proven clean")

// resetConn restores the start-up session state of c and verifies it. A non-nil error means the
// connection must be destroyed.
func resetConn(ctx context.Context, c *pgx.Conn) error {
	results, err := c.PgConn().Exec(ctx, resetSQL).ReadAll()
	if err != nil {
		return fmt.Errorf("store: reset connection: %w", err)
	}
	// The last result is the foreign-prepared-statement count.
	last := results[len(results)-1]
	if len(last.Rows) != 1 || len(last.Rows[0]) != 1 || string(last.Rows[0][0]) != "0" {
		return fmt.Errorf("%w: a statement outside pgx's cache is prepared on it", errDirtyConn)
	}
	return checkLexing(c)
}

// checkLexing verifies, from the ParameterStatus messages the server has sent (no round trip), the two
// settings that change how SQL text is lexed. Anything else is rejected, so a settings change the
// reset did not undo can never reach the next borrower.
func checkLexing(c *pgx.Conn) error {
	pc := c.PgConn()
	if ce := pc.ParameterStatus("client_encoding"); ce != "UTF8" {
		return fmt.Errorf("%w: client_encoding is %q", errDirtyConn, ce)
	}
	if sc := pc.ParameterStatus("standard_conforming_strings"); sc != "on" {
		return fmt.Errorf("%w: standard_conforming_strings is %q", errDirtyConn, sc)
	}
	return nil
}

// installReset wires the reset into a pool config. Called for the main and the separate pool alike.
func installReset(pc *pgxpool.Config) {
	pc.AfterRelease = func(c *pgx.Conn) bool {
		// Runs in pgxpool's goroutine with no caller context.
		ctx, cancel := context.WithTimeout(context.Background(), resetTimeout)
		defer cancel()
		if err := resetConn(ctx, c); err != nil {
			slog.Warn("store: destroying a pooled connection that could not be reset", "error", sanitize(err))
			return false
		}
		return true
	}
	pc.PrepareConn = func(_ context.Context, c *pgx.Conn) (bool, error) {
		if err := checkLexing(c); err != nil {
			slog.Warn("store: destroying a pooled connection with non-default lexing settings", "error", sanitize(err))
			return false, nil
		}
		return true, nil
	}
}

// sanitize keeps the server's message text out of the log: it can echo statement text.
func sanitize(err error) string {
	if errors.Is(err, errDirtyConn) {
		return err.Error()
	}
	return "reset round trip failed"
}
