package authn

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/store"
)

// Audit kinds of the session lifecycle (DM-31). Every event names the session by its handle and the
// account; none carries the token or its hash.
const (
	KindSessionCreated audit.Kind = "authn.session.created"
	KindSessionEvicted audit.Kind = "authn.session.evicted" // ended by the concurrent-session limit
	KindSessionExpired audit.Kind = "authn.session.expired" // idle or absolute timeout
	KindSessionRevoked audit.Kind = "authn.session.revoked" // logout, on demand, account events
	// KindSessionsPurged is what the retention purge records about itself.
	KindSessionsPurged audit.Kind = "authn.sessions.purged"
)

// systemChain is the actor of an end the store itself causes: a timeout, or the concurrent limit.
var systemChain = authority.Chain{Requester: authority.Principal{ID: "authn", Kind: authority.System}}

// accountChain is the actor of a sign-in or a sign-out: the account itself. For a delegated account
// the requester is the account's pseudonymous ID, as everywhere else in the trail.
func accountChain(account string) authority.Chain {
	return authority.Chain{Requester: authority.Principal{ID: authority.PrincipalID(account), Kind: authority.Human}}
}

// endStmt names one of the constant UPDATE ... RETURNING statements that end sessions. The statement
// text is chosen here and never passed in, so every query is a constant (safe-primitives §7).
type endStmt int

const (
	endExpireDue endStmt = iota
	endEvict
	endRevokeAccount
	endRevokeSession
	endRevokeToken
)

// sessionRows is what endRows reads from a statement's result.
type sessionRows interface {
	Next() bool
	Scan(dest ...any) error
	Err() error
	Close()
}

func (e endStmt) query(ctx context.Context, tx store.Tx, args []any) (sessionRows, error) {
	switch e {
	case endExpireDue:
		return tx.Query(ctx, expireDue, args...)
	case endEvict:
		return tx.Query(ctx, evict, args...)
	case endRevokeAccount:
		return tx.Query(ctx, sqlRevokeAccount, args...)
	case endRevokeSession:
		return tx.Query(ctx, sqlRevokeSession, args...)
	case endRevokeToken:
		return tx.Query(ctx, sqlRevokeToken, args...)
	}
	return nil, errors.New("authn: unknown session statement")
}

// endRows runs an UPDATE ... RETURNING id, account_id, end_reason that ends sessions, and records one
// event of kind per ended session in the same transaction. by is nil for the system.
func (s *Store) endRows(ctx context.Context, tx store.Tx, now time.Time, stmt endStmt, args []any, kind audit.Kind, by func(account string) authority.Chain) (int, error) {
	type ended struct{ id, account, reason string }
	var out []ended
	rows, err := stmt.query(ctx, tx, args)
	if err != nil {
		return 0, err
	}
	for rows.Next() {
		var e ended
		if err := rows.Scan(&e.id, &e.account, &e.reason); err != nil {
			rows.Close()
			return 0, err
		}
		out = append(out, e)
	}
	rows.Close() // the connection is busy until the rows are closed
	if err := rows.Err(); err != nil {
		return 0, err
	}
	for _, e := range out {
		actor := systemChain
		if by != nil {
			actor = by(e.account)
		}
		if err := s.emit(ctx, tx, now, kind, e.id, e.account, actor, e.reason, nil); err != nil {
			return 0, err
		}
	}
	return len(out), nil
}

// emit appends one session lifecycle event. The event ID is stable per session and phase, so a retried
// transaction cannot record it twice.
func (s *Store) emit(ctx context.Context, tx store.Tx, now time.Time, kind audit.Kind, sessionID, account string, actor authority.Chain, reason string, methods []string) error {
	phase := "ended"
	if kind == KindSessionCreated {
		phase = "created"
	}
	// Keys are in increasing order, as the envelope requires.
	details := []audit.Detail{{Key: "account", Value: account}}
	if len(methods) > 0 {
		details = append(details, audit.Detail{Key: "methods", Value: strings.Join(methods, ",")})
	}
	ev := audit.Event{
		ID: "authn.session." + sessionID + "." + phase, Kind: kind, At: now, Actor: actor,
		Target:    authority.TargetRef{GUID: sessionID, Class: "session"},
		Component: "authn", Outcome: audit.Success, Reason: reason, Details: details,
	}
	if err := s.audit.Append(ctx, tx, ev); err != nil {
		return fmt.Errorf("authn: audit session event: %w", err)
	}
	return nil
}
