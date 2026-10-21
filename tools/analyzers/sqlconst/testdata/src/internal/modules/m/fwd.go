package m

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
)

type wrap struct{ p *pgxpool.Pool }

// A wrapper outside policy.SQLForwarders is not exempt even when it forwards its parameter unchanged:
// otherwise its callers would pass built SQL unjudged (the wrapper is not a driverish type).
func (w wrap) Exec(ctx context.Context, sql string, args ...any) (any, error) {
	return w.p.Exec(ctx, sql, args...) // want `not a constant`
}

func useWrap(ctx context.Context, w wrap, name string) {
	w.Exec(ctx, "DELETE FROM t WHERE n='"+name+"'")
}

// A different name is a new query path, not an interface forwarder.
func (w wrap) Run(ctx context.Context, sql string) (any, error) {
	return w.p.Exec(ctx, sql) // want `not a constant`
}

// A parameter that is changed before the call is not forwarded as received.
func (w wrap) Query(ctx context.Context, sql string, args ...any) (any, error) {
	sql += " WHERE 1=1"
	return w.p.Query(ctx, sql, args...) // want `not a constant`
}

// A plain function has no interface to forward for.
func fwd(ctx context.Context, p *pgxpool.Pool, sql string) {
	p.Exec(ctx, sql) // want `not a constant`
}

// A local that shadows nothing and was never a parameter is reported.
func (w wrap) QueryRow(ctx context.Context, _ string, args ...any) any {
	q := "SELECT " + string(args[0].(string))
	return w.p.QueryRow(ctx, q) // want `not a constant`
}
