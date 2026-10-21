package wrap

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
)

type tx struct{ p *pgxpool.Pool }

// A thin wrapper forwards its own sql parameter to the same-named method: judged at its callers.
func (x tx) Exec(ctx context.Context, sql string, args ...any) (any, error) {
	return x.p.Exec(ctx, sql, args...)
}

// Forwarding under another name, or a different variable, is not a pass-through.
func (x tx) Run(ctx context.Context, sql string) (any, error) {
	return x.p.Exec(ctx, sql) // want `not a constant`
}

func (x tx) Query(ctx context.Context, sql string, other string) (any, error) {
	return x.p.Query(ctx, other) // want `not a constant`
}
