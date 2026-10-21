package store

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
)

// tx is the listed forwarder (policy.SQLForwarders): its forwarding line is not reported.
type tx struct{ p *pgxpool.Pool }

func (x tx) Exec(ctx context.Context, sql string, args ...any) (any, error) {
	return x.p.Exec(ctx, sql, args...)
}

// A parameter reassigned in a listed forwarder is still reported.
func (x tx) Query(ctx context.Context, sql string, args ...any) (any, error) {
	sql += " WHERE 1=1"
	return x.p.Query(ctx, sql, args...) // want `not a constant`
}

// A wrapper in the same package that is not listed is reported even though it forwards unchanged.
type other struct{ p *pgxpool.Pool }

func (o other) Exec(ctx context.Context, sql string, args ...any) (any, error) {
	return o.p.Exec(ctx, sql, args...) // want `not a constant`
}
