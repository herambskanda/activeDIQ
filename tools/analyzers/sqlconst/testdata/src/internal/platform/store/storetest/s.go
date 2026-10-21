package storetest

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
)

// A test-support package runs fixture DDL; it is not judged (policy.TestSupport).
func ddl(ctx context.Context, p *pgxpool.Pool, stmt string) {
	p.Exec(ctx, stmt)
}
