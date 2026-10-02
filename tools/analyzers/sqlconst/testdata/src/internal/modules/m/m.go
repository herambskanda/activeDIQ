package m

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
	"internal/platform/store/reportsql"
)

const listUsers = "SELECT id FROM users WHERE tenant_id = $1"

func f(ctx context.Context, p *pgxpool.Pool, name string, c reportsql.CompiledSQL) {
	p.Exec(ctx, listUsers, 1)
	p.Exec(ctx, "SELECT 1")
	p.Query(ctx, string(c))                                // want `not a constant`
	p.Query(ctx, "SELECT id FROM t WHERE n = '"+name+"'")  // want `not a constant`
	p.QueryRow(ctx, fmt.Sprintf("SELECT %s FROM t", name)) // want `not a constant`
	p.Exec(ctx, name)                                      // want `not a constant`
	p.Exec(ctx, "SELECT id FROM users"+" WHERE a = $1", name)
}
