package x

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
)

func tierL(ctx context.Context, p *pgxpool.Pool, q string) { p.Exec(ctx, q) }
