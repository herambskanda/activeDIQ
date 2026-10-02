package pgxpool

import "context"

type Pool struct{}

func (*Pool) Exec(ctx context.Context, sql string, args ...any) (any, error)  { return nil, nil }
func (*Pool) Query(ctx context.Context, sql string, args ...any) (any, error) { return nil, nil }
func (*Pool) QueryRow(ctx context.Context, sql string, args ...any) any       { return nil }
