package store

import (
	"context"
	"time"
)

type Tx interface{}
type ID string

type DB struct{}

func (d *DB) WithTenant(ctx context.Context, id ID, fn func(ctx context.Context, tx Tx) error) error {
	return fn(ctx, nil)
}

func (d *DB) WithPlatform(ctx context.Context, reason string, fn func(ctx context.Context, tx Tx) error) error {
	return fn(ctx, nil)
}

func (d *DB) WithTenantSeparate(ctx context.Context, id ID, wait time.Duration, fn func(ctx context.Context, tx Tx) error) error {
	return fn(ctx, nil)
}
