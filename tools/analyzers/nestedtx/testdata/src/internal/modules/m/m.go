package m

import (
	"context"

	"internal/platform/store"
)

type other struct{}

func (other) WithTenant(ctx context.Context, fn func(context.Context) error) error { return fn(ctx) }

func helper(ctx context.Context, db *store.DB) error { return db.WithTenant(ctx, "t", nil) }

func bad(ctx context.Context, db *store.DB) error {
	return db.WithTenant(ctx, "t", func(c context.Context, tx store.Tx) error {
		_ = db.WithTenant(c, "t", nil)                    // want `nested store transaction: WithTenant`
		_ = db.WithPlatform(c, "r", nil)                  // want `nested store transaction: WithPlatform`
		_ = db.WithTenant(context.Background(), "t", nil) // want `nested store transaction` `Background inside`
		_ = context.TODO()                                // want `TODO inside`
		_ = db.WithTenant(ctx, "t", nil)                  // want `nested store transaction`
		func() { _ = context.Background() }()             // want `Background inside`
		return nil
	})
}

func badPlatform(ctx context.Context, db *store.DB) error {
	return db.WithPlatform(ctx, "why", func(c context.Context, tx store.Tx) error {
		return db.WithTenant(c, "t", func(c2 context.Context, tx2 store.Tx) error { // want `nested store transaction`
			_ = context.Background() // want `Background inside`
			return nil
		})
	})
}

func good(ctx context.Context, db *store.DB, o other) error {
	_ = context.Background()
	_ = db.WithTenant(ctx, "t", nil)
	return db.WithTenant(ctx, "t", func(c context.Context, tx store.Tx) error {
		_ = c.Err()
		_ = helper(c, db) // indirect call: accepted residual (ADR-0005 rule 11)
		return o.WithTenant(c, func(context.Context) error { return nil })
	})
}
