// Package provision is the tenant-provisioning platform path: the code that creates a tenant, which by
// definition runs before that tenant exists. Today it holds the first-run bootstrap of a self-hosted
// install; SaaS tenant provisioning (capability "tenant-provisioning") will add its entry point here.
//
// It lives under internal/platform/tenant because tenant owns the tenants table (the exemption
// registry's owning package): only SQL in this tree may name public.tenants. Its entry points are
// listed in the exemption registry, which is what allows them to call store.WithPlatform and mint a
// tenant.ID (ADR-0002 rules 4 and 5).
package provision

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"unicode/utf8"

	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// Initialiser prepares one tenant's own data the first time it exists, for example audit.InitTenant's
// genesis chain head and first checkpoint key (ADR-0005 rule 11). It runs inside the tenant's own
// store.WithTenant transaction, after the tenants row has committed. It must be idempotent: FirstRun
// runs every initialiser again on each start, which is how a tenant left half-initialised by a crash is
// completed.
type Initialiser func(ctx context.Context, tx store.Tx, id tenant.ID) error

// Errors.
var (
	// ErrInvalidName is returned for a blank or over-long name, invalid UTF-8 or a NUL (rule 7: PostgreSQL
	// cannot store NUL in text).
	ErrInvalidName = errors.New("provision: the tenant name must be 1 to 200 characters of valid text without NUL")
	// ErrNotSingleTenant is returned when the database already holds more than one tenant: first-run
	// bootstrap is for a single-tenant self-hosted install, and it will not guess which tenant is meant.
	ErrNotSingleTenant = errors.New("provision: more than one tenant exists: first-run bootstrap is for a single-tenant install")
)

const maxNameLen = 200

// firstRunLockKey serialises concurrent first starts (two nodes booting together) so that exactly one
// creates the tenant. It is a transaction-level advisory lock: it ends with the transaction.
const firstRunLockKey int64 = 0x61646951_5f545031 // "adiQ_TP1"

// Result says which tenant the install has and whether this call created it.
type Result struct {
	Tenant  tenant.ID
	Created bool
}

// FirstRun makes sure a self-hosted install has exactly one tenant, then runs the initialisers for it.
//
// If the database holds no tenant, it creates one named name with a random UUID (never a constant:
// ADR-0002 rule 5). If it holds one, that is the tenant and nothing is created. More than one is
// ErrNotSingleTenant. Running it again is a no-op apart from the idempotent initialisers, so it is safe
// on every start and from several nodes at once.
//
// The tenants row commits under store.WithPlatform before any initialiser runs, and the initialisers
// run in the new tenant's first store.WithTenant transaction (ADR-0005 rule 11). If an initialiser
// fails, the tenant exists and the next FirstRun completes it.
func FirstRun(ctx context.Context, db *store.DB, name string, inits ...Initialiser) (Result, error) {
	if !validName(name) {
		return Result{}, ErrInvalidName
	}
	var res Result
	err := db.WithPlatform(ctx, "first-run bootstrap: ensure the install's single tenant exists", func(ctx context.Context, tx store.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, firstRunLockKey); err != nil {
			return fmt.Errorf("provision: lock: %w", err)
		}
		rows, err := tx.Query(ctx, `SELECT id::text FROM public.tenants ORDER BY created_at, id LIMIT 2`)
		if err != nil {
			return fmt.Errorf("provision: read tenants: %w", err)
		}
		defer rows.Close()
		var existing []string
		for rows.Next() {
			var s string
			if err := rows.Scan(&s); err != nil {
				return fmt.Errorf("provision: read tenants: %w", err)
			}
			existing = append(existing, s)
		}
		if err := rows.Err(); err != nil {
			return fmt.Errorf("provision: read tenants: %w", err)
		}
		rows.Close()
		switch len(existing) {
		case 0:
			id := tenant.New()
			if _, err := tx.Exec(ctx, `INSERT INTO public.tenants (id, name) VALUES ($1::uuid, $2)`, id.String(), name); err != nil {
				return fmt.Errorf("provision: create tenant: %w", err)
			}
			res = Result{Tenant: id, Created: true}
		case 1:
			id, err := tenant.Parse(existing[0])
			if err != nil {
				return fmt.Errorf("provision: the stored tenant id is not a UUID: %w", err)
			}
			res = Result{Tenant: id}
		default:
			return ErrNotSingleTenant
		}
		return nil
	})
	if err != nil {
		return Result{}, err
	}
	if res.Created {
		slog.InfoContext(ctx, "tenant created by first-run bootstrap", "tenant_id", res.Tenant.String())
	}
	if len(inits) == 0 {
		return res, nil
	}
	err = db.WithTenant(ctx, res.Tenant, func(ctx context.Context, tx store.Tx) error {
		for _, init := range inits {
			if err := init(ctx, tx, res.Tenant); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return res, fmt.Errorf("provision: initialise tenant %s: %w", res.Tenant, err)
	}
	return res, nil
}

func validName(s string) bool {
	return strings.TrimSpace(s) != "" && utf8.RuneCountInString(s) <= maxNameLen && utf8.ValidString(s) && !strings.ContainsRune(s, 0)
}
