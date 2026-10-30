package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/apihost"
	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/authn/tenantref"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/rbac"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// AuditPermissionDenied is the audit kind of an API request refused for a missing permission. The
// event names the permission and scope asked for, never the request's content.
const AuditPermissionDenied audit.Kind = "authz.permission.denied"

// tenantTx runs fn in a transaction scoped to a tenant. *store.DB satisfies it.
type tenantTx interface {
	WithTenant(ctx context.Context, id tenant.ID, fn func(ctx context.Context, tx store.Tx) error) error
}

// auditedAuthz records every refusal of the wrapped Authorizer in the tenant's audit trail (AG-2: a
// refused request is recorded as well as a failed one) and passes the decision through unchanged. A
// failure to record never turns a refusal into an approval: the request is still refused and the fault
// is logged. Only a principal that names a tenant can be recorded; a platform principal has no chain.
type auditedAuthz struct {
	next apihost.Authorizer
	db   tenantTx
	sink audit.Sink
	now  func() time.Time
	log  *slog.Logger
}

func (a auditedAuthz) Allow(ctx context.Context, p apihost.Principal, permission, scope string) (bool, error) {
	ok, err := a.next.Allow(ctx, p, permission, scope)
	if ok || err != nil {
		return ok, err // an infrastructure fault is not a refusal of the permission; the chain refuses it
	}
	a.record(ctx, p, permission, scope)
	return false, nil
}

func (a auditedAuthz) record(ctx context.Context, p apihost.Principal, permission, scope string) {
	tid, err := tenantref.TenantFromText(p.Tenant)
	if err != nil || p.ID == "" {
		return
	}
	kind := authority.Human
	if p.Kind == apihost.KindToken {
		kind = authority.APIToken
	}
	var idb [16]byte
	if _, err := rand.Read(idb[:]); err != nil {
		a.log.Error("authz denial audit: no entropy", "error_class", "entropy")
		return
	}
	ev := audit.Event{
		ID: hex.EncodeToString(idb[:]), Kind: AuditPermissionDenied, At: a.now(),
		Actor:     authority.Chain{Requester: authority.Principal{ID: authority.PrincipalID(p.ID), Kind: kind}},
		Target:    authority.TargetRef{Class: rbac.TargetClassTenant, GUID: tid.String()},
		Component: "server", Outcome: audit.Denied, Reason: "permission_denied",
		Details: []audit.Detail{{Key: "permission", Value: permission}, {Key: "scope", Value: scope}},
	}
	// The caller's context may be cancelled by the very client that was refused; the record is kept anyway.
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	if err := a.db.WithTenant(rctx, tid, func(ctx context.Context, tx store.Tx) error {
		return a.sink.Append(ctx, tx, ev)
	}); err != nil {
		a.log.Error("authz denial audit: not recorded", "error_class", "audit")
	}
}
