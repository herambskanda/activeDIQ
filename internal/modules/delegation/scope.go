package delegation

import (
	"fmt"

	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/module"
	"github.com/skenzeriq/activediq/internal/platform/rbac"
)

// RootKindOUOneLevel is the assignment root kind for the direct children of an OU. The kind is
// assignable once T-0881 adds it to rbac; the evaluator is registered now so the read-scope
// consumers can start (T-0880).
const RootKindOUOneLevel = "ou_one_level"

// scopeEvaluator is the EP-6 evaluator for one directory root kind. The three kinds share this one
// shape and differ only in the name and the term they produce.
type scopeEvaluator struct {
	rootKind string
	term     authz.TermKind
}

// ScopeEvaluators returns the evaluators this module owns, one per directory root kind: the whole
// naming context, an OU and everything below it, and the direct children of an OU. Any other root
// kind (entra_tenant, tier0_scope, tenant, group_members, …) has none, so it contributes no
// directory read scope.
func ScopeEvaluators() []authz.ScopeEvaluator {
	return []authz.ScopeEvaluator{
		scopeEvaluator{string(rbac.NamingContext), authz.TermNamingContext},
		scopeEvaluator{string(rbac.OUSubtree), authz.TermSubtree},
		scopeEvaluator{RootKindOUOneLevel, authz.TermOneLevel},
	}
}

// RootKind implements authz.ScopeEvaluator.
func (e scopeEvaluator) RootKind() string { return e.rootKind }

// Term implements authz.ScopeEvaluator. A zero connection or root is refused: the caller must fail
// closed, because an exclude that could not be bound would otherwise widen the scope.
func (e scopeEvaluator) Term(connection, root authz.ObjectID) (authz.ScopeTerm, error) {
	if connection.IsZero() || root.IsZero() {
		return authz.ScopeTerm{}, fmt.Errorf("delegation: %s root needs a connection and a root: %w", e.rootKind, authz.ErrInvalidObjectID)
	}
	return authz.ScopeTerm{Kind: e.term, Connection: connection, Root: root}, nil
}

func registerScopeEvaluators(r *module.Registrar) error {
	for _, e := range ScopeEvaluators() {
		if err := r.ScopeEvaluator(e); err != nil {
			return err
		}
	}
	return nil
}
