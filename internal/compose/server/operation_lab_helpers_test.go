//go:build lab

package server

import (
	"context"
	"io"
	"slices"
	"sync"
	"testing"

	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
	"github.com/skenzeriq/activediq/internal/directory/connection"
	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/audit/chain"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/operation/step"
	"github.com/skenzeriq/activediq/internal/platform/rbac"
	"github.com/skenzeriq/activediq/internal/platform/store"
)

var ioEOF = io.EOF

func contains(s []string, v string) bool { return slices.Contains(s, v) }

func connectionIdentity(nc string) connection.DirectoryIdentity {
	return connection.DirectoryIdentity(nc)
}

func mustUUID(t *testing.T, s string) []byte {
	t.Helper()
	b := make([]byte, 0, 16)
	for i := 0; i < len(s); i++ {
		if s[i] == '-' {
			continue
		}
		var v byte
		for _, c := range []byte{s[i], s[i+1]}[:2] {
			v <<= 4
			switch {
			case c >= '0' && c <= '9':
				v |= c - '0'
			case c >= 'a' && c <= 'f':
				v |= c - 'a' + 10
			default:
				t.Fatalf("bad uuid %q", s)
			}
		}
		i++
		b = append(b, v)
	}
	return b
}

// labPins is an in-memory write.PinStore for the connector's classifier.
type labPins struct {
	mu sync.Mutex
	g  []guid.GUID
}

func (m *labPins) PinnedC13(context.Context) ([]guid.GUID, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]guid.GUID(nil), m.g...), nil
}
func (m *labPins) PinC13(_ context.Context, gs []guid.GUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.g = append(m.g, gs...)
	return nil
}

// assignRole grants role to acct over one OU subtree root.
func assignRole(t *testing.T, e *bkEnv, role, acct, ouGUID string) {
	t.Helper()
	e.exec(t, `INSERT INTO public.authz_assignments (tenant_id, account_id, role_id, valid_from, granted_by, assignment_state)
		SELECT $1::uuid, $2::uuid, r.id, now() - interval '2 hours', 'test', 'active' FROM public.authz_roles r WHERE r.tenant_id = $1::uuid AND r.role_name = $3`, e.ten.String(), acct, role)
	e.exec(t, `INSERT INTO public.authz_assignment_roots (tenant_id, assignment_id, ordinal, is_exclude, root_kind, connection_id, root_guid)
		SELECT $1::uuid, a.id, 0, false, $3, $4::uuid, $5::uuid FROM public.authz_assignments a WHERE a.tenant_id = $1::uuid AND a.account_id = $2::uuid ORDER BY a.id DESC LIMIT 1`,
		e.ten.String(), acct, string(rbac.OUSubtree), e.ad, ouGUID)
}

// itemReason is the reason recorded on item 0 of an operation.
func itemReason(t *testing.T, e *bkEnv, op step.OperationID) string {
	t.Helper()
	var reason *string
	err := e.db.WithTenant(context.Background(), e.ten, func(ctx context.Context, tx store.Tx) error {
		return tx.QueryRow(ctx, `SELECT reason FROM public.operation_items WHERE tenant_id = $1::uuid AND operation_id = $2::uuid AND item_no = 0`, e.ten.String(), string(op)).Scan(&reason)
	})
	if err != nil {
		t.Fatalf("reading item reason: %v", err)
	}
	if reason == nil {
		return ""
	}
	return *reason
}

// auditOutcomes returns the outcome of every chained event written by component, oldest first.
func auditOutcomes(t *testing.T, e *bkEnv, cp *audit.Checkpointer, ctx context.Context, component string) []string {
	t.Helper()
	human := authority.Chain{Requester: authority.Principal{ID: "auditor", Kind: authority.Human}}
	b, err := audit.NewExporter(cp).Export(ctx, e.db, e.ten, human, 0, 0)
	if err != nil {
		t.Fatalf("audit export: %v", err)
	}
	var out []string
	for _, ev := range b.Events {
		env, err := chain.ParseEnvelope(ev.Envelope)
		if err != nil {
			t.Fatal(err)
		}
		if env.Component == component {
			out = append(out, env.Outcome)
		}
	}
	return out
}
