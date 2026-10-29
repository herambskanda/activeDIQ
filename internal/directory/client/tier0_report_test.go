package client

import (
	"slices"
	"testing"

	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

func TestResultTier0AfterWrite(t *testing.T) {
	g := make([]byte, 16)
	g[0], g[15] = 0xab, 0x01
	r := Result{Apply: &connectorv1.ApplyResponse{Tier0AfterWrite: []*connectorv1.Tier0Member{
		{Object: &connectorv1.Guid{Value: g}, Basis: []connectorv1.Tier0Basis{connectorv1.Tier0Basis_TIER0_BASIS_C2_PROTECTED_GROUP_MEMBER, connectorv1.Tier0Basis_TIER0_BASIS_C11_DCSYNC_PRINCIPAL}},
		{Object: &connectorv1.Guid{Value: g}},
	}}}
	got := r.Tier0AfterWrite()
	if len(got) != 2 || got[0].Object != "ab000000-0000-0000-0000-000000000001" || !slices.Equal(got[0].Bases, []string{"C2", "C11"}) || len(got[1].Bases) != 0 {
		t.Fatalf("got %+v", got)
	}
	if (Result{NoOp: true}).Tier0AfterWrite() != nil {
		t.Fatal("a no-op reports findings")
	}
}
