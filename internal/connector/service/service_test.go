package service_test

import (
	"errors"
	"testing"

	"github.com/skenzeriq/activediq/internal/connector/provider"
	"github.com/skenzeriq/activediq/internal/connector/provider/entra"
	"github.com/skenzeriq/activediq/internal/connector/rights"
	"github.com/skenzeriq/activediq/internal/connector/service"
	"github.com/skenzeriq/activediq/internal/connector/write"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

type nopBase struct{}

func (nopBase) Append(string, []write.Mark) error { return nil }

func deps(t *testing.T) service.Deps {
	t.Helper()
	g, err := write.NewGateBook(nopBase{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return service.Deps{Gate: g, Epoch: rights.NewEpochState(nil, nil, nil)}
}

func TestNewRefusesIncompleteDeps(t *testing.T) {
	p := &entra.EntraProvider{TenantID: "t"}
	if _, err := service.New(nil, deps(t)); !errors.Is(err, service.ErrDeps) {
		t.Errorf("nil provider: %v", err)
	}
	d := deps(t)
	d.Gate = nil
	if _, err := service.New(p, d); !errors.Is(err, service.ErrDeps) {
		t.Errorf("nil gate: %v", err)
	}
	d = deps(t)
	d.Epoch = nil
	if _, err := service.New(p, d); !errors.Is(err, service.ErrDeps) {
		t.Errorf("nil epoch: %v", err)
	}
}

// A core-only provider builds a Service; its capabilities are the provider's Supports rows plus the
// write group's, and every provider-derived group is UNSUPPORTED.
func TestCoreOnlyProviderService(t *testing.T) {
	var p provider.Provider = &entra.EntraProvider{TenantID: "t"}
	s, err := service.New(p, deps(t))
	if err != nil {
		t.Fatal(err)
	}
	if s.Server() == nil || s.Read() == nil || s.Write() == nil || s.Verify() == nil {
		t.Fatal("missing handle")
	}
	got := s.Capabilities()
	want := append(provider.Supports(p), write.Capabilities()...)
	if len(got) != len(want) {
		t.Fatalf("got %d rows, want %d", len(got), len(want))
	}
	for i := range got {
		if got[i].GetOperation() != want[i].GetOperation() || got[i].GetState() != want[i].GetState() {
			t.Errorf("row %d: %v != %v", i, got[i], want[i])
		}
	}
	for _, r := range provider.Supports(p) {
		if r.GetState() != connectorv1.SupportState_SUPPORT_STATE_UNSUPPORTED {
			t.Errorf("%s: %s", r.GetOperation(), r.GetState())
		}
	}
}

// kindAD claims the AD kind but exposes no DCBound facet.
type kindAD struct{ provider.Provider }

func (kindAD) Kind() connectorv1.ProviderKind { return connectorv1.ProviderKind_PROVIDER_KIND_AD }

// An AD-kind provider that hides DCBound is refused at construction, not planned on the Entra plane.
func TestNewRefusesADKindWithoutDCBound(t *testing.T) {
	if _, err := service.New(kindAD{&entra.EntraProvider{TenantID: "t"}}, deps(t)); err == nil {
		t.Fatal("service built over an AD-kind provider without DCBound")
	}
}
