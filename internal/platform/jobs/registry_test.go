package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

func TestRegisterAndLookup(t *testing.T) {
	r := NewRegistry()
	k := Kind{Name: "a.b", Timeout: time.Minute, Mode: ModeManagedTx}
	if err := r.Register(k); err != nil {
		t.Fatal(err)
	}
	got, ok := r.Lookup("a.b")
	if !ok || got.Name != "a.b" || got.Timeout != time.Minute || got.Mode != ModeManagedTx {
		t.Fatalf("Lookup = %+v, %v", got, ok)
	}
	if l := r.Leases(); len(l) != 1 || l[0].Lease != time.Minute+ClaimGrace {
		t.Fatalf("Leases = %+v", l)
	}
}

func TestRegisterRefusals(t *testing.T) {
	r := NewRegistry()
	if err := r.Register(Kind{Name: "a.b", Timeout: time.Minute, Mode: ModeDefault}); err != nil {
		t.Fatal(err)
	}
	cases := map[string]struct {
		k    Kind
		want error
	}{
		"duplicate":    {Kind{Name: "a.b", Timeout: time.Hour, Mode: ModeDefault}, ErrKindRegistered},
		"zero timeout": {Kind{Name: "a.c", Mode: ModeDefault}, ErrInvalid},
		"neg timeout":  {Kind{Name: "a.c", Timeout: -1, Mode: ModeDefault}, ErrInvalid},
		"huge timeout": {Kind{Name: "a.c", Timeout: 48 * time.Hour, Mode: ModeDefault}, ErrInvalid},
		"zero mode":    {Kind{Name: "a.c", Timeout: time.Minute}, ErrInvalid},
		"unknown mode": {Kind{Name: "a.c", Timeout: time.Minute, Mode: 9}, ErrInvalid},
		"bad name":     {Kind{Name: "A C", Timeout: time.Minute, Mode: ModeDefault}, ErrInvalid},
	}
	for name, c := range cases {
		if err := r.Register(c.k); !errors.Is(err, c.want) {
			t.Errorf("%s: err = %v, want %v", name, err, c.want)
		}
	}
	if _, ok := r.Lookup("a.c"); ok {
		t.Error("a refused kind was registered")
	}
	if got, _ := r.Lookup("a.b"); got.Timeout != time.Minute {
		t.Error("a duplicate replaced the original")
	}
	if len(r.Leases()) != 1 {
		t.Errorf("registry holds %d kinds, want 1", len(r.Leases()))
	}
}

// The refusals below happen before SQL: the transaction is nil, so any use of it would panic.
func TestEnqueueRefusedBeforeSQL(t *testing.T) {
	r := NewRegistry()
	_ = r.Register(Kind{Name: "t.kind", Timeout: time.Minute, Mode: ModeDefault})
	_ = r.Register(Kind{Name: "p.kind", Timeout: time.Minute, Mode: ModeDefault, Platform: true})
	tid := tenant.New()
	ctx := context.Background()

	_, err := r.Enqueue(ctx, nil, Job{Kind: "no.such", Tenant: tid, Args: map[string]string{"secret": "hunter2"}})
	if !errors.Is(err, ErrKindUnknown) || !strings.Contains(err.Error(), "no.such") || strings.Contains(err.Error(), "hunter2") {
		t.Errorf("unregistered kind: %v", err)
	}
	if _, err := r.Enqueue(ctx, nil, Job{Kind: "t.kind"}); !errors.Is(err, ErrKindScope) {
		t.Errorf("tenant-less job of a tenant kind: %v", err)
	}
	if _, err := r.Enqueue(ctx, nil, Job{Kind: "p.kind", Tenant: tid}); !errors.Is(err, ErrKindScope) {
		t.Errorf("tenant job of a platform kind: %v", err)
	}
}

func TestEnqueueValidatesArgs(t *testing.T) {
	r := NewRegistry()
	_ = r.Register(Kind{Name: "v.kind", Timeout: time.Minute, Mode: ModeDefault,
		ValidateArgs: func(a json.RawMessage) error {
			var v struct {
				ID int64 `json:"id"`
			}
			dec := json.NewDecoder(strings.NewReader(string(a)))
			dec.DisallowUnknownFields()
			if err := dec.Decode(&v); err != nil {
				return errors.New("args do not match the kind's shape")
			}
			return nil
		}})
	_, err := r.Enqueue(context.Background(), nil, Job{Kind: "v.kind", Tenant: tenant.New(), Args: map[string]string{"name": "alice"}})
	if !errors.Is(err, ErrInvalid) || strings.Contains(err.Error(), "alice") {
		t.Errorf("untyped args: %v", err)
	}
}
