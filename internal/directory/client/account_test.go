package client

import (
	"context"
	"errors"
	"testing"

	"github.com/skenzeriq/activediq/internal/directory/accountkind"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/operation"
	"github.com/skenzeriq/activediq/internal/platform/operation/step"
)

// withKind mints a Step whose digest is for the given account kind and an empty diff.
func withKind(t *testing.T, key string, target authority.TargetRef, diff []operation.Change, fn func(ctx context.Context, s step.Step)) {
	t.Helper()
	pins := authority.Pins{ncGUID: "dc1.corp.example"}
	withStepKind(t, target, pins, dsasFor(pins), key, diff, fn)
}

// Acceptance 3: an unlock digest replayed against a disable payload is refused by the client before
// any transport call.
func TestUnlockDigestReplayedAsDisableRefused(t *testing.T) {
	tr := &transport{}
	c := New(WithTransport(tr), WithFacts(&facts{}), WithTier0Builder(&builder{}))
	withKind(t, accountkind.KeyUnlock, acctTarget, []operation.Change{}, func(ctx context.Context, s step.Step) {
		_, err := c.Write(ctx, s, WriteOp{DigestKind: accountkind.KeyDisable, Target: acctTarget})
		if !errors.Is(err, ErrDigest) {
			t.Errorf("got %v, want ErrDigest", err)
		}
	})
	if tr.plans != 0 || tr.applies != 0 {
		t.Errorf("transport reached: plans=%d applies=%d", tr.plans, tr.applies)
	}
}

func TestAccountKindsCarryChangeOnPlanAndApply(t *testing.T) {
	for _, key := range []string{accountkind.KeyUnlock, accountkind.KeyEnable, accountkind.KeyDisable} {
		tr := &transport{}
		c := New(WithTransport(tr), WithFacts(&facts{}), WithTier0Builder(&builder{}))
		withKind(t, key, acctTarget, []operation.Change{}, func(ctx context.Context, s step.Step) {
			if _, err := c.Write(ctx, s, WriteOp{DigestKind: key, Target: acctTarget}); err != nil {
				t.Fatalf("%s: %v", key, err)
			}
		})
		if tr.planReq.GetChange() == nil || tr.applyReq.GetChange() == nil {
			t.Errorf("%s: change arm missing on plan=%v apply=%v", key, tr.planReq.GetChange() != nil, tr.applyReq.GetChange() != nil)
		}
		sp, _ := accountkind.ByKey(key)
		if tr.planReq.GetKind() != sp.Kind || tr.applyReq.GetSecretInput() != nil {
			t.Errorf("%s: kind %v secret %v", key, tr.planReq.GetKind(), tr.applyReq.GetSecretInput())
		}
	}
}

func resetDiff() []operation.Change {
	return []operation.Change{
		{Attribute: accountkind.AttrMustChange, After: []string{"true"}},
		{Attribute: accountkind.AttrSecret, Secret: true},
	}
}

func TestResetWithoutStepSecretRefused(t *testing.T) {
	tr := &transport{}
	c := New(WithTransport(tr), WithFacts(&facts{}), WithTier0Builder(&builder{}))
	withKind(t, accountkind.KeyResetPassword, acctTarget, resetDiff(), func(ctx context.Context, s step.Step) {
		op := WriteOp{DigestKind: accountkind.KeyResetPassword, Target: acctTarget, Attrs: []step.Attr{
			{Name: accountkind.AttrMustChange, Values: []string{"true"}}, {Name: accountkind.AttrSecret, Secret: true}}}
		if _, err := c.Write(ctx, s, op); !errors.Is(err, ErrNoSecret) {
			t.Errorf("got %v, want ErrNoSecret", err)
		}
	})
	if tr.applies != 0 {
		t.Error("apply reached without a secret")
	}
}

func TestDeriveChangeGuards(t *testing.T) {
	good := WriteOp{DigestKind: accountkind.KeyUnlock, Target: acctTarget}
	cases := map[string]struct {
		mut  func(*WriteOp)
		want error
	}{
		"wrong class":         {func(o *WriteOp) { o.Target.Class = "group" }, ErrKindClass},
		"upper-case guid":     {func(o *WriteOp) { o.Target.GUID = "6F1C2A40-0000-4000-8000-0000000000BB" }, ErrNotCanonical},
		"stray attr":          {func(o *WriteOp) { o.Attrs = []step.Attr{{Name: "description", Values: []string{"x"}}} }, ErrKindAttrs},
		"computer for unlock": {func(o *WriteOp) { o.Target.Class = "computer" }, ErrKindClass},
	}
	for name, tc := range cases {
		op := good
		tc.mut(&op)
		if err := op.deriveChange(&wire{}); !errors.Is(err, tc.want) {
			t.Errorf("%s: got %v, want %v", name, err, tc.want)
		}
	}
	// reset: attrs shaped right derive a change that is marked as needing a secret.
	w := wire{}
	reset := WriteOp{DigestKind: accountkind.KeyResetPassword, Target: acctTarget, Attrs: []step.Attr{
		{Name: accountkind.AttrMustChange, Values: []string{"false"}}, {Name: accountkind.AttrSecret, Secret: true}}}
	if err := reset.deriveChange(&w); err != nil || w.change == nil || !w.secret {
		t.Errorf("reset derive: err=%v change=%v secret=%v", err, w.change, w.secret)
	}
}
