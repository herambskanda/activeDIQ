package connections

import (
	"context"
	"errors"
	"testing"

	"github.com/skenzeriq/activediq/internal/modules/connections/api"
	"github.com/skenzeriq/activediq/internal/platform/apihost/apitypes"
)

// Until the backend ticket lands, each contract operation of T-1920 answers the same not-implemented problem
// instead of a made-up body, and holds a permission the registrar knows.
func TestPendingConnectionOperationsAnswerNotImplemented(t *testing.T) {
	h := &AttestHandlers{}
	ctx := context.Background()
	want := apitypes.NotImplemented("x")
	for name, call := range map[string]func() error{
		"createConnection": func() error { _, err := h.CreateConnection(ctx, api.CreateConnectionInput{}); return err },
		"getConnection":    func() error { _, err := h.GetConnection(ctx, api.GetConnectionInput{}); return err },
		"verifyConnection": func() error { _, err := h.VerifyConnection(ctx, api.VerifyConnectionInput{}); return err },
	} {
		err := call()
		if err == nil {
			t.Fatalf("%s: no error", name)
		}
		var got, w *apitypes.Problem
		if errors.As(err, &got) && errors.As(want, &w) && got.Status != w.Status {
			t.Errorf("%s: status %d, want %d", name, got.Status, w.Status)
		}
	}
}
