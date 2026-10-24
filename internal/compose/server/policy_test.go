package server

import (
	"strings"
	"testing"

	"github.com/skenzeriq/activediq/internal/compose/config"
	"github.com/skenzeriq/activediq/internal/platform/apihost"
)

// The server router follows the parsed policy file, not a Go copy: edit the fixture policy and the
// router changes (T-0088).
func TestBuildAPIFollowsPolicyFile(t *testing.T) {
	cfg := config.Config{APIBodyBudget: config.DefaultAPIBodyBudget}
	build := func(doc string) error {
		p, err := apihost.ParsePolicy([]byte(doc))
		if err != nil {
			t.Fatalf("fixture policy: %v", err)
		}
		_, err = buildAPIWith(cfg, p, testLimiter(t))
		return err
	}
	row := func(op, extra string) string {
		return `{"operation": "` + op + `", ` + extra + `"gate": "none", "reason": "r", "ref": "AN-1"}`
	}
	both := `{"anonymous": [` + row("getLiveness", "") + `, ` + row("getReadiness", "") + `]}`
	if err := build(both); err != nil {
		t.Fatalf("both health rows: %v", err)
	}
	if err := build(`{"anonymous": [` + row("getLiveness", "") + `]}`); err == nil || !strings.Contains(err.Error(), "getReadiness") {
		t.Errorf("dropping a row must fail Build naming the operation, got %v", err)
	}
	// A host binding in the file reaches the router: it is refused until a hostname is configured.
	bound := `{"anonymous": [` + row("getLiveness", `"host": "sspr", `) + `, ` + row("getReadiness", "") + `]}`
	if err := build(bound); err == nil || !strings.Contains(err.Error(), "sspr") {
		t.Errorf("a host binding in the policy must reach Build, got %v", err)
	}
}

func TestEmbeddedPolicyBuilds(t *testing.T) {
	if _, err := buildAPI(config.Config{APIBodyBudget: config.DefaultAPIBodyBudget}, testLimiter(t)); err != nil {
		t.Fatal(err)
	}
}
