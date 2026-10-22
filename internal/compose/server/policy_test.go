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
	build := func(yaml string) error {
		p, err := apihost.ParsePolicy([]byte(yaml))
		if err != nil {
			t.Fatalf("fixture policy: %v", err)
		}
		_, err = buildAPIWith(cfg, p)
		return err
	}
	both := "anonymous:\n  - operation: getLiveness\n    gate: none\n    reason: r\n    ref: AN-1\n  - operation: getReadiness\n    gate: none\n    reason: r\n    ref: AN-1\n"
	if err := build(both); err != nil {
		t.Fatalf("both health rows: %v", err)
	}
	if err := build("anonymous:\n  - operation: getLiveness\n    gate: none\n    reason: r\n    ref: AN-1\n"); err == nil || !strings.Contains(err.Error(), "getReadiness") {
		t.Errorf("dropping a row must fail Build naming the operation, got %v", err)
	}
	// A host binding in the file reaches the router: it is refused until a hostname is configured.
	bound := strings.Replace(both, "  - operation: getLiveness\n", "  - operation: getLiveness\n    host: sspr\n", 1)
	if err := build(bound); err == nil || !strings.Contains(err.Error(), "sspr") {
		t.Errorf("a host binding in the policy must reach Build, got %v", err)
	}
}

func TestEmbeddedPolicyBuilds(t *testing.T) {
	if _, err := buildAPI(config.Config{APIBodyBudget: config.DefaultAPIBodyBudget}); err != nil {
		t.Fatal(err)
	}
}
