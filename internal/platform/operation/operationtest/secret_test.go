package operationtest

import (
	"strings"
	"testing"

	"github.com/skenzeriq/activediq/internal/platform/operation"
)

// testSecret stands in for secretattr.IsStatic, which the kernel's test helpers may not import.
func testSecret(name string) bool {
	switch strings.ToLower(name) {
	case "unicodepwd", "ms-mcs-admpwd", "mslaps-password":
		return true
	}
	return false
}

func withSecret(fx Fixture) Fixture {
	if fx.SecretAttr == nil {
		fx.SecretAttr = testSecret
	}
	return fx
}

func chk(t testing.TB, a operation.Action, fx Fixture) (Record, []Violation) {
	t.Helper()
	return check(t, a, withSecret(fx))
}

func chkWith(t testing.TB, a operation.Action, fx Fixture, o options) (Record, []Violation) {
	t.Helper()
	return checkWith(t, a, withSecret(fx), o)
}

func Chk(t testing.TB, a operation.Action, fx Fixture) []Violation {
	t.Helper()
	return Check(t, a, withSecret(fx))
}

// Contract refuses a Fixture without SecretAttr: the runner needs it and the AG-9 check relies on it.
func TestCheckRequiresSecretAttr(t *testing.T) {
	a, fx := newFixture("test.thing.modify")
	vs := Check(t, a, fx)
	if len(vs) != 1 || vs[0].Clause != ClauseDescriptor || !strings.Contains(vs[0].Detail, "SecretAttr") {
		t.Fatalf("Check without SecretAttr: %v", vs)
	}
}
