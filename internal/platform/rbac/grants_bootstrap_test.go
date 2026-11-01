package rbac

import (
	"context"
	"errors"
	"testing"

	"github.com/skenzeriq/activediq/internal/platform/authority"
)

// T-0808 AC2: GrantBootstrap accepts exactly one system principal, the install-time CLI. The identity
// check runs before any database access, so these cases need no store (a nil tx would panic if reached).
func TestGrantBootstrapRefusesEveryOtherChain(t *testing.T) {
	sys := func(id authority.PrincipalID) authority.Principal {
		return authority.Principal{ID: id, Kind: authority.System}
	}
	for name, by := range map[string]authority.Chain{
		"other system principal": {Requester: sys("job-runner")},
		"authn-password":         {Requester: sys("authn-password")},
		"bootstrap id as human":  {Requester: authority.Principal{ID: BootstrapPrincipal, Kind: authority.Human}},
		"bootstrap via a token":  {Requester: sys(BootstrapPrincipal), Via: []authority.Principal{{Kind: authority.APIToken, ID: "tok"}}},
		"bootstrap via system":   {Requester: sys(BootstrapPrincipal), Via: []authority.Principal{sys("job-runner")}},
		"empty chain":            {},
	} {
		err := (&Grants{}).GrantBootstrap(context.Background(), nil, by, GrantInput{})
		if !errors.Is(err, ErrActorNotDirect) {
			t.Errorf("%s: want ErrActorNotDirect, got %v", name, err)
		}
	}
}
