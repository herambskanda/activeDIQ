package server

import (
	"github.com/skenzeriq/activediq/internal/platform/apihost"
)

// APIPolicy is the policy the server passes to apihost.Build: policy.yaml as embedded in the binary
// (policy.gen.json, parsed by apihost.ParsePolicy). fitness-api A4 compares it with the policy.yaml it
// reads from the tree. It panics if the embedded policy does not parse; TestEmbeddedPolicyBuilds and
// gen-api -check keep that from shipping.
func APIPolicy() apihost.Policy {
	p, err := apihost.LoadPolicy()
	if err != nil {
		panic("server: embedded api policy: " + err.Error())
	}
	return p
}
