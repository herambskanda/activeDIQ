// This file is the only place in compose/agent that names an agent module (blueprint §2 rule 5).
// tools/gen/modules does not exist yet, so it is maintained by hand and must stay this small.

package agent

import (
	"github.com/skenzeriq/activediq/internal/agentmodules/addc"
	kernel "github.com/skenzeriq/activediq/internal/platform/agent"
	"github.com/skenzeriq/activediq/internal/platform/fleet"
)

// buildModule returns the module for a component kind. A kind with no module here has no agent.
func buildModule(kind string, dcGUID string) (kernel.Module, bool) {
	switch kind {
	case fleet.KindADDC:
		return addc.New(addc.NewSource(), dcGUID), true
	}
	return nil, false
}
