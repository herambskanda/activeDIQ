// Package moduletest is the test kit for module unit tests (ADR-0003 rule 5). Register runs a
// module through the same validations as module.Boot, against a real, private Registrar, and hands
// the contributions back. It touches no host, so nothing it does reaches a running process.
package moduletest

import (
	"context"
	"fmt"

	"github.com/skenzeriq/activediq/internal/platform/capability"
	"github.com/skenzeriq/activediq/internal/platform/module"
)

// Register boots m alone, with every capability it requires enabled, and returns what it
// contributed. Any Boot validation failure (namespacing, duplicates, ID rules) is the error.
func Register(m module.Module) (*module.Contributions, error) {
	if m == nil {
		return nil, fmt.Errorf("%w: nil module", module.ErrInvalid)
	}
	enabled := capability.NewSet(m.Requires()...)
	return module.Boot(context.Background(), []module.Entry{{ID: m.ID(), Module: m}}, enabled)
}
