package directory

import (
	"context"

	"github.com/skenzeriq/activediq/internal/modules/directory/api"
	"github.com/skenzeriq/activediq/internal/platform/apihost/apitypes"
)

// explorerPending answers the AD Explorer operations (ADM-004, spec ad-explorer-read-api.md section 3)
// that are in the contract ahead of their implementation: the inventory port and the explorer module land
// in T-2089 (over reportsql.CompileTree, T-2088). Until then they answer 501 not-implemented rather than a
// made-up tree, which a client would read as "no objects in your scope". T-2089 deletes this file.
type explorerPending struct{}

func (explorerPending) ListExplorerRoots(context.Context, api.ListExplorerRootsInput) (api.ListExplorerRootsOutput, error) {
	return nil, apitypes.NotImplemented("not available yet (Explorer read model, T-2089)")
}

func (explorerPending) GetExplorerNode(context.Context, api.GetExplorerNodeInput) (api.GetExplorerNodeOutput, error) {
	return nil, apitypes.NotImplemented("not available yet (Explorer read model, T-2089)")
}

func (explorerPending) ListExplorerChildren(context.Context, api.ListExplorerChildrenInput) (api.ListExplorerChildrenOutput, error) {
	return nil, apitypes.NotImplemented("not available yet (Explorer read model, T-2089)")
}
