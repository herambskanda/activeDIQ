package reports

import (
	"context"

	"github.com/skenzeriq/activediq/internal/modules/reports/api"
	"github.com/skenzeriq/activediq/internal/platform/apihost/apitypes"
)

// pending answers the operations whose rows of modules/reports.md 12 have not landed. They are in the contract
// and mounted, and until their row lands they answer 501 not-implemented rather than a made-up body. Each row
// deletes its methods here.
type pending struct{}

// ListReportRunPolicyTargets (T-1718) is in the contract ahead of the policy dataset (T-1114, inventory.policies).
// Until the dataset lands no run holds a policy row, so every policyId is "not a policy row of the run"; the
// honest answer is 501 rather than a made-up empty page, which a client would read as "no direct targets".
func (pending) ListReportRunPolicyTargets(context.Context, api.ListReportRunPolicyTargetsInput) (api.ListReportRunPolicyTargetsOutput, error) {
	return nil, apitypes.NotImplemented("not available yet (policy dataset, T-1114)")
}

// GetReportRunRowDetail (T-1717) is in the contract ahead of the read behind it (T-2117). Until then the honest
// answer is 501, not an empty or invented detail a client would read as "no attributes changed".
func (pending) GetReportRunRowDetail(context.Context, api.GetReportRunRowDetailInput) (api.GetReportRunRowDetailOutput, error) {
	return nil, apitypes.NotImplemented("not available yet (change-history row detail, T-2117)")
}

var _ api.Handlers = (*Handlers)(nil)
