package provider

import (
	"bytes"

	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// Supports derives the Describe rows of p's contract groups from the facets p implements. Nothing
// else declares provider support, so a provider cannot claim a group it does not implement. The
// write group's rows come from write's operation table (write.Capabilities); the rows here are
// VERIFY_CONNECTION, READ and SCOPED_SEARCH.
//
// READ needs ObjectReader and DCBound: the Read header is pinned to, and re-checked against, the
// serving DC. SCOPED_SEARCH needs the same and Searcher.
func Supports(p Provider) []*connectorv1.OperationSupport {
	_, rights := p.(RightsSource)
	_, reader := p.(ObjectReader)
	_, dc := p.(DCBound)
	_, search := p.(Searcher)
	return []*connectorv1.OperationSupport{
		row(connectorv1.Operation_OPERATION_VERIFY_CONNECTION, rights, "provider has no rights-source facet"),
		row(connectorv1.Operation_OPERATION_READ, reader && dc, "provider has no object-reader and DC-bound facets"),
		row(connectorv1.Operation_OPERATION_SCOPED_SEARCH, reader && dc && search, "provider has no searcher facet"),
	}
}

func row(op connectorv1.Operation, ok bool, reason string) *connectorv1.OperationSupport {
	if ok {
		return &connectorv1.OperationSupport{Operation: op, State: connectorv1.SupportState_SUPPORT_STATE_SUPPORTED}
	}
	return &connectorv1.OperationSupport{Operation: op, State: connectorv1.SupportState_SUPPORT_STATE_UNSUPPORTED, Reason: reason}
}

// Matches reports whether evidence names the object whose live anchors are a (F4).
func (a Anchors) Matches(ev *connectorv1.CorrelationEvidence) bool {
	switch x := ev.GetEvidence().(type) {
	case *connectorv1.CorrelationEvidence_SourceAnchor:
		for _, s := range a.Source {
			if len(x.SourceAnchor) > 0 && bytes.Equal(s, x.SourceAnchor) {
				return true
			}
		}
	case *connectorv1.CorrelationEvidence_SecurityIdentifier:
		for _, s := range a.SIDs {
			if len(x.SecurityIdentifier.GetValue()) > 0 && bytes.Equal(s, x.SecurityIdentifier.GetValue()) {
				return true
			}
		}
	}
	return false
}
