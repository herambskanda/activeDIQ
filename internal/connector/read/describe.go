package read

import (
	"context"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/skenzeriq/activediq/internal/connector/ad"
	"github.com/skenzeriq/activediq/internal/connector/write"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// contractName is the contract this connector speaks (connector-contract §4).
const contractName = "activediq.connector.v1"

func invalidDescribe(field string) error {
	r := write.NewRefusal(connectorv1.ErrorCode_ERROR_CODE_INVALID_ARGUMENT, connectorv1.RetryAdvice_RETRY_ADVICE_NEVER, "invalid request")
	r.Err.Details = &connectorv1.ConnectorError_RejectedInput{RejectedInput: &connectorv1.RejectedInputDetails{RuleId: "InvalidDescribeRequest", Field: field}}
	return r
}

// Describe serves the topology half of Describe (connector-contract §4): the naming contexts with
// their kinds and the DC's paging limits, read live on the one bound session (the connector keeps no
// cache, so Refresh changes nothing). The capability, feature, DC and health sections are the other
// groups' and are not set here. Every GUID is in wire order, as in Read.
func (h *Handler) Describe(ctx context.Context, req *connectorv1.DescribeRequest) (*connectorv1.DescribeResponse, error) {
	d, ok := h.src.(Describer)
	if !ok {
		return nil, refuse(connectorv1.ErrorCode_ERROR_CODE_CAPABILITY_UNSUPPORTED, connectorv1.RetryAdvice_RETRY_ADVICE_NEVER, "describe not supported")
	}
	if req.GetConnection().GetConnectionId() == "" || req.GetConnection().GetDirectoryIdentity() == nil {
		return nil, invalidDescribe("connection")
	}
	if !proto.Equal(req.GetConnection().GetDirectoryIdentity(), h.src.Identity()) {
		return nil, refuse(connectorv1.ErrorCode_ERROR_CODE_DIRECTORY_IDENTITY_MISMATCH, connectorv1.RetryAdvice_RETRY_ADVICE_NEVER, "directory identity mismatch")
	}
	before, err := h.bound(ctx, nil)
	if err != nil {
		return nil, err
	}
	top, err := d.Topology(ctx)
	if err != nil {
		return nil, mapAD(err, before)
	}
	// The topology must come from the DC it was asked of, as for Read.
	if _, err := h.bound(ctx, before.GetDsaGuid()); err != nil {
		return nil, err
	}
	out := &connectorv1.DescribeResponse{
		Contract:          contractName,
		ProviderKind:      connectorv1.ProviderKind_PROVIDER_KIND_AD,
		DirectoryIdentity: h.src.Identity(),
		DescribedAt:       timestamppb.New(h.now()),
		Limits:            &connectorv1.Limits{MaxPageSize: top.Limits.MaxPageSize, MaxValueRange: top.Limits.MaxValueRange},
	}
	out.Operations = write.Capabilities()
	for _, nc := range top.NamingContexts {
		info := &connectorv1.NamingContextInfo{
			NcGuid:      write.GUIDToWire(nc.GUID),
			Kind:        kindOf(nc.Kind),
			DnsName:     nc.DNSName,
			NetbiosName: nc.NetBIOSName,
			Head:        &connectorv1.DnValue{DisplayDn: nc.Head, Guid: write.GUIDToWire(nc.GUID)},
		}
		if nc.HasSID {
			info.DomainSid = &connectorv1.Sid{Value: nc.DomainSID.Bytes()}
			info.Head.Sid = &connectorv1.Sid{Value: nc.DomainSID.Bytes()}
		}
		if nc.HasFunctionalLevel {
			lvl := nc.FunctionalLevel
			info.FunctionalLevel = &lvl
		}
		out.NamingContexts = append(out.NamingContexts, info)
	}
	return out, nil
}

func kindOf(k ad.NCKind) connectorv1.NamingContextKind {
	switch k {
	case ad.NCDomain:
		return connectorv1.NamingContextKind_NAMING_CONTEXT_KIND_DOMAIN
	case ad.NCConfiguration:
		return connectorv1.NamingContextKind_NAMING_CONTEXT_KIND_CONFIGURATION
	case ad.NCSchema:
		return connectorv1.NamingContextKind_NAMING_CONTEXT_KIND_SCHEMA
	case ad.NCApplication:
		return connectorv1.NamingContextKind_NAMING_CONTEXT_KIND_APPLICATION
	}
	return connectorv1.NamingContextKind_NAMING_CONTEXT_KIND_UNSPECIFIED
}
