package read_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/skenzeriq/activediq/internal/connector/ad"
	"github.com/skenzeriq/activediq/internal/connector/read"
	"github.com/skenzeriq/activediq/internal/connector/write"
	"github.com/skenzeriq/activediq/internal/directory/attr/sid"
	"github.com/skenzeriq/activediq/internal/directory/client"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

const (
	domGUID = "11111111-2222-3333-4444-555555555555"
	cfgGUID = "66666666-7777-8888-9999-aaaaaaaaaaaa"
)

// describing adds the optional topology half to the read fake.
type describing struct {
	*src
	top *ad.Topology
	err error
}

func (d *describing) Topology(context.Context) (*ad.Topology, error) { return d.top, d.err }

func describeReq() *connectorv1.DescribeRequest {
	return &connectorv1.DescribeRequest{Connection: &connectorv1.ConnectionRef{ConnectionId: "c1", DirectoryIdentity: ident}}
}

func TestDescribeServesNamingContextsAndLimits(t *testing.T) {
	s, err := sid.Parse("S-1-5-21-1-2-3")
	if err != nil {
		t.Fatal(err)
	}
	d := &describing{src: &src{dsa: dsaA}, top: &ad.Topology{
		NamingContexts: []ad.NamingContext{
			{GUID: g(domGUID), Kind: ad.NCDomain, Head: "DC=lab,DC=test", DNSName: "lab.test", NetBIOSName: "LAB", DomainSID: s, HasSID: true, FunctionalLevel: 7, HasFunctionalLevel: true},
			{GUID: g(cfgGUID), Kind: ad.NCConfiguration, Head: "CN=Configuration,DC=lab,DC=test"},
			{GUID: g(objGUID), Kind: ad.NCSchema, Head: "CN=Schema,CN=Configuration,DC=lab,DC=test"},
			{GUID: g(parGUID), Kind: ad.NCApplication, Head: "DC=DomainDnsZones,DC=lab,DC=test"},
		},
		Limits: ad.ServerLimits{MaxPageSize: 1000, MaxValueRange: 1500},
	}}
	resp, err := start(t, d).Describe(context.Background(), describeReq())
	if err != nil {
		t.Fatal(err)
	}
	if resp.GetContract() != "activediq.connector.v1" || resp.GetProviderKind() != connectorv1.ProviderKind_PROVIDER_KIND_AD {
		t.Errorf("contract/provider = %q / %v", resp.GetContract(), resp.GetProviderKind())
	}
	// T-1583 AC1: APPLY and PLAN are SUPPORTED through Describe, naming the four account kinds.
	var seen int
	for _, o := range resp.GetOperations() {
		if o.GetOperation() != connectorv1.Operation_OPERATION_PLAN && o.GetOperation() != connectorv1.Operation_OPERATION_APPLY {
			continue
		}
		seen++
		if o.GetState() != connectorv1.SupportState_SUPPORT_STATE_SUPPORTED {
			t.Errorf("%v = %v", o.GetOperation(), o.GetState())
		}
		for _, k := range []string{"USER_PASSWORD_RESET", "USER_UNLOCK", "ACCOUNT_ENABLE", "ACCOUNT_DISABLE"} {
			if !strings.Contains(o.GetReason(), k) {
				t.Errorf("%v reason %q lacks %s", o.GetOperation(), o.GetReason(), k)
			}
		}
	}
	if seen != 2 {
		t.Errorf("operations = %v", resp.GetOperations())
	}
	if resp.GetLimits().GetMaxPageSize() != 1000 || resp.GetLimits().GetMaxValueRange() != 1500 {
		t.Errorf("limits = %v", resp.GetLimits())
	}
	want := []connectorv1.NamingContextKind{
		connectorv1.NamingContextKind_NAMING_CONTEXT_KIND_DOMAIN, connectorv1.NamingContextKind_NAMING_CONTEXT_KIND_CONFIGURATION,
		connectorv1.NamingContextKind_NAMING_CONTEXT_KIND_SCHEMA, connectorv1.NamingContextKind_NAMING_CONTEXT_KIND_APPLICATION}
	ncs := resp.GetNamingContexts()
	if len(ncs) != len(want) {
		t.Fatalf("%d naming contexts, want %d", len(ncs), len(want))
	}
	for i, k := range want {
		if ncs[i].GetKind() != k {
			t.Errorf("nc %d kind = %v, want %v", i, ncs[i].GetKind(), k)
		}
	}
	dom := ncs[0]
	if got := string(dom.GetNcGuid().GetValue()); got != string(write.GUIDToWire(g(domGUID)).GetValue()) {
		t.Errorf("domain nc_guid is not the wire form of the objectGUID")
	}
	if string(dom.GetDomainSid().GetValue()) != string(s.Bytes()) || dom.GetDnsName() != "lab.test" || dom.GetNetbiosName() != "LAB" ||
		dom.GetHead().GetDisplayDn() != "DC=lab,DC=test" || dom.FunctionalLevel == nil || dom.GetFunctionalLevel() != 7 {
		t.Errorf("domain nc = %v", dom)
	}
	if ncs[1].DomainSid != nil || ncs[1].FunctionalLevel != nil {
		t.Errorf("configuration nc carries domain facts: %v", ncs[1])
	}
}

func TestDescribeRefusals(t *testing.T) {
	good := &describing{src: &src{dsa: dsaA}, top: &ad.Topology{}}
	other := &connectorv1.DirectoryIdentity{Identity: &connectorv1.DirectoryIdentity_AdForest{AdForest: &connectorv1.AdForestIdentity{
		ForestRootNcGuid: &connectorv1.Guid{Value: []byte("fedcba9876543210")}}}}
	for name, c := range map[string]struct {
		src  read.Source
		req  *connectorv1.DescribeRequest
		want connectorv1.ErrorCode
	}{
		"no connection":           {good, &connectorv1.DescribeRequest{}, connectorv1.ErrorCode_ERROR_CODE_INVALID_ARGUMENT},
		"identity mismatch":       {good, &connectorv1.DescribeRequest{Connection: &connectorv1.ConnectionRef{ConnectionId: "c1", DirectoryIdentity: other}}, connectorv1.ErrorCode_ERROR_CODE_DIRECTORY_IDENTITY_MISMATCH},
		"source without topology": {&src{dsa: dsaA}, describeReq(), connectorv1.ErrorCode_ERROR_CODE_CAPABILITY_UNSUPPORTED},
		"directory unreachable":   {&describing{src: &src{dsa: dsaA}, err: ad.NewError(ad.CodeUnreachable)}, describeReq(), connectorv1.ErrorCode_ERROR_CODE_UNREACHABLE_DC},
		"other DC after":          {&describing{src: &src{dsa: dsaA, dcAfter: dsaB}, top: &ad.Topology{}}, describeReq(), connectorv1.ErrorCode_ERROR_CODE_UNREACHABLE_DC},
	} {
		t.Run(name, func(t *testing.T) {
			resp, err := start(t, c.src).Describe(context.Background(), c.req)
			if err == nil {
				t.Fatalf("answered: %v", resp)
			}
			var re *client.RemoteError
			if !errors.As(client.FromStatus(err), &re) || re.Err.GetCode() != c.want {
				t.Errorf("error = %v, want code %v", err, c.want)
			}
		})
	}
}
