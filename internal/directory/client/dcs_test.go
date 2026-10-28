package client

import (
	"errors"
	"testing"

	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

const (
	dNC  = "aaaaaaaa-0000-0000-0000-0000000000a1"
	dNC2 = "aaaaaaaa-0000-0000-0000-0000000000a2"
	dCfg = "aaaaaaaa-0000-0000-0000-0000000000c0"
)

func dcInfo(host, dsa, nc string, rodc connectorv1.TriState, reachable bool) *connectorv1.DomainControllerInfo {
	return &connectorv1.DomainControllerInfo{
		Identity:     &connectorv1.DcIdentity{DsaGuid: guidOf(dsa), DnsHostname: host},
		DomainNcGuid: guidOf(nc),
		IsRodc:       rodc,
		Reachable:    reachable,
	}
}

func describeOf(dcs ...*connectorv1.DomainControllerInfo) *connectorv1.DescribeResponse {
	return &connectorv1.DescribeResponse{
		NamingContexts: []*connectorv1.NamingContextInfo{
			{NcGuid: guidOf(dNC), Kind: connectorv1.NamingContextKind_NAMING_CONTEXT_KIND_DOMAIN},
			{NcGuid: guidOf(dNC2), Kind: connectorv1.NamingContextKind_NAMING_CONTEXT_KIND_DOMAIN},
			{NcGuid: guidOf(dCfg), Kind: connectorv1.NamingContextKind_NAMING_CONTEXT_KIND_CONFIGURATION},
		},
		DomainControllers: dcs,
	}
}

func TestWritableDCsFiltersAndDecodes(t *testing.T) {
	f, tr := connectorv1.TriState_TRI_STATE_FALSE, connectorv1.TriState_TRI_STATE_TRUE
	resp := describeOf(
		dcInfo("dc2.example.test", "66666666-7777-8888-9999-aaaaaaaaaaaa", dNC, f, true),
		dcInfo("dc1.example.test", "11111111-2222-3333-4444-555555555555", dNC, f, true),
		dcInfo("rodc.example.test", "22222222-2222-3333-4444-555555555555", dNC, tr, true),
		dcInfo("unknown.example.test", "33333333-2222-3333-4444-555555555555", dNC, connectorv1.TriState_TRI_STATE_UNKNOWN, true),
		dcInfo("down.example.test", "44444444-2222-3333-4444-555555555555", dNC, f, false),
		dcInfo("other.example.test", "55555555-2222-3333-4444-555555555555", dNC2, f, true),
	)
	nc, _ := parseUUID(dNC)
	got, err := writableDCsOf(resp, nc)
	if err != nil || len(got) != 2 || got[0].Host != "dc1.example.test" || got[0].DSAGUID != "11111111-2222-3333-4444-555555555555" || got[1].Host != "dc2.example.test" {
		t.Fatalf("got %+v, %v", got, err)
	}
}

func TestWritableDCsForestWideNCUsesEveryWritableDC(t *testing.T) {
	f := connectorv1.TriState_TRI_STATE_FALSE
	resp := describeOf(dcInfo("a.example.test", "11111111-2222-3333-4444-555555555555", dNC, f, true), dcInfo("b.example.test", "66666666-7777-8888-9999-aaaaaaaaaaaa", dNC2, f, true))
	nc, _ := parseUUID(dCfg)
	if got, err := writableDCsOf(resp, nc); err != nil || len(got) != 2 {
		t.Fatalf("got %+v, %v", got, err)
	}
}

func TestWritableDCsRefusesUnknownNCAndBadIdentity(t *testing.T) {
	f := connectorv1.TriState_TRI_STATE_FALSE
	other, _ := parseUUID("bbbbbbbb-0000-0000-0000-000000000000")
	if _, err := writableDCsOf(describeOf(), other); !errors.Is(err, ErrDCNC) {
		t.Fatalf("unknown NC: %v", err)
	}
	nc, _ := parseUUID(dNC)
	for name, dc := range map[string]*connectorv1.DomainControllerInfo{
		"nil guid":   dcInfo("a.example.test", "00000000-0000-0000-0000-000000000000", dNC, f, true),
		"no host":    dcInfo("", "11111111-2222-3333-4444-555555555555", dNC, f, true),
		"short guid": {Identity: &connectorv1.DcIdentity{DsaGuid: &connectorv1.Guid{Value: []byte{1, 2}}, DnsHostname: "a"}, DomainNcGuid: guidOf(dNC), IsRodc: f, Reachable: true},
	} {
		if got, err := writableDCsOf(describeOf(dc), nc); !errors.Is(err, ErrDCIdentity) || got != nil {
			t.Errorf("%s: got %+v, %v", name, got, err)
		}
	}
}
