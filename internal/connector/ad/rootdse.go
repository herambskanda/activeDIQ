package ad

import (
	"context"
	"strconv"

	"github.com/go-ldap/ldap/v3"
)

// RootDSE is the subset of the DC's rootDSE the connector uses.
type RootDSE struct {
	DNSHostName                   string
	ServerName                    string
	DefaultNamingContext          string
	RootDomainNamingContext       string
	ConfigurationNamingContext    string
	SchemaNamingContext           string
	NamingContexts                []string
	SupportedControls             []string
	SupportedCapabilities         []string
	DomainFunctionality           int
	ForestFunctionality           int
	DomainControllerFunctionality int
	HighestCommittedUSN           int64
	IsSynchronized                bool
	IsGlobalCatalogReady          bool
}

// SupportsControl reports whether the DC advertises the control OID.
func (r RootDSE) SupportsControl(oid string) bool {
	for _, c := range r.SupportedControls {
		if c == oid {
			return true
		}
	}
	return false
}

var rootDSEAttrs = []string{
	"dnsHostName", "serverName", "defaultNamingContext", "rootDomainNamingContext",
	"configurationNamingContext", "schemaNamingContext", "namingContexts", "supportedControl",
	"supportedCapabilities", "domainFunctionality", "forestFunctionality",
	"domainControllerFunctionality", "highestCommittedUSN", "isSynchronized", "isGlobalCatalogReady",
}

// RootDSE reads the rootDSE of the bound DC (anonymous-readable, but read on the bound session so
// the answer is the same DC the later requests use).
func (s *Session) RootDSE(ctx context.Context) (*RootDSE, error) {
	res, err := s.searchOnce(ctx, "", ldap.ScopeBaseObject, objectClassPresent, rootDSEAttrs, nil)
	if err != nil {
		return nil, err
	}
	if len(res.Entries) != 1 {
		return nil, fail(CodeProtocol, "rootDSE not returned", nil)
	}
	e := res.Entries[0]
	one := func(n string) string { return e.GetAttributeValue(n) }
	num := func(n string) int { v, _ := strconv.Atoi(one(n)); return v }
	usn, _ := strconv.ParseInt(one("highestCommittedUSN"), 10, 64)
	return &RootDSE{
		DNSHostName:                   one("dnsHostName"),
		ServerName:                    one("serverName"),
		DefaultNamingContext:          one("defaultNamingContext"),
		RootDomainNamingContext:       one("rootDomainNamingContext"),
		ConfigurationNamingContext:    one("configurationNamingContext"),
		SchemaNamingContext:           one("schemaNamingContext"),
		NamingContexts:                e.GetAttributeValues("namingContexts"),
		SupportedControls:             e.GetAttributeValues("supportedControl"),
		SupportedCapabilities:         e.GetAttributeValues("supportedCapabilities"),
		DomainFunctionality:           num("domainFunctionality"),
		ForestFunctionality:           num("forestFunctionality"),
		DomainControllerFunctionality: num("domainControllerFunctionality"),
		HighestCommittedUSN:           usn,
		IsSynchronized:                one("isSynchronized") == "TRUE",
		IsGlobalCatalogReady:          one("isGlobalCatalogReady") == "TRUE",
	}, nil
}
