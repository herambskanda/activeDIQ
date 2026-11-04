package ad

import (
	"context"
	"net"
	"sort"
	"strings"

	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
	"github.com/skenzeriq/activediq/internal/directory/dn"
	"github.com/skenzeriq/activediq/internal/directory/ldapfilter"
)

// DomainController is one nTDSDSA object of the configuration NC: a DC known to the forest, reachable
// or not. Nothing is dropped because it cannot be contacted.
type DomainController struct {
	Host    string    // dNSHostName of the server object; empty if the server object has none
	Site    string    // the site's name
	DSAGUID guid.GUID // objectGUID of the NTDS Settings object
	// RODC is msDS-isRODC when the DC says; RODCKnown is false when it does not (never guessed).
	RODC, RODCKnown bool
}

// DomainControllers lists the DCs of the domain whose naming-context head is domainNC, from the
// configuration NC (CN=Sites): every nTDSDSA whose msDS-HasDomainNCs names domainNC. The list is
// whatever the bound DC's copy of the configuration NC holds, sorted by host then DSA GUID. A DC
// with no usable server object is returned with an empty Host; the caller reports it as unreachable
// rather than omit it.
func (s *Session) DomainControllers(ctx context.Context, domainNC dn.DN) ([]DomainController, error) {
	rd, err := s.RootDSE(ctx)
	if err != nil {
		return nil, err
	}
	cfg, err := dn.Parse(rd.ConfigurationNamingContext, dn.Strict)
	if err != nil || cfg.Len() == 0 {
		return nil, fail(CodeProtocol, "configurationNamingContext", err)
	}
	sites, err := dn.Child(cfg, dn.CN, "Sites")
	if err != nil {
		return nil, fail(CodeProtocol, "sites container", err)
	}
	oc, err := ldapfilter.ParseAttrName("objectClass", s.schema)
	if err != nil {
		return nil, fail(CodeInvalidArgument, "objectClass", err)
	}
	var out []DomainController
	var servers []dn.DN // servers[i] is the server object of out[i]
	err = s.Search(ctx, SearchRequest{
		Base: dn.DNRef(sites), Scope: ScopeSubtree, Filter: ldapfilter.Eq(oc, ldapfilter.String("nTDSDSA")),
		Attributes: []string{"objectGUID", "msDS-HasDomainNCs", "msDS-isRODC"},
	}, func(e *Entry) error {
		has := false
		for _, v := range e.Strings("msDS-HasDomainNCs") {
			if d, err := dn.Parse(v, dn.Strict); err == nil && d.Equal(domainNC) {
				has = true
			}
		}
		if !has {
			return nil
		}
		ntds, err := dn.Parse(e.DN, dn.Strict)
		if err != nil || ntds.Len() < 4 { // NTDS Settings, server, Servers, site, Sites…
			return fail(CodeProtocol, "NTDS Settings object in an unexpected place", err)
		}
		g, err := e.GUID()
		if err != nil {
			return err
		}
		server := ntds.Parent()
		dc := DomainController{DSAGUID: g, Site: server.Parent().Parent().RDNs()[0].Value()}
		if v := e.Strings("msDS-isRODC"); len(v) == 1 {
			switch strings.ToUpper(v[0]) {
			case "TRUE":
				dc.RODC, dc.RODCKnown = true, true
			case "FALSE":
				dc.RODCKnown = true
			}
		}
		out = append(out, dc)
		servers = append(servers, server)
		return nil
	})
	if err != nil {
		return nil, err
	}
	// The host name is on the server object: one base read per DC, after the search (a Search
	// callback must not call back into the Session).
	for i, srv := range servers {
		e, err := s.Read(ctx, dn.DNRef(srv), []string{"dNSHostName"}, ReadOptions{})
		if err != nil {
			if CodeOf(err) == CodeObjectNotFound {
				continue // no usable server object: the DC stays listed with an empty host
			}
			return nil, err
		}
		if h := e.Strings("dNSHostName"); len(h) == 1 && ValidDCHostname(h[0]) {
			out[i].Host = h[0]
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Host != out[j].Host {
			return out[i].Host < out[j].Host
		}
		return out[i].DSAGUID.String() < out[j].DSAGUID.String()
	})
	return out, nil
}

// ValidDCHostname reports whether h is a bare DNS host name safe to dial: no port, brackets, IP
// literal, or other punctuation. A directory-controlled value that fails is treated as no name.
func ValidDCHostname(h string) bool {
	if h == "" || len(h) > 253 || net.ParseIP(h) != nil {
		return false
	}
	for _, l := range strings.Split(strings.TrimSuffix(h, "."), ".") {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for _, c := range l {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return false
			}
		}
	}
	return true
}
