package ad

import (
	"context"

	"github.com/go-ldap/ldap/v3"
	"github.com/skenzeriq/activediq/internal/directory/dn"

	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
)

// DCIdentity names the domain controller a Session is bound to: the objectGUID of its NTDS Settings
// object (the DSA GUID, stable across renames and re-IPs) and its current invocationId.
type DCIdentity struct {
	DSAGUID      guid.GUID
	InvocationID guid.GUID
	DNSHostName  string
	Site         string
}

// DCIdentity reads the bound DC's identity on the bound session: rootDSE dsServiceName, then that
// NTDS Settings object's objectGUID and invocationId. Both reads use the one connection, so the
// answer is about the DC later requests on this session reach. Any failure is an error (the caller
// must treat an unknown DC as not the pinned one).
func (s *Session) DCIdentity(ctx context.Context) (DCIdentity, error) {
	rd, err := s.RootDSE(ctx)
	if err != nil {
		return DCIdentity{}, err
	}
	if rd.DSServiceName == "" {
		return DCIdentity{}, fail(CodeProtocol, "rootDSE has no dsServiceName", nil)
	}
	res, err := s.searchOnce(ctx, rd.DSServiceName, ldap.ScopeBaseObject, objectClassPresent, []string{"objectGUID", "invocationId"}, nil)
	if err != nil {
		return DCIdentity{}, err
	}
	if len(res.Entries) != 1 {
		return DCIdentity{}, fail(CodeProtocol, "NTDS Settings object not returned", nil)
	}
	e := res.Entries[0]
	dsa, err := guid.FromBytes(e.GetRawAttributeValue("objectGUID"))
	if err != nil {
		return DCIdentity{}, fail(CodeProtocol, "NTDS Settings objectGUID is not a GUID", err)
	}
	inv, err := guid.FromBytes(e.GetRawAttributeValue("invocationId"))
	if err != nil {
		return DCIdentity{}, fail(CodeProtocol, "invocationId is not a GUID", err)
	}
	return DCIdentity{DSAGUID: dsa, InvocationID: inv, DNSHostName: rd.DNSHostName, Site: siteOf(rd.DSServiceName)}, nil
}

// siteOf extracts the site from CN=NTDS Settings,CN=<server>,CN=Servers,CN=<site>,CN=Sites,...
func siteOf(dsServiceName string) string {
	d, err := dn.Parse(dsServiceName, dn.Strict) // the DC's own output; a multi-valued RDN is an error here
	if err != nil || d.Len() < 4 {
		return ""
	}
	return d.RDNs()[3].Value()
}
