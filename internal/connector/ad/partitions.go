package ad

import (
	"context"
	"strconv"
	"strings"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"

	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
	"github.com/skenzeriq/activediq/internal/directory/attr/sid"
	"github.com/skenzeriq/activediq/internal/directory/dn"
	"github.com/skenzeriq/activediq/internal/directory/ldapfilter"
)

// NCKind is what a naming context is for.
type NCKind uint8

const (
	NCApplication NCKind = iota + 1
	NCDomain
	NCConfiguration
	NCSchema
)

// NamingContext is one partition of the forest, from its crossRef in CN=Partitions (MS-ADTS 6.1.1.2.1).
type NamingContext struct {
	GUID        guid.GUID // objectGUID of the NC head, from the extended form of crossRef nCName
	Kind        NCKind
	Head        string  // the head's DN, display only
	DNSName     string  // crossRef dnsRoot
	NetBIOSName string  // crossRef nETBIOSName (domains)
	DomainSID   sid.SID // the domain's SID (domain NCs); valid when HasSID
	HasSID      bool
	// FunctionalLevel is msDS-Behavior-Version of the domain head, known only for the domain the
	// bound DC serves (rootDSE domainFunctionality); other domains leave it unset.
	FunctionalLevel    uint32
	HasFunctionalLevel bool
}

// ServerLimits are the bound DC's LDAP limits as they bear on the connector's reads.
type ServerLimits struct {
	// MaxPageSize is the DC's MaxPageSize (lDAPAdminLimits) capped at what the session itself asks
	// for in one page (MaxPageSize const): the size a reader may rely on getting per page.
	MaxPageSize uint32
	// MaxValueRange is the DC's MaxValRange: values per attribute range.
	MaxValueRange uint32
}

// AD's documented defaults for the lDAPAdminLimits an administrator has not changed
// (MS-ADTS 3.1.1.3.4.7); used only when the DC's query policy does not carry the entry.
const (
	defaultAdminMaxPageSize = 1000
	defaultAdminMaxValRange = 1500
)

// Topology is what Describe reports about the directory itself.
type Topology struct {
	NamingContexts []NamingContext
	Limits         ServerLimits
}

const (
	extendedDNStringForm = 1 // extended DN control flag: GUID and SID as strings, not hex
	crossRefSysDomain    = 0x2
)

// extendedDNControl asks for <GUID=…>;<SID=…>;dn in DN-valued attributes (string form).
type extendedDNControl struct{}

func (extendedDNControl) GetControlType() string { return oidExtendedDN }
func (extendedDNControl) String() string         { return "Extended DN control" }
func (extendedDNControl) Encode() *berPacket {
	p := encodeValuelessControl(oidExtendedDN)
	val := ber.Encode(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, nil, "Control Value")
	seq := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "ExtendedDN")
	seq.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, int64(extendedDNStringForm), "Flag"))
	val.AppendChild(seq)
	p.AppendChild(val)
	return p
}

// Topology reads the forest's naming contexts and the DC's paging limits on the bound session. The
// partitions come from the crossRef objects in CN=Partitions,<configuration NC> (paged, one DC):
// kind from the crossRef's systemFlags, head GUID and domain SID from the extended form of nCName,
// so a domain this DC does not hold is described too. A crossRef that is not yet enabled (a partition
// being created) is not listed. Nothing is guessed: a crossRef whose nCName carries no GUID, or
// whose systemFlags cannot be read, fails the call.
func (s *Session) Topology(ctx context.Context) (*Topology, error) {
	rd, err := s.RootDSE(ctx)
	if err != nil {
		return nil, err
	}
	if rd.ConfigurationNamingContext == "" || rd.SchemaNamingContext == "" {
		return nil, fail(CodeProtocol, "rootDSE has no configuration or schema naming context", nil)
	}
	cfg, err := dn.Parse(rd.ConfigurationNamingContext, dn.Strict)
	if err != nil {
		return nil, fail(CodeProtocol, "configuration naming context is not a DN", err)
	}
	schema, err := dn.Parse(rd.SchemaNamingContext, dn.Strict)
	if err != nil {
		return nil, fail(CodeProtocol, "schema naming context is not a DN", err)
	}
	var local dn.DN
	hasLocal := rd.DefaultNamingContext != ""
	if hasLocal {
		if local, err = dn.Parse(rd.DefaultNamingContext, dn.Strict); err != nil {
			return nil, fail(CodeProtocol, "default naming context is not a DN", err)
		}
	}

	parts, err := dn.Child(cfg, dn.CN, "Partitions")
	if err != nil {
		return nil, fail(CodeInvalidArgument, "partitions container", err)
	}
	base, err := dn.DNRef(parts).ForRequest()
	if err != nil {
		return nil, fail(CodeInvalidArgument, "partitions container", err)
	}
	cls, err := ldapfilter.ParseAttrName("objectClass", DefaultSchema())
	if err != nil {
		return nil, fail(CodeInvalidArgument, "filter", err)
	}
	flt, err := ldapfilter.Render(ldapfilter.Eq(cls, ldapfilter.String("crossRef")), DefaultSchema())
	if err != nil {
		return nil, fail(CodeInvalidArgument, "filter", err)
	}

	t := &Topology{}
	attrs := []string{"nCName", "systemFlags", "dnsRoot", "nETBIOSName", "enabled"}
	err = s.pagesWith(ctx, base, ldap.ScopeSingleLevel, flt.String(), attrs, s.pageSize, []ldap.Control{extendedDNControl{}}, func(page []*Entry) error {
		for _, e := range page {
			nc, listed, err := namingContextOf(e, cfg, schema, local, hasLocal, rd)
			if err != nil {
				return err
			}
			if listed {
				t.NamingContexts = append(t.NamingContexts, nc)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	if t.Limits, err = s.serverLimits(ctx, rd, cfg); err != nil {
		return nil, err
	}
	return t, nil
}

func namingContextOf(e *Entry, cfg, schema, local dn.DN, hasLocal bool, rd *RootDSE) (NamingContext, bool, error) {
	if v := e.Strings("enabled"); len(v) == 1 && strings.EqualFold(v[0], "FALSE") {
		return NamingContext{}, false, nil
	}
	names := e.Strings("nCName")
	if len(names) != 1 {
		return NamingContext{}, false, fail(CodeProtocol, "crossRef has no single nCName", nil)
	}
	x, err := dn.ParseExtendedDN(names[0])
	if err != nil {
		return NamingContext{}, false, fail(CodeProtocol, "crossRef nCName has no GUID", err)
	}
	flags, ok, err := e.Int32("systemFlags")
	if err != nil || !ok {
		return NamingContext{}, false, fail(CodeProtocol, "crossRef systemFlags unreadable", err)
	}
	nc := NamingContext{GUID: x.GUID, Head: x.DN.String(), DNSName: first(e.Strings("dnsRoot")), NetBIOSName: first(e.Strings("nETBIOSName"))}
	switch {
	case x.DN.Equal(cfg):
		nc.Kind = NCConfiguration
	case x.DN.Equal(schema):
		nc.Kind = NCSchema
	case flags&crossRefSysDomain != 0:
		nc.Kind = NCDomain
		nc.DomainSID, nc.HasSID = x.SID, x.HasSID
		if hasLocal && x.DN.Equal(local) {
			nc.FunctionalLevel, nc.HasFunctionalLevel = uint32(rd.DomainFunctionality), true
		}
	default:
		nc.Kind = NCApplication
	}
	return nc, true, nil
}

func first(v []string) string {
	if len(v) == 0 {
		return ""
	}
	return v[0]
}

// serverLimits reads MaxPageSize and MaxValRange from the DC's query policy: the object its NTDS
// Settings names in queryPolicyObject, else CN=Default Query Policy (MS-ADTS 3.1.1.3.4.7). An entry
// the policy does not carry (or a policy that does not exist) is AD's documented default.
func (s *Session) serverLimits(ctx context.Context, rd *RootDSE, cfg dn.DN) (ServerLimits, error) {
	lim := ServerLimits{MaxPageSize: defaultAdminMaxPageSize, MaxValueRange: defaultAdminMaxValRange}
	policy, err := s.queryPolicyDN(ctx, rd, cfg)
	if err != nil {
		return lim, err
	}
	base, err := dn.DNRef(policy).ForRequest()
	if err != nil {
		return lim, fail(CodeInvalidArgument, "query policy", err)
	}
	res, err := s.searchOnce(ctx, base, ldap.ScopeBaseObject, objectClassPresent, []string{"lDAPAdminLimits"}, nil)
	switch {
	case CodeOf(err) == CodeObjectNotFound:
		// no such policy: the documented defaults stand
	case err != nil:
		return lim, err
	case len(res.Entries) == 1:
		for _, v := range res.Entries[0].GetAttributeValues("lDAPAdminLimits") {
			k, val, ok := strings.Cut(v, "=")
			if !ok {
				continue
			}
			n, perr := strconv.ParseUint(val, 10, 32)
			if perr != nil {
				continue
			}
			switch strings.ToLower(k) {
			case "maxpagesize":
				lim.MaxPageSize = uint32(n)
			case "maxvalrange":
				lim.MaxValueRange = uint32(n)
			}
		}
	}
	// A DC answering a page above the session's own page ceiling is not something the connector asks for.
	if lim.MaxPageSize > MaxPageSize {
		lim.MaxPageSize = MaxPageSize
	}
	if lim.MaxPageSize == 0 || lim.MaxValueRange == 0 {
		return lim, fail(CodeProtocol, "DC reports a zero paging limit", nil)
	}
	return lim, nil
}

func (s *Session) queryPolicyDN(ctx context.Context, rd *RootDSE, cfg dn.DN) (dn.DN, error) {
	if rd.DSServiceName != "" {
		ntds, err := dn.Parse(rd.DSServiceName, dn.Strict)
		if err != nil {
			return dn.DN{}, fail(CodeProtocol, "dsServiceName is not a DN", err)
		}
		base, err := dn.DNRef(ntds).ForRequest()
		if err != nil {
			return dn.DN{}, fail(CodeInvalidArgument, "ntds settings", err)
		}
		res, err := s.searchOnce(ctx, base, ldap.ScopeBaseObject, objectClassPresent, []string{"queryPolicyObject"}, nil)
		if err != nil {
			return dn.DN{}, err
		}
		if len(res.Entries) == 1 {
			if v := res.Entries[0].GetAttributeValue("queryPolicyObject"); v != "" {
				d, err := dn.Parse(v, dn.Strict)
				if err != nil {
					return dn.DN{}, fail(CodeProtocol, "queryPolicyObject is not a DN", err)
				}
				return d, nil
			}
		}
	}
	d := cfg
	for _, c := range [...]struct {
		t dn.RDNType
		v string
	}{{dn.CN, "Services"}, {dn.CN, "Windows NT"}, {dn.CN, "Directory Service"}, {dn.CN, "Query-Policies"}, {dn.CN, "Default Query Policy"}} {
		var err error
		if d, err = dn.Child(d, c.t, c.v); err != nil {
			return dn.DN{}, fail(CodeInvalidArgument, "query policy", err)
		}
	}
	return d, nil
}
