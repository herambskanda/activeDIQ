package replstatus

import (
	"context"

	"github.com/skenzeriq/activediq/internal/connector/ad"
	"github.com/skenzeriq/activediq/internal/connector/write"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// Bound adapts the one session of a single-DC connection to Source: the DC list is the bound DC,
// read live, and Open returns the session itself. It is the whole implementation until the
// Describe domain-controller section can list every DC and open per-DC sessions; a connection
// with more DCs is then a Source with more entries. Bound cannot tell an RODC, so it reports the
// DC as writable [UNVERIFIED]; the multi-DC lister supplies ReadOnly.
type Bound struct {
	Sess  *ad.Session
	Ident *connectorv1.DirectoryIdentity
}

// Identity implements Source.
func (b *Bound) Identity() *connectorv1.DirectoryIdentity { return b.Ident }

// DCs implements DCLister.
func (b *Bound) DCs(ctx context.Context) ([]DC, error) {
	id, err := b.Sess.DCIdentity(ctx)
	if err != nil {
		return nil, err
	}
	return []DC{{Identity: &connectorv1.DcIdentity{
		DsaGuid:      write.GUIDToWire(id.DSAGUID),
		InvocationId: write.GUIDToWire(id.InvocationID),
		DnsHostname:  id.DNSHostName,
		Site:         id.Site,
	}}}, nil
}

// Open implements Opener: the session is the DC's reader and is not the handler's to close.
func (b *Bound) Open(context.Context, DC) (DCReader, func(), error) {
	return b.Sess, func() {}, nil
}
