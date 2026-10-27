package read

import (
	"context"

	"github.com/skenzeriq/activediq/internal/connector/ad"
	"github.com/skenzeriq/activediq/internal/connector/write"
	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
	"github.com/skenzeriq/activediq/internal/directory/dn"
	"github.com/skenzeriq/activediq/internal/directory/ldapfilter"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// ADSource is the Source over an AD session. The provider's directory and bound-DC binder must be
// over the same session (write.NewADProvider does that); a provider whose two halves are on
// different sessions reports no bound DC, and every Read fails.
type ADSource struct {
	Sess *ad.Session
	Prov *write.ADProvider
}

var _ Source = ADSource{}

func (a ADSource) Identity() *connectorv1.DirectoryIdentity { return a.Prov.Identity() }

func (a ADSource) BoundDC(ctx context.Context) (*connectorv1.DcIdentity, error) {
	return a.Prov.BoundDC(ctx)
}

func (a ADSource) Read(ctx context.Context, id guid.GUID, attrs []string, maxValues int) (*ad.Entry, error) {
	return a.Sess.Read(ctx, dn.GUIDRef(id), attrs, ad.ReadOptions{MaxValues: maxValues})
}

func (a ADSource) Parent(ctx context.Context, e *ad.Entry) (guid.GUID, bool, error) {
	ref, err := dn.ParseObjectRef(e.DN)
	if err != nil {
		return guid.GUID{}, false, nil
	}
	d, ok := ref.DN()
	if !ok || d.Len() < 2 {
		return guid.GUID{}, false, nil
	}
	pe, err := a.Sess.Read(ctx, dn.DNRef(d.Parent()), []string{"objectGUID"}, ad.ReadOptions{})
	if err != nil {
		if ad.CodeOf(err) == ad.CodeObjectNotFound || ad.CodeOf(err) == ad.CodeInsufficientRights {
			return guid.GUID{}, false, nil // parent unreadable: ParentGuid stays empty ("source did not supply it")
		}
		return guid.GUID{}, false, err
	}
	g, err := pe.GUID()
	if err != nil {
		return guid.GUID{}, false, nil
	}
	return g, true, nil
}

func (a ADSource) Syntax(name string) (ldapfilter.Syntax, bool) { return a.Sess.AttrSyntax(name) }

func (a ADSource) Classify(ctx context.Context, id guid.GUID) (write.Verdict, error) {
	return a.Prov.Classify(ctx, id, nil)
}
