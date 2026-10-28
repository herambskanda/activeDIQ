package read

import (
	"context"
	"errors"

	"github.com/skenzeriq/activediq/internal/connector/ad"
	"github.com/skenzeriq/activediq/internal/connector/write"
	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
	"github.com/skenzeriq/activediq/internal/directory/dn"
	"github.com/skenzeriq/activediq/internal/directory/ldapfilter"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// instanceTypeNCHead is IT_NC_HEAD in instanceType: the object is the head of a naming context.
const instanceTypeNCHead = 0x1

// ADSource is the Source over an AD session. The reads, the classification and the DC identity
// must all come from one DC, so the only way to build one is NewADSource, which refuses a provider
// that is not over the very session it reads on. The fields are unexported: a struct literal
// cannot bypass the check, and the zero value fails every Read at the DC-identity step.
type ADSource struct {
	sess *ad.Session
	prov *write.ADProvider
}

var _ Source = (*ADSource)(nil)

// NewADSource returns the source for sess. prov's directory and bound-DC binder must both be over
// sess (write.NewADProvider(sess, …) does that); otherwise a pinned Read could be answered by one
// DC while the pin and the verdict name another.
func NewADSource(sess *ad.Session, prov *write.ADProvider) (*ADSource, error) {
	if sess == nil || prov == nil {
		return nil, errors.New("read: a session and a provider are required")
	}
	if !prov.OverSession(sess) {
		return nil, errors.New("read: the provider is not over the reading session")
	}
	return &ADSource{sess: sess, prov: prov}, nil
}

func (a *ADSource) ok() bool { return a != nil && a.sess != nil && a.prov != nil }

func (a *ADSource) Identity() *connectorv1.DirectoryIdentity {
	if !a.ok() {
		return nil
	}
	return a.prov.Identity()
}

func (a *ADSource) BoundDC(ctx context.Context) (*connectorv1.DcIdentity, error) {
	if !a.ok() {
		return nil, write.ErrNoBoundDC
	}
	return a.prov.BoundDC(ctx)
}

func (a *ADSource) Read(ctx context.Context, id guid.GUID, attrs []string, maxValues int) (*ad.Entry, error) {
	return a.sess.Read(ctx, dn.GUIDRef(id), attrs, ad.ReadOptions{MaxValues: maxValues})
}

// Parent returns the parent's objectGUID. ok is false only for a naming-context head, which the
// directory says about itself (instanceType, requested with the entry); an unreadable or
// undecodable parent is an error, never "no parent", because the ancestry feeds authorisation.
func (a *ADSource) Parent(ctx context.Context, e *ad.Entry) (guid.GUID, bool, error) {
	it, present, err := e.Int32("instanceType")
	if err != nil || !present {
		return guid.GUID{}, false, errors.New("read: instanceType unavailable")
	}
	if it&instanceTypeNCHead != 0 {
		return guid.GUID{}, false, nil
	}
	ref, err := dn.ParseObjectRef(e.DN)
	if err != nil {
		return guid.GUID{}, false, errors.New("read: object DN does not parse")
	}
	d, found := ref.DN()
	if !found || d.Len() < 2 {
		return guid.GUID{}, false, errors.New("read: object has no parent DN")
	}
	pe, err := a.sess.Read(ctx, dn.DNRef(d.Parent()), []string{"objectGUID"}, ad.ReadOptions{})
	if err != nil {
		return guid.GUID{}, false, err
	}
	g, err := pe.GUID()
	if err != nil {
		return guid.GUID{}, false, errors.New("read: parent GUID does not decode")
	}
	return g, true, nil
}

func (a *ADSource) Syntax(name string) (ldapfilter.Syntax, bool) {
	if !a.ok() {
		return 0, false
	}
	return a.sess.AttrSyntax(name)
}

func (a *ADSource) CanonicalAttr(name string) (string, error) {
	if !a.ok() {
		return "", write.ErrNoBoundDC
	}
	return a.sess.CanonicalAttr(name)
}

func (a *ADSource) Classify(ctx context.Context, id guid.GUID) (write.Verdict, error) {
	if !a.ok() {
		return write.Verdict{}, write.ErrNoBoundDC
	}
	return a.prov.Classify(ctx, id, nil)
}

var _ SearchSource = (*ADSource)(nil)

// FilterSchema implements SearchSource.
func (a *ADSource) FilterSchema() *ldapfilter.Schema {
	if !a.ok() {
		return ldapfilter.NewSchema()
	}
	return a.sess.FilterSchema()
}

// ScopedSearch implements SearchSource over the one session, hence one DC.
func (a *ADSource) ScopedSearch(ctx context.Context, req ad.ScopedRequest, fn func(*ad.Entry) error) (ad.ScopedResult, error) {
	if !a.ok() {
		return ad.ScopedResult{}, write.ErrNoBoundDC
	}
	return a.sess.ScopedSearch(ctx, req, fn)
}
