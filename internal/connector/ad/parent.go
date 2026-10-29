package ad

import (
	"context"
	"strings"

	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
	"github.com/skenzeriq/activediq/internal/directory/dn"
)

// instanceTypeNCHead is IT_NC_HEAD in instanceType: the object is the head of a naming context.
const instanceTypeNCHead = 0x1

// Parent returns the objectGUID of e's parent. hasParent is false only for a naming-context head,
// which the directory says about itself (instanceType, which e must carry); an unreadable or
// undecodable parent is an error, never "no parent", because ancestry feeds authorisation. It reads
// through the session, so it must not be called from inside Search's callback (use SearchPages).
func (s *Session) Parent(ctx context.Context, e *Entry) (g guid.GUID, hasParent bool, err error) {
	g, hasParent, _, err = s.parentOf(ctx, e, nil)
	return g, hasParent, err
}

// parentOf is Parent with a cache keyed by the parent's normalised DN. reads reports whether a
// directory read was made (a cache hit makes none).
func (s *Session) parentOf(ctx context.Context, e *Entry, cache map[string]guid.GUID) (g guid.GUID, hasParent, read bool, err error) {
	it, present, err := e.Int32("instanceType")
	if err != nil || !present {
		return guid.GUID{}, false, false, fail(CodeProtocol, "instanceType unavailable", err)
	}
	if it&instanceTypeNCHead != 0 {
		return guid.GUID{}, false, false, nil
	}
	ref, err := dn.ParseObjectRef(e.DN)
	if err != nil {
		return guid.GUID{}, false, false, fail(CodeProtocol, "object DN does not parse", err)
	}
	d, found := ref.DN()
	if !found || d.Len() < 2 {
		return guid.GUID{}, false, false, fail(CodeProtocol, "object has no parent DN", nil)
	}
	pd := d.Parent()
	key := ""
	if cache != nil {
		key = strings.ToLower(pd.String())
		if g, ok := cache[key]; ok {
			return g, true, false, nil
		}
	}
	pe, err := s.Read(ctx, dn.DNRef(pd), []string{"objectGUID"}, ReadOptions{})
	if err != nil {
		if CodeOf(err) == CodeObjectNotFound { // the entry exists; a missing parent is not a missing root
			err = fail(CodeProtocol, "parent not found", err)
		}
		return guid.GUID{}, false, true, err
	}
	g, err = pe.GUID()
	if err != nil {
		return guid.GUID{}, false, true, fail(CodeProtocol, "parent GUID does not decode", err)
	}
	if cache != nil {
		cache[key] = g
	}
	return g, true, true, nil
}
