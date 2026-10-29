package tier0

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"

	"github.com/skenzeriq/activediq/internal/connector/ad"
	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
	"github.com/skenzeriq/activediq/internal/directory/attr/sid"
	"github.com/skenzeriq/activediq/internal/directory/dn"
	"github.com/skenzeriq/activediq/internal/directory/ldapfilter"
)

// fobj is one object of the in-memory forest.
type fobj struct {
	dn    string
	cls   []string
	sid   string
	attrs map[string][]string
	raw   map[string][]byte
	multi map[string][][]byte
	guid  guid.GUID
	bare  bool // a denied Read on Windows: the entry comes back with no attributes at all
}

// fakeDir is an in-memory ADDirectory. It implements the directory's semantics (subtree scope,
// transitive membership with cycles, NotFound) and nothing of the classifier.
type fakeDir struct {
	nm          Naming
	objs        []*fobj
	failDN      string // any Get/Find touching a DN containing this fails
	denyDN      string // any Find under a DN containing this is refused (InsufficientRights)
	failHas     string // any Find presence-testing this attribute fails
	nextGID     byte
	failSIDFind bool    // any Find by objectSid fails
	finds       []Query // every Find, in order (search-count assertions)

	// Forest seam: other domains of the forest and the GC's objects (their objectSid is the key).
	forestDoms []string
	gc         []*fobj
	gcErr      error
	gcCalls    int
}

func (f *fakeDir) ForestDomains(context.Context) ([]sid.SID, error) {
	if f.gcErr != nil {
		return nil, f.gcErr
	}
	var out []sid.SID
	for _, d := range f.forestDoms {
		v, err := sid.Parse(d)
		if err != nil {
			panic(err)
		}
		out = append(out, v)
	}
	return out, nil
}

func (f *fakeDir) GCLookup(_ context.Context, s sid.SID, _ []string) (*ad.Entry, bool, error) {
	f.gcCalls++
	if f.gcErr != nil {
		return nil, false, f.gcErr
	}
	for _, o := range f.gc {
		if o.sid == s.String() {
			return o.entry(), true, nil
		}
	}
	return nil, false, nil
}

func mustDN(s string) dn.DN {
	d, err := dn.Parse(s, dn.Strict)
	if err != nil {
		panic(err)
	}
	return d
}

func newFake() *fakeDir {
	return &fakeDir{nm: Naming{
		Domain: mustDN("DC=lab,DC=test"), RootDomain: mustDN("DC=lab,DC=test"),
		Config: mustDN("CN=Configuration,DC=lab,DC=test"), Schema: mustDN("CN=Schema,CN=Configuration,DC=lab,DC=test"),
	}}
}

// add creates an object; kv is attr, value pairs (repeat the attr for multi-values).
func (f *fakeDir) add(dnText, sidText string, cls []string, kv ...string) *fobj {
	f.nextGID++
	o := &fobj{dn: dnText, sid: sidText, cls: cls, attrs: map[string][]string{}, raw: map[string][]byte{}, multi: map[string][][]byte{}}
	o.guid[0], o.guid[15] = f.nextGID, 0xA5
	for i := 0; i < len(kv); i += 2 {
		o.attrs[strings.ToLower(kv[i])] = append(o.attrs[strings.ToLower(kv[i])], kv[i+1])
	}
	f.objs = append(f.objs, o)
	return o
}

func (f *fakeDir) find(text string) *fobj {
	for _, o := range f.objs {
		if strings.EqualFold(o.dn, text) {
			return o
		}
	}
	panic("no fake object " + text)
}

func (o *fobj) entry() *ad.Entry {
	if o.bare {
		return ad.NewEntry(o.dn, nil)
	}
	m := map[string][][]byte{"objectGUID": {o.guid.Bytes()}}
	for _, c := range o.cls {
		m["objectClass"] = append(m["objectClass"], []byte(c))
	}
	if o.sid != "" {
		s, err := sid.Parse(o.sid)
		if err != nil {
			panic(err)
		}
		m["objectSid"] = [][]byte{s.Bytes()}
	}
	for k, vs := range o.attrs {
		for _, v := range vs {
			m[k] = append(m[k], []byte(v))
		}
	}
	for k, v := range o.raw {
		m[k] = [][]byte{v}
	}
	for k, vs := range o.multi {
		m[k] = vs
	}
	return ad.NewEntry(o.dn, m)
}

func (o *fobj) is(class string) bool {
	for _, c := range o.cls {
		if strings.EqualFold(c, class) {
			return true
		}
	}
	return false
}

func (f *fakeDir) guard(d string) error {
	if f.denyDN != "" && strings.Contains(strings.ToLower(d), strings.ToLower(f.denyDN)) {
		return &ad.Error{Code: ad.CodeInsufficientRights, Detail: "injected"}
	}
	if f.failDN != "" && strings.Contains(strings.ToLower(d), strings.ToLower(f.failDN)) {
		return &ad.Error{Code: ad.CodeUnreachable, Detail: "injected"}
	}
	return nil
}

func (f *fakeDir) Naming(context.Context) (Naming, error) { return f.nm, nil }

// checkAttrs refuses an attribute outside the real connector schema, as the live Session does
// (INVALID_ARGUMENT: UnknownAttribute), so a unit test cannot pass on a read a real DC would reject.
func checkAttrs(attrs []string) error {
	sc := ad.DefaultSchema()
	for _, a := range attrs {
		if _, err := ldapfilter.ParseAttrName(a, sc); err != nil {
			return fmt.Errorf("fake dir: attribute %q: %w", a, err)
		}
	}
	return nil
}

func (f *fakeDir) Get(_ context.Context, ref dn.ObjectRef, attrs []string) (*ad.Entry, error) {
	if err := checkAttrs(attrs); err != nil {
		return nil, err
	}
	for _, o := range f.objs {
		switch {
		case func() bool { d, ok := ref.DN(); return ok && dn.Equal(d, mustDN(o.dn)) }():
		case func() bool { g, ok := ref.GUID(); return ok && g == o.guid }():
		case func() bool { s, ok := ref.SID(); return ok && o.sid != "" && s.String() == o.sid }():
		default:
			continue
		}
		if err := f.guard(o.dn); err != nil {
			return nil, err
		}
		return o.entry(), nil
	}
	if d, ok := ref.DN(); ok {
		if err := f.guard(d.String()); err != nil {
			return nil, err
		}
	}
	return nil, &ad.Error{Code: ad.CodeObjectNotFound}
}

func (f *fakeDir) Find(_ context.Context, base dn.DN, _ ad.Scope, q Query, attrs []string, fn func(*ad.Entry) error) error {
	if err := checkAttrs(attrs); err != nil {
		return err
	}
	f.finds = append(f.finds, q)
	if err := f.guard(base.String()); err != nil {
		return err
	}
	if len(q.AnySID) > 0 && f.failSIDFind {
		return &ad.Error{Code: ad.CodeUnreachable, Detail: "injected"}
	}
	for _, h := range q.Has {
		if f.failHas != "" && strings.EqualFold(h, f.failHas) {
			return &ad.Error{Code: ad.CodeUnreachable, Detail: "injected"}
		}
	}
	baseFound := false
	var hits []*fobj
	for _, o := range f.objs {
		d := mustDN(o.dn)
		if dn.Equal(d, base) {
			baseFound = true
		} else if !d.IsDescendantOf(base) {
			continue
		}
		if f.match(o, q) {
			hits = append(hits, o)
		}
	}
	if !baseFound {
		return &ad.Error{Code: ad.CodeObjectNotFound}
	}
	for _, o := range hits {
		if len(q.AnySID) > 0 {
			if err := f.guard(o.dn); err != nil {
				return err
			}
		}
		if err := fn(o.entry()); err != nil {
			return err
		}
	}
	return nil
}

func (f *fakeDir) match(o *fobj, q Query) bool {
	if len(q.Classes) > 0 {
		ok := false
		for _, c := range q.Classes {
			// objectClass "user" matches computers, as in AD (computer is a subclass of user)
			ok = ok || o.is(c) || (strings.EqualFold(c, "user") && o.is("computer"))
		}
		if !ok {
			return false
		}
	}
	for _, e := range q.Eq {
		hit := false
		for _, v := range o.attrs[strings.ToLower(e.Attr)] {
			hit = hit || strings.EqualFold(v, e.Value)
		}
		if !hit {
			return false
		}
	}
	for _, e := range q.EqInt {
		hit := false
		for _, v := range o.attrs[strings.ToLower(e.Attr)] {
			n, _ := strconv.Atoi(v)
			hit = hit || int32(n) == e.Value
		}
		if !hit {
			return false
		}
	}
	if len(q.AnyInt) > 0 {
		hit := false
		for _, e := range q.AnyInt {
			for _, v := range o.attrs[strings.ToLower(e.Attr)] {
				n, _ := strconv.Atoi(v)
				hit = hit || int32(n) == e.Value
			}
		}
		if !hit {
			return false
		}
	}
	if len(q.AnyGUID) > 0 {
		hit := false
		for _, e := range q.AnyGUID {
			hit = hit || bytes.Equal(o.raw[e.Attr], e.Value.Bytes())
		}
		if !hit {
			return false
		}
	}
	if len(q.AnySID) > 0 {
		hit := false
		for _, s := range q.AnySID {
			hit = hit || (o.sid != "" && s.String() == o.sid)
		}
		if !hit {
			return false
		}
	}
	for _, h := range q.Has {
		if len(o.attrs[strings.ToLower(h)]) == 0 && len(o.raw[h]) == 0 && len(o.multi[h]) == 0 {
			return false
		}
	}
	if q.UACAny != 0 {
		v := o.attrs["useraccountcontrol"]
		if len(v) == 0 {
			return false
		}
		n, _ := strconv.ParseUint(v[0], 10, 32)
		if uint32(n)&q.UACAny == 0 {
			return false
		}
	}
	return true
}

// ---- security descriptor builder ----

type aceSpec struct {
	sid     string
	mask    uint32
	objType *guid.GUID
	flags   byte
	typ     byte // 0 = derive from objType (allow / allow object); else the literal ACE type
	junk    int  // trailing bytes after the SID (a callback ACE's condition), must be a multiple of 4
}

const (
	aceInheritOnly = 0x08
	defaultOwner   = "S-1-5-32-544"
)

func sdBytes(aces ...aceSpec) []byte { return sdOwned(defaultOwner, aces...) }

// sdOwned builds a self-relative descriptor with a DACL and an owner; owner "" omits the owner.
func sdOwned(owner string, aces ...aceSpec) []byte {
	var body []byte
	for _, a := range aces {
		s, err := sid.Parse(a.sid)
		if err != nil {
			panic(err)
		}
		typ, hdr := byte(0x00), []byte{}
		if a.objType != nil {
			typ = 0x05
			hdr = binary.LittleEndian.AppendUint32(nil, 0x1)
			hdr = append(hdr, a.objType.Bytes()...)
		}
		if a.typ != 0 {
			typ = a.typ
			if len(hdr) == 0 && (typ == 0x05 || typ == 0x0B || typ == 0x0C) { // object form without GUIDs
				hdr = make([]byte, 4)
			}
		}
		sb := s.Bytes()
		size := 8 + len(hdr) + len(sb) + a.junk
		ace := []byte{typ, a.flags}
		ace = binary.LittleEndian.AppendUint16(ace, uint16(size))
		ace = binary.LittleEndian.AppendUint32(ace, a.mask)
		ace = append(ace, hdr...)
		ace = append(ace, sb...)
		ace = append(ace, make([]byte, a.junk)...)
		body = append(body, ace...)
	}
	acl := []byte{4, 0}
	acl = binary.LittleEndian.AppendUint16(acl, uint16(8+len(body)))
	acl = binary.LittleEndian.AppendUint16(acl, uint16(len(aces)))
	acl = append(acl, 0, 0)
	acl = append(acl, body...)
	var ob []byte
	offOwner := uint32(0)
	if owner != "" {
		o, err := sid.Parse(owner)
		if err != nil {
			panic(err)
		}
		ob = o.Bytes()
		offOwner = uint32(20 + len(acl))
	}
	sd := []byte{1, 0}
	sd = binary.LittleEndian.AppendUint16(sd, 0x8004)
	for _, off := range []uint32{offOwner, 0, 0, 20} {
		sd = binary.LittleEndian.AppendUint32(sd, off)
	}
	return append(append(sd, acl...), ob...)
}

var _ = fmt.Sprint

// history sets the object's sIDHistory.
func (o *fobj) history(sids ...string) *fobj {
	for _, t := range sids {
		s, err := sid.Parse(t)
		if err != nil {
			panic(err)
		}
		o.multi["sIDHistory"] = append(o.multi["sIDHistory"], s.Bytes())
	}
	return o
}
