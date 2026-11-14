package ad

import (
	"bytes"
	"context"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/go-ldap/ldap/v3"

	"github.com/skenzeriq/activediq/internal/connector/ad/scope"
	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
	"github.com/skenzeriq/activediq/internal/directory/dn"
)

// The DirSync primitive of the ChangeTracking named operation (connector-contract §6, DM-19). One
// response is one DirSyncPage; a cycle is the pages until the DC reports no more results. What it
// does not do: wrap itself in gRPC, and check a cookie against the DC that issued it (the pre-checks
// of §6.3 belong to the layer above). The request carries the DirSync control with flags exactly
// object-security | incremental-values, the show-deleted control and nothing else (CC-FEED-23); no
// parameter can change either, and the OIDs are written only in package scope.

// ChangeState is the lifecycle state of a changed object (DM-19).
type ChangeState uint8

const (
	StateLive     ChangeState = iota + 1 // isDeleted absent or FALSE
	StateDeleted                         // isDeleted = TRUE, isRecycled not TRUE: restorable only with the Recycle Bin on
	StateRecycled                        // isRecycled = TRUE (wins over isDeleted): never restorable. Also what a tombstone
	// looks like when the Recycle Bin is off (Samba sets both flags); the decoder cannot tell the two apart (T-1270).
)

// ChangeOp is how an attribute changed.
type ChangeOp uint8

const (
	OpSet           ChangeOp = iota + 1 // Values is the full current value set
	OpCleared                           // the attribute now has no values
	OpValuesAdded                       // link attribute: these values were added
	OpValuesRemoved                     // link attribute: these values were removed
)

// AttributeChange is one attribute of a changed object.
type AttributeChange struct {
	Name   string // the attribute's name without any range option
	Op     ChangeOp
	Values [][]byte // raw octets as the DC sent them; empty for OpCleared
}

// ObjectChange is the final state of one object since the cookie: a patch, not a snapshot. No change
// carries an old value, and a rename or move of a parent does not report its children (DM-19.I5).
type ObjectChange struct {
	GUID  guid.GUID
	State ChangeState
	DN    string // display only; for a tombstone the CN=…\0ADEL:<guid>,CN=Deleted Objects,… form
	// Parent is the DC-supplied parentGUID; HasParent is false when the DC did not send one (a
	// tombstone, an NC head, or a DC that does not supply it).
	Parent    guid.GUID
	HasParent bool
	// Attributes are the changed attributes among those requested plus the mandatory set, sorted by
	// name then op. objectGUID, isDeleted, isRecycled and parentGUID are folded into the fields above.
	// Zero attributes is legal: the object changed only in attributes that were not requested.
	Attributes []AttributeChange
}

// DirSyncRequest asks for one DirSync response.
type DirSyncRequest struct {
	// NC is the head of the naming context to follow. The DC must say it is an NC head (instanceType);
	// DirSync refuses any other base, and the scope is the whole subtree.
	NC dn.ObjectRef
	// Cookie is where to resume; nil on the first request of a new feed. Opaque.
	Cookie []byte
	// Attributes are explicit names. "*", "+", constructed attributes and SecretAttrs members are
	// refused; the last fail with SECRET_ATTRIBUTE before any DirSync request is sent. The mandatory
	// set is added by the connector.
	Attributes []string
}

// DirSyncPage is one DirSync response.
type DirSyncPage struct {
	Changes []ObjectChange
	// Cookie resumed yields everything after this page. It is valid on this DC only (DM-19.I4).
	Cookie []byte
	// More is true while the DC has more of the cycle to send.
	More bool
	// SecretAttributesDropped counts attributes (one per object per attribute, however many values)
	// removed from Changes because they are SecretAttrs members. Their names and values are gone.
	SecretAttributesDropped int
}

// dirSyncMandatory is the attribute set requested on every DirSync, whatever the caller asked for
// (contract §6.4). objectCategory is not in it: tombstones lack it. parentGUID is asked for by name
// so a DC that only supplies it on request does.
var dirSyncMandatory = []string{"objectGUID", "objectClass", "name", "isDeleted", "isRecycled", "lastKnownParent", "parentGUID"}

// foldedAttrs never appear in ObjectChange.Attributes: they are the identity and state fields.
var foldedAttrs = map[string]struct{}{"objectguid": {}, "isdeleted": {}, "isrecycled": {}, "parentguid": {}}

// DirSync sends one DirSync search and decodes its response. The session lock is held for the one
// round trip only.
func (s *Session) DirSync(ctx context.Context, req DirSyncRequest) (DirSyncPage, error) {
	attrs, want, err := s.dirSyncAttrs(req.Attributes)
	if err != nil {
		return DirSyncPage{}, err
	}
	base, err := s.dirSyncBase(ctx, req.NC)
	if err != nil {
		return DirSyncPage{}, err
	}
	return s.dirSyncOnce(ctx, base, req.Cookie, attrs, want)
}

// DirSyncCycle runs DirSync responses from req.Cookie until the DC reports no more results and hands
// each page to fn (nil discards the changes, as a prime does). fn gets pages in the order sent; the
// page's Cookie is the one to commit with the changes it covers. The returned page is the last one,
// without its changes: it holds the final cookie.
func (s *Session) DirSyncCycle(ctx context.Context, req DirSyncRequest, fn func(DirSyncPage) error) (DirSyncPage, error) {
	attrs, want, err := s.dirSyncAttrs(req.Attributes)
	if err != nil {
		return DirSyncPage{}, err
	}
	base, err := s.dirSyncBase(ctx, req.NC)
	if err != nil {
		return DirSyncPage{}, err
	}
	cookie := req.Cookie
	for {
		if err := ctx.Err(); err != nil {
			return DirSyncPage{}, fail(CodeCanceled, "", err)
		}
		page, err := s.dirSyncOnce(ctx, base, cookie, attrs, want)
		if err != nil {
			return DirSyncPage{}, err
		}
		if page.More && len(page.Changes) == 0 && bytes.Equal(page.Cookie, cookie) {
			return DirSyncPage{}, fail(CodeProtocol, "dirsync made no progress", nil) // never spin on a stuck DC
		}
		if fn != nil {
			if err := fn(page); err != nil {
				return DirSyncPage{}, err
			}
		}
		cookie = page.Cookie
		if !page.More {
			page.Changes = nil
			return page, nil
		}
	}
}

// dirSyncAttrs validates the caller's names (secrets and wildcards fail here, before any request)
// and returns the attribute list to send and the lower-cased set the response is filtered to.
func (s *Session) dirSyncAttrs(names []string) ([]string, map[string]struct{}, error) {
	checked, err := s.checkAttrs(names, false)
	if err != nil {
		return nil, nil, err
	}
	out := make([]string, 0, len(checked)+len(dirSyncMandatory))
	want := map[string]struct{}{}
	for _, n := range append(append([]string(nil), dirSyncMandatory...), checked...) {
		k := strings.ToLower(n)
		if _, dup := want[k]; dup {
			continue
		}
		want[k] = struct{}{}
		out = append(out, n)
	}
	return out, want, nil
}

// dirSyncBase reads the NC reference and returns the head's DN as the request base. A reference that
// is not an NC head is refused here rather than left to the DC's unwillingToPerform.
func (s *Session) dirSyncBase(ctx context.Context, nc dn.ObjectRef) (string, error) {
	e, err := s.Read(ctx, nc, []string{"instanceType"}, ReadOptions{})
	if err != nil {
		return "", err
	}
	it, ok, err := e.Int32("instanceType")
	if err != nil || !ok {
		return "", fail(CodeProtocol, "instanceType unavailable", err)
	}
	if it&instanceTypeNCHead == 0 {
		return "", fail(CodeInvalidArgument, "not a naming context head", nil)
	}
	ref, err := dn.ParseObjectRef(e.DN)
	if err != nil {
		return "", fail(CodeProtocol, "naming context DN does not parse", err)
	}
	base, err := ref.ForRequest()
	if err != nil {
		return "", fail(CodeProtocol, "naming context DN", err)
	}
	return base, nil
}

// dirSyncControls is the whole control list of a DirSync request. It is closed: no caller input but
// the opaque cookie reaches it.
func dirSyncControls(cookie []byte) []ldap.Control {
	return []ldap.Control{scope.DirSync(cookie), scope.ShowDeleted()}
}

func (s *Session) dirSyncOnce(ctx context.Context, base string, cookie []byte, attrs []string, want map[string]struct{}) (DirSyncPage, error) {
	s.mu.Lock()
	if s.conn == nil {
		s.mu.Unlock()
		return DirSyncPage{}, fail(CodeUnreachable, "session closed", nil)
	}
	stop := s.watch(ctx, s.conn)
	// searchRaw, not searchOnceLocked: the request carries exactly the two controls below, so the
	// domain-scope control is not added (CC-FEED-23).
	res, err := s.searchRaw(ctx, base, ldap.ScopeWholeSubtree, objectClassPresent, attrs, dirSyncControls(cookie))
	stop()
	s.mu.Unlock()
	if err != nil {
		return DirSyncPage{}, err
	}
	resp, ok := scope.DirSyncResponse(res.Controls)
	if !ok {
		return DirSyncPage{}, fail(CodeProtocol, "no dirsync response control", nil)
	}
	page := DirSyncPage{Cookie: resp.Cookie, More: resp.MoreResults, Changes: make([]ObjectChange, 0, len(res.Entries))}
	for _, e := range res.Entries {
		c, dropped, err := s.decodeChange(e, want)
		if err != nil {
			return DirSyncPage{}, err
		}
		page.SecretAttributesDropped += dropped
		page.Changes = append(page.Changes, c)
	}
	return page, nil
}

// decodeChange turns one DirSync entry into an ObjectChange. SecretAttrs members are dropped and
// counted before anything else is looked at; attributes that were not requested are ignored.
func (s *Session) decodeChange(e *ldap.Entry, want map[string]struct{}) (ObjectChange, int, error) {
	var (
		oc       = ObjectChange{DN: e.DN, State: StateLive}
		dropped  int
		sawGUID  bool
		deleted  bool
		recycled bool
		byKey    = map[string]*AttributeChange{}
	)
	for _, a := range e.Attributes {
		base, op, err := decodeIncrementalName(a.Name)
		if err != nil {
			return ObjectChange{}, 0, err
		}
		if s.schema.IsSecret(base) {
			dropped++
			continue
		}
		lb := strings.ToLower(base)
		switch lb {
		case "objectguid":
			g, err := guid.FromBytes(firstValue(a.ByteValues))
			if err != nil {
				return ObjectChange{}, 0, fail(CodeProtocol, "objectGUID malformed", err)
			}
			oc.GUID, sawGUID = g, true
		case "isdeleted":
			deleted = deleted || boolTrue(a.ByteValues)
		case "isrecycled":
			recycled = recycled || boolTrue(a.ByteValues)
		case "parentguid":
			if g, err := guid.FromBytes(firstValue(a.ByteValues)); err == nil {
				oc.Parent, oc.HasParent = g, true
			}
		}
		if _, folded := foldedAttrs[lb]; folded {
			continue
		}
		if _, asked := want[lb]; !asked {
			continue
		}
		if op == 0 { // a plain attribute: its value set, or none
			op = OpSet
			if len(a.ByteValues) == 0 {
				op = OpCleared
			}
		}
		key := lb + "\x00" + string(rune('0'+op))
		ch := byKey[key]
		if ch == nil {
			ch = &AttributeChange{Name: base, Op: op}
			byKey[key] = ch
		}
		ch.Values = append(ch.Values, a.ByteValues...)
	}
	// The state is decided after the loop: LDAP does not fix attribute order, and a recycled object
	// (isRecycled, usually with isDeleted) must never be reported as the restorable DELETED.
	switch {
	case recycled:
		oc.State = StateRecycled
	case deleted:
		oc.State = StateDeleted
	}
	if !sawGUID {
		return ObjectChange{}, 0, fail(CodeProtocol, "objectGUID missing from dirsync entry", nil)
	}
	for _, ch := range byKey {
		oc.Attributes = append(oc.Attributes, *ch)
	}
	sort.Slice(oc.Attributes, func(i, j int) bool {
		a, b := oc.Attributes[i], oc.Attributes[j]
		if la, lb := strings.ToLower(a.Name), strings.ToLower(b.Name); la != lb {
			return la < lb
		}
		return a.Op < b.Op
	})
	return oc, dropped, nil
}

// decodeIncrementalName maps a DirSync attribute name onto (base name, op). This is the incremental
// values decoder, not the ranged-read loop: with INCREMENTAL_VALUES the range is not a paging cursor
// but a marker (contract §6.4). `x;range=1-1` is a value added (Windows and Samba); `x;range=0-0` is a
// value removed (Samba's form; Windows' form is [UNVERIFIED Windows], CC-FEED-04). A name without a
// range option returns op 0. Any other range form is refused: guessing would corrupt membership.
func decodeIncrementalName(name string) (base string, op ChangeOp, err error) {
	if name == "" || !utf8.ValidString(name) {
		return "", 0, fail(CodeProtocol, "malformed attribute name in dirsync", nil)
	}
	i := indexRangeOption(name)
	if i < 0 {
		if strings.Contains(name, ";") {
			return "", 0, fail(CodeProtocol, "unexpected attribute option", nil)
		}
		return name, 0, nil
	}
	base, spec := name[:i], name[i+len(";range="):]
	if base == "" || strings.Contains(base, ";") {
		return "", 0, fail(CodeProtocol, "unexpected attribute name in dirsync", nil)
	}
	switch spec { // exact forms only: no sign, no leading zeros, no ranges
	case "1-1":
		return base, OpValuesAdded, nil
	case "0-0":
		return base, OpValuesRemoved, nil
	}
	return "", 0, fail(CodeProtocol, "unexpected range form in dirsync", nil)
}

func firstValue(v [][]byte) []byte {
	if len(v) == 0 {
		return nil
	}
	return v[0]
}

func boolTrue(v [][]byte) bool { return len(v) == 1 && strings.EqualFold(string(v[0]), "TRUE") }
