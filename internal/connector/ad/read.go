package ad

import (
	"context"
	"strconv"
	"strings"

	"github.com/go-ldap/ldap/v3"

	"github.com/skenzeriq/activediq/internal/directory/dn"
)

// Range sizing. The first request is explicit (member;range=0-1499) because Samba returns every
// value unranged on a plain read while Windows ranges it (ad-lab runbook §5): a connector that does
// not ask passes the lab and fails at a customer. Windows' default MaxValRange is 1500.
const (
	rangeWindow      = 1500
	DefaultMaxValues = 100_000
	maxRangeRequests = 1000 // hard bound on round trips for one attribute
)

// rangedByDefault are the large multi-valued link attributes Read always requests in range form.
var rangedByDefault = map[string]struct{}{
	"member": {}, "memberof": {}, "directreports": {}, "managedobjects": {},
}

// ReadOptions tunes Read. The zero value is valid.
type ReadOptions struct {
	// SD selects the security descriptor parts for nTSecurityDescriptor and sDRightsEffective. The
	// zero value means DefaultSDFlags (owner, group, DACL). It has no SACL member by construction.
	SD SDFlags
	// Ranged names further multi-valued attributes to request in range form.
	Ranged []string
	// MaxValues caps the values returned per attribute; 0 means DefaultMaxValues. A cut attribute is
	// named in Entry.Truncated.
	MaxValues int
	// ShowDeleted sends the show-deleted control, so a deleted object can be read by GUID.
	ShowDeleted bool
	// ExtendedDN asks for extended DNs (<GUID=…>;<SID=…>;dn) in DN-syntax values, on the first
	// request and on every range follow-up, so member values beyond the first range carry identity
	// too. Entry.DN stays plain.
	ExtendedDN bool
}

// Read reads one object by DN or GUID (base-scope search) and follows ranged attributes to the
// terminal range. Constructed attributes (tokenGroups, allowedAttributesEffective,
// allowedChildClassesEffective, sDRightsEffective) are served here and only here: the values are
// what the bound connector identity sees (TM §6.5). objectGUID is always included.
func (s *Session) Read(ctx context.Context, ref dn.ObjectRef, attrs []string, opts ReadOptions) (*Entry, error) {
	base, err := ref.ForRequest()
	if err != nil {
		return nil, fail(CodeInvalidArgument, "object reference", err)
	}
	if len(attrs) == 0 {
		return nil, fail(CodeInvalidArgument, "attributes required", nil)
	}
	names, err := s.checkAttrs(append([]string{"objectGUID"}, attrs...), true)
	if err != nil {
		return nil, err
	}
	max := opts.MaxValues
	if max <= 0 {
		max = DefaultMaxValues
	}
	ranged := map[string]struct{}{}
	for k := range rangedByDefault {
		ranged[k] = struct{}{}
	}
	if len(opts.Ranged) > 0 {
		extra, err := s.checkAttrs(opts.Ranged, false)
		if err != nil {
			return nil, err
		}
		for _, n := range extra {
			ranged[strings.ToLower(n)] = struct{}{}
		}
	}

	var ctrls []ldap.Control
	needSD := false
	for _, n := range names {
		if l := strings.ToLower(n); l == "ntsecuritydescriptor" || l == "sdrightseffective" {
			needSD = true
		}
	}
	if needSD {
		f := opts.SD
		if f.IsZero() {
			f = DefaultSDFlags()
		}
		ctrls = append(ctrls, f.control())
	}

	if opts.ShowDeleted {
		ctrls = append(ctrls, deletedControls()...)
	}
	if opts.ExtendedDN {
		ctrls = append(ctrls, extendedDN{})
	}

	req := make([]string, len(names))
	for i, n := range names {
		req[i] = n
		if _, ok := ranged[strings.ToLower(n)]; ok {
			req[i] = n + ";range=0-" + strconv.Itoa(rangeWindow-1)
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn == nil {
		return nil, fail(CodeUnreachable, "session closed", nil)
	}
	stop := s.watch(ctx, s.conn)
	defer stop()

	res, err := s.searchOnceLocked(ctx, base, ldap.ScopeBaseObject, objectClassPresent, req, ctrls)
	if err != nil {
		return nil, err
	}
	if len(res.Entries) != 1 {
		return nil, fail(CodeObjectNotFound, "", nil)
	}
	ent := newEntry(plainDN(res.Entries[0].DN))
	pending := map[string]int{} // base name -> next range start still to fetch
	asked := make(map[string]struct{}, len(names))
	for _, n := range names {
		asked[strings.ToLower(n)] = struct{}{}
	}
	absorb := func(raw *ldap.Entry) { absorbEntry(ent, pending, asked, raw) }
	absorb(res.Entries[0])

	var followCtrls []ldap.Control
	if opts.ExtendedDN {
		followCtrls = []ldap.Control{extendedDN{}}
	}
	// Follow ranges to the terminal "*" range, bounded by the value ceiling and a round-trip cap.
	for round := 0; len(pending) > 0 && round < maxRangeRequests; round++ {
		var next []string
		for key, from := range pending {
			if len(ent.attrs[key]) >= max {
				ent.Truncated = append(ent.Truncated, key)
				delete(pending, key)
				continue
			}
			next = append(next, key+";range="+strconv.Itoa(from)+"-*")
		}
		if len(next) == 0 {
			break
		}
		clear(pending)
		r, err := s.searchOnceLocked(ctx, base, ldap.ScopeBaseObject, objectClassPresent, next, followCtrls)
		if err != nil {
			return nil, err
		}
		if len(r.Entries) != 1 {
			return nil, fail(CodeObjectNotFound, "", nil)
		}
		absorb(r.Entries[0])
	}
	for key := range pending { // round-trip cap reached
		ent.Truncated = append(ent.Truncated, key)
	}
	for _, v := range ent.attrs["ntsecuritydescriptor"] {
		if sdHasSACL(v) {
			return nil, fail(CodeInvalidArgument, "security descriptor contains a SACL", nil)
		}
	}
	for key, v := range ent.attrs {
		if len(v) > max {
			ent.attrs[key] = v[:max]
			ent.Truncated = append(ent.Truncated, key)
		}
	}
	return ent, nil
}

// sdHasSACL reports whether a binary security descriptor has SE_SACL_PRESENT (0x0010) set in its
// control word (bytes 2-3, little endian). The connector never requests the SACL; this is the
// backstop if a DC or intermediary ignores the SD flags control.
func sdHasSACL(sd []byte) bool {
	return len(sd) >= 4 && sd[2]&0x10 != 0
}

// absorbEntry merges one response into ent. Only attributes we asked for are kept or followed: a DC
// (or proxy) that returns "foo;range=0-1" for something we never requested cannot make us loop.
func absorbEntry(ent *Entry, pending map[string]int, asked map[string]struct{}, raw *ldap.Entry) {
	for _, a := range raw.Attributes {
		name, _, hi, star, isRange := splitRange(a.Name)
		key := strings.ToLower(name)
		if _, ok := asked[key]; !ok {
			continue
		}
		ent.attrs[key] = append(ent.attrs[key], a.ByteValues...)
		if isRange && !star {
			pending[key] = hi + 1
		} else if isRange {
			delete(pending, key)
		}
	}
}
