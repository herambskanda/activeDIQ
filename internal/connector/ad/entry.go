package ad

import (
	"sort"
	"strconv"
	"strings"

	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
	"github.com/skenzeriq/activediq/internal/directory/attr/sid"
)

// Entry is one directory object as read. Attribute names are case-insensitive. Values are raw
// octets exactly as the DC sent them; the typed accessors decode with the attr codecs.
type Entry struct {
	DN        string // display only; identity is the objectGUID (rule 9)
	attrs     map[string][][]byte
	Truncated []string // attributes cut at the value ceiling (Read only)
}

func newEntry(dn string) *Entry { return &Entry{DN: dn, attrs: map[string][][]byte{}} }

// NewEntry builds an Entry from raw octet values, for adapters and test doubles of the directory
// seams that consumers define over Session. Attribute names are case-insensitive.
func NewEntry(dn string, attrs map[string][][]byte) *Entry {
	e := newEntry(dn)
	for k, v := range attrs {
		e.attrs[strings.ToLower(k)] = v
	}
	return e
}

// Raw returns the octet values of an attribute (nil when absent).
func (e *Entry) Raw(name string) [][]byte { return e.attrs[strings.ToLower(name)] }

// Names returns the lower-cased names of the attributes the DC returned, sorted.
func (e *Entry) Names() []string {
	out := make([]string, 0, len(e.attrs))
	for k := range e.attrs {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Has reports whether the DC returned the attribute.
func (e *Entry) Has(name string) bool { _, ok := e.attrs[strings.ToLower(name)]; return ok }

// Strings returns the values as UTF-8 text.
func (e *Entry) Strings(name string) []string {
	raw := e.Raw(name)
	out := make([]string, len(raw))
	for i, v := range raw {
		out[i] = string(v)
	}
	return out
}

// GUID decodes objectGUID.
func (e *Entry) GUID() (guid.GUID, error) {
	v := e.Raw("objectGUID")
	if len(v) != 1 {
		return guid.GUID{}, fail(CodeProtocol, "objectGUID missing", nil)
	}
	g, err := guid.FromBytes(v[0])
	if err != nil {
		return guid.GUID{}, fail(CodeProtocol, "objectGUID malformed", err)
	}
	return g, nil
}

// SIDs decodes a SID-valued attribute (objectSid, tokenGroups, sIDHistory).
func (e *Entry) SIDs(name string) ([]sid.SID, error) {
	raw := e.Raw(name)
	out := make([]sid.SID, 0, len(raw))
	for _, v := range raw {
		s, err := sid.FromBytes(v)
		if err != nil {
			return nil, fail(CodeProtocol, "sid malformed", err)
		}
		out = append(out, s)
	}
	return out, nil
}

// Int32 decodes a single Integer-syntax value (userAccountControl, sDRightsEffective).
func (e *Entry) Int32(name string) (int32, bool, error) {
	raw := e.Raw(name)
	if len(raw) == 0 {
		return 0, false, nil
	}
	n, err := strconv.ParseInt(string(raw[0]), 10, 32)
	if err != nil {
		return 0, true, fail(CodeProtocol, "integer malformed", err)
	}
	return int32(n), true, nil
}

// splitRange splits "member;range=0-1499" into ("member", 0, 1499, false) and
// "member;range=1500-*" into ("member", 1500, 0, true). ok is false for a name without a range option.
func splitRange(name string) (base string, lo, hi int, star, ok bool) {
	i := strings.Index(strings.ToLower(name), ";range=")
	if i < 0 {
		return name, 0, 0, false, false
	}
	base, spec := name[:i], name[i+len(";range="):]
	l, h, found := strings.Cut(spec, "-")
	if !found {
		return name, 0, 0, false, false
	}
	var err error
	if lo, err = strconv.Atoi(l); err != nil || lo < 0 {
		return name, 0, 0, false, false
	}
	if h == "*" {
		return base, lo, 0, true, true
	}
	if hi, err = strconv.Atoi(h); err != nil || hi < lo {
		return name, 0, 0, false, false
	}
	return base, lo, hi, false, true
}
