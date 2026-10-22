package dn

import (
	"encoding/hex"
	"strings"

	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
	"github.com/skenzeriq/activediq/internal/directory/attr/sid"
)

type refKind uint8

const (
	refNone refKind = iota
	refGUID
	refSID
	refDN
)

// ObjectRef names an existing object in a request: by objectGUID, by objectSid or by DN. Prefer
// GUIDRef for every modify, delete and modifyDN (identity is the GUID; DNs move). The zero value
// is invalid and ForRequest refuses it.
type ObjectRef struct {
	kind refKind
	g    guid.GUID
	s    sid.SID
	d    DN
}

func GUIDRef(g guid.GUID) ObjectRef { return ObjectRef{kind: refGUID, g: g} }
func SIDRef(s sid.SID) ObjectRef    { return ObjectRef{kind: refSID, s: s} }
func DNRef(d DN) ObjectRef          { return ObjectRef{kind: refDN, d: d} }

func (r ObjectRef) GUID() (guid.GUID, bool) { return r.g, r.kind == refGUID }
func (r ObjectRef) SID() (sid.SID, bool)    { return r.s, r.kind == refSID }
func (r ObjectRef) DN() (DN, bool)          { return r.d, r.kind == refDN }

// ForRequest is the text sent as an LDAP DN: "<GUID=hex32>", "<SID=hex>" (binary, lower-case hex,
// forms every DC accepts) or the canonical DN. A DN holding an opaque `#hex` RDN is NotRequestable.
func (r ObjectRef) ForRequest() (string, error) {
	switch r.kind {
	case refGUID:
		return r.g.ObjectRef(), nil
	case refSID:
		return "<SID=" + hex.EncodeToString(r.s.Bytes()) + ">", nil
	case refDN:
		if r.d.Len() == 0 {
			return "", fail(EmptyRDN, -1)
		}
		for _, x := range r.d.rdns {
			if x.opaque != nil {
				return "", fail(NotRequestable, -1)
			}
		}
		return string(r.d.Render()), nil
	}
	return "", fail(InvalidObjectRef, -1)
}

// ParseObjectRef reads "<GUID=…>", "<SID=…>" or a strict DN. GUID takes the 32-hex binary form
// or the dashed form; SID the binary hex or S-1-… text. Anything else starting with '<' is
// InvalidObjectRef: the whole input must be consumed, so `<GUID=…>)(cn=*` fails.
func ParseObjectRef[S ~string](text S) (ObjectRef, error) {
	s := string(text)
	if len(s) > MaxDNLen {
		return ObjectRef{}, fail(TooLong, 0)
	}
	if s == "" || s[0] != '<' {
		d, err := parse(s, Strict)
		if err != nil {
			return ObjectRef{}, err
		}
		return DNRef(d), nil
	}
	k, v, ok := altForm(s)
	if !ok {
		return ObjectRef{}, fail(InvalidObjectRef, 0)
	}
	switch k {
	case "GUID":
		g, err := parseGUID(v)
		if err != nil {
			return ObjectRef{}, fail(InvalidObjectRef, 0)
		}
		return GUIDRef(g), nil
	case "SID":
		x, err := parseSID(v)
		if err != nil {
			return ObjectRef{}, fail(InvalidObjectRef, 0)
		}
		return SIDRef(x), nil
	}
	return ObjectRef{}, fail(InvalidObjectRef, 0)
}

// altForm splits exactly "<KEY=value>" with nothing after '>'.
func altForm(s string) (key, val string, ok bool) {
	if len(s) < 4 || s[0] != '<' || s[len(s)-1] != '>' {
		return "", "", false
	}
	body := s[1 : len(s)-1]
	i := strings.IndexByte(body, '=')
	if i <= 0 || strings.ContainsAny(body, "<>;,()*\\ \x00") {
		return "", "", false
	}
	key = strings.ToUpper(body[:i])
	if key != "GUID" && key != "SID" {
		return "", "", false
	}
	return key, body[i+1:], true
}

func parseGUID(v string) (guid.GUID, error) {
	if len(v) == 2*guid.Size {
		b, err := hex.DecodeString(v)
		if err != nil {
			return guid.GUID{}, err
		}
		return guid.FromBytes(b)
	}
	return guid.Parse(v)
}

func parseSID(v string) (sid.SID, error) {
	if len(v) >= 2 && (v[0] == 'S' || v[0] == 's') {
		return sid.Parse(v)
	}
	b, err := hex.DecodeString(v)
	if err != nil {
		return sid.SID{}, err
	}
	return sid.FromBytes(b)
}

// ExtendedDN is the response-only form "<GUID=…>;<SID=…>;dn" (SID optional). It has no conversion
// to a request value (MS-ADTS: not accepted in requests); use the GUID as an ObjectRef instead.
type ExtendedDN struct {
	GUID   guid.GUID
	SID    sid.SID
	HasSID bool
	DN     DN
}

// ParseExtendedDN reads a DC's extended DN. The DN part is parsed Strict.
func ParseExtendedDN[S ~string](text S) (ExtendedDN, error) {
	s := string(text)
	var out ExtendedDN
	if len(s) > MaxDNLen {
		return out, fail(TooLong, 0)
	}
	var haveGUID bool
	for len(s) > 0 && s[0] == '<' {
		end := strings.IndexByte(s, '>')
		if end < 0 || end+1 >= len(s) || s[end+1] != ';' {
			return out, fail(InvalidExtendedDN, 0)
		}
		k, v, ok := altForm(s[:end+1])
		if !ok {
			return out, fail(InvalidExtendedDN, 0)
		}
		switch {
		case k == "GUID" && !haveGUID && !out.HasSID:
			g, err := parseGUID(v)
			if err != nil {
				return out, fail(InvalidExtendedDN, 0)
			}
			out.GUID, haveGUID = g, true
		case k == "SID" && haveGUID && !out.HasSID:
			x, err := parseSID(v)
			if err != nil {
				return out, fail(InvalidExtendedDN, 0)
			}
			out.SID, out.HasSID = x, true
		default:
			return out, fail(InvalidExtendedDN, 0)
		}
		s = s[end+2:]
	}
	if !haveGUID {
		return out, fail(InvalidExtendedDN, 0)
	}
	d, err := parse(s, Strict)
	if err != nil {
		return out, err
	}
	out.DN = d
	return out, nil
}
