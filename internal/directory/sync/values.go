package sync

import (
	"strings"
	"time"
	"unicode/utf8"

	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
	"github.com/skenzeriq/activediq/internal/directory/attr/sid"
	"github.com/skenzeriq/activediq/internal/directory/inventory"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// The store's bounds (inventory.validateObservation), mirrored so an entry that Populate would refuse
// is refused here, per entry, instead of failing a whole batch.
const (
	maxClass      = 100
	maxDN         = 4096
	maxRDN        = 1024
	maxSAM        = 256
	maxUPN        = 1024
	maxDisplay    = 1024
	maxBag        = 60 * 1024 // the store's 64 KiB, less the JSON framing the estimate leaves out
	maxMembers    = 100000
	maxMultiValue = 10000
	// maxDNSHostName is dNSHostName's schema rangeUpper.
	maxDNSHostName = 2048
)

// attrSet is the wanted attributes of one entry, by lower-case name. Attributes the Mapper did not
// ask for are not in it: they are never looked at again.
type attrSet map[string]*connectorv1.Attribute

func (s attrSet) get(name string) (*connectorv1.Attribute, bool) {
	a, ok := s[strings.ToLower(name)]
	return a, ok
}

// values returns an attribute's values, bounded.
func values(a *connectorv1.Attribute, name string) ([]*connectorv1.AttributeValue, error) {
	if len(a.GetValues()) > maxMultiValue && name != "member" {
		return nil, refuse(name, CodeTooMany)
	}
	return a.GetValues(), nil
}

// one returns the single value of a single-valued attribute: nil, nil when the attribute is present
// without a value.
func one(a *connectorv1.Attribute, name string) (*connectorv1.AttributeValue, error) {
	switch vs := a.GetValues(); len(vs) {
	case 0:
		return nil, nil
	case 1:
		if vs[0] == nil {
			return nil, refuse(name, CodeType)
		}
		return vs[0], nil
	}
	return nil, refuse(name, CodeMultiValued)
}

func cleanText(name, s string, max int) (string, error) {
	if strings.ContainsRune(s, 0) || !utf8.ValidString(s) {
		return "", refuse(name, CodeBadText)
	}
	// max counts characters, as the schema's rangeUpper does (UTF-16 units; a rune is never more), not
	// bytes: a 256-character sAMAccountName of non-ASCII text is valid in AD and several times 256 bytes.
	if utf8.RuneCountInString(s) > max {
		return "", refuse(name, CodeTooLong)
	}
	return s, nil
}

// text reads a single-valued string attribute. "" with a nil error is present-and-empty or absent.
func text(set attrSet, name string, max int) (string, bool, error) {
	a, ok := set.get(name)
	if !ok {
		return "", false, nil
	}
	v, err := one(a, name)
	if err != nil || v == nil {
		return "", true, err
	}
	t, isText := v.GetValue().(*connectorv1.AttributeValue_Text)
	if !isText {
		return "", true, refuse(name, CodeType)
	}
	s, err := cleanText(name, t.Text, max)
	return s, true, err
}

// firstText reads a string attribute that the schema allows several values of (description) and keeps
// the first, which is all a column holds.
func firstText(set attrSet, name string, max int) (string, bool, error) {
	a, ok := set.get(name)
	if !ok {
		return "", false, nil
	}
	vs, err := values(a, name)
	if err != nil || len(vs) == 0 {
		return "", true, err
	}
	t, isText := vs[0].GetValue().(*connectorv1.AttributeValue_Text)
	if !isText {
		return "", true, refuse(name, CodeType)
	}
	s, err := cleanText(name, t.Text, max)
	return s, true, err
}

// texts reads a multi-valued string attribute.
func texts(set attrSet, name string, max int) ([]string, bool, error) {
	a, ok := set.get(name)
	if !ok {
		return nil, false, nil
	}
	vs, err := values(a, name)
	if err != nil {
		return nil, true, err
	}
	out := make([]string, 0, len(vs))
	for _, v := range vs {
		var s string
		switch t := v.GetValue().(type) {
		case *connectorv1.AttributeValue_Text:
			s = t.Text
		case *connectorv1.AttributeValue_Dn:
			s = t.Dn.GetDisplayDn()
		default:
			return nil, true, refuse(name, CodeType)
		}
		s, err := cleanText(name, s, max)
		if err != nil {
			return nil, true, err
		}
		out = append(out, s)
	}
	return out, true, nil
}

// dnText reads a single-valued DN attribute as its display text.
func dnValue(set attrSet, name string) (*connectorv1.DnValue, bool, error) {
	a, ok := set.get(name)
	if !ok {
		return nil, false, nil
	}
	v, err := one(a, name)
	if err != nil || v == nil {
		return nil, true, err
	}
	d, isDN := v.GetValue().(*connectorv1.AttributeValue_Dn)
	if !isDN || d.Dn == nil {
		return nil, true, refuse(name, CodeType)
	}
	return d.Dn, true, nil
}

func boolean(set attrSet, name string) (val, present bool, err error) {
	a, ok := set.get(name)
	if !ok {
		return false, false, nil
	}
	v, err := one(a, name)
	if err != nil || v == nil {
		return false, true, err
	}
	b, isBool := v.GetValue().(*connectorv1.AttributeValue_Boolean)
	if !isBool {
		return false, true, refuse(name, CodeType)
	}
	return b.Boolean, true, nil
}

func int32Of(set attrSet, name string) (val int32, present, hasValue bool, err error) {
	a, ok := set.get(name)
	if !ok {
		return 0, false, false, nil
	}
	v, err := one(a, name)
	if err != nil {
		return 0, true, false, err
	}
	if v == nil {
		return 0, true, false, nil
	}
	n, isInt := v.GetValue().(*connectorv1.AttributeValue_Int32Value)
	if !isInt {
		return 0, true, false, refuse(name, CodeType)
	}
	return n.Int32Value, true, true, nil
}

// entryGUID is a connector Guid (16 bytes, RFC 4122 order: the order of the canonical text) as the
// inventory's canonical text.
func entryGUID(g *connectorv1.Guid, name string) (inventory.GUID, error) {
	b := g.GetValue()
	if len(b) != guid.Size {
		return "", refuse(name, CodeBadGUID)
	}
	var wire guid.GUID
	// RFC 4122 order to the LDAP octet-string order: Data1, Data2 and Data3 swap ends.
	wire = guid.GUID{b[3], b[2], b[1], b[0], b[5], b[4], b[7], b[6], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]}
	if wire == (guid.GUID{}) {
		return "", refuse(name, CodeBadGUID)
	}
	return inventory.GUID(wire.String()), nil
}

// sidBytes validates a connector Sid and returns its binary form.
func sidBytes(s *connectorv1.Sid, name string) ([]byte, error) {
	v, err := sid.FromBytes(s.GetValue())
	if err != nil {
		return nil, refuse(name, CodeBadSID)
	}
	return v.Bytes(), nil
}

// minTime is 1601-01-01 in Unix seconds, the earliest instant a FILETIME can name.
const minTime = -11644473600

// timeInput is what a time attribute held: read says the entry carried the attribute, t is zero when
// it held "no time" (a missing value, or the ZERO sentinel).
type timeInput struct {
	t    time.Time
	read bool
}

// timeOf reads a single-valued time attribute. neverIsMax lets the MAX sentinel and a FILETIME beyond
// year 9999 stand for "never" (accountExpires only); everywhere else they are malformed.
func timeOf(set attrSet, name string, neverIsMax bool) (timeInput, error) {
	a, ok := set.get(name)
	if !ok {
		return timeInput{}, nil
	}
	v, err := one(a, name)
	if err != nil {
		return timeInput{}, err
	}
	if v == nil {
		return timeInput{read: true}, nil
	}
	tv, isTime := v.GetValue().(*connectorv1.AttributeValue_Time)
	if !isTime || tv.Time == nil {
		return timeInput{}, refuse(name, CodeType)
	}
	switch k := tv.Time.GetKind().(type) {
	case *connectorv1.TimeValue_At:
		if k.At == nil || k.At.CheckValid() != nil || k.At.GetSeconds() < minTime {
			return timeInput{}, refuse(name, CodeBadTime)
		}
		return timeInput{t: k.At.AsTime(), read: true}, nil
	case *connectorv1.TimeValue_Sentinel:
		switch k.Sentinel {
		case connectorv1.TimeSentinel_TIME_SENTINEL_ZERO:
			return timeInput{read: true}, nil
		case connectorv1.TimeSentinel_TIME_SENTINEL_MAX:
			if neverIsMax {
				return timeInput{read: true}, nil
			}
		}
		return timeInput{}, refuse(name, CodeBadTime)
	case *connectorv1.TimeValue_FiletimeTicksOutOfRange:
		if neverIsMax && k.FiletimeTicksOutOfRange > 0 {
			return timeInput{read: true}, nil
		}
		return timeInput{}, refuse(name, CodeBadTime)
	}
	return timeInput{}, refuse(name, CodeType)
}

// generalized reads whenCreated and whenChanged. Absent is the zero time (the store's "absent").
func generalized(set attrSet, name string) (time.Time, error) {
	a, ok := set.get(name)
	if !ok {
		return time.Time{}, nil
	}
	v, err := one(a, name)
	if err != nil || v == nil {
		return time.Time{}, err
	}
	tv, isTime := v.GetValue().(*connectorv1.AttributeValue_Time)
	if !isTime || tv.Time == nil {
		return time.Time{}, refuse(name, CodeType)
	}
	at, isAt := tv.Time.GetKind().(*connectorv1.TimeValue_At)
	if !isAt || at.At == nil || at.At.CheckValid() != nil || at.At.GetSeconds() < minTime {
		return time.Time{}, refuse(name, CodeBadTime)
	}
	return at.At.AsTime(), nil
}
